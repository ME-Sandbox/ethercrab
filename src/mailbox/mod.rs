pub mod coe;
pub mod eoe;

use crate::{
    SubDevice, SubDeviceRef,
    error::{Error, MailboxError},
    fmt,
    pdu_loop::ReceivedPdu,
    register::RegisterAddress,
    subdevice::Mailbox,
    timer_factory::IntoTimeout,
};
use core::ops::Deref;

/// Waits for a SubDevice's mailboxes to be ready to read and write.
///
/// Nothing here is protocol specific - it is sync manager status and mailbox addresses - so
/// it serves CoE and EoE alike rather than each carrying its own copy.
///
/// Note the pairing of the two errors below: `.write` is reported as `NoReadMailbox` and
/// `.read` as `NoWriteMailbox`. The *names* look swapped, but the variants' own doc
/// comments agree with this pairing - `NoReadMailbox` is documented as "a SubDevice has no
/// write (SubDevice IN) mailbox". (Their `Display` text then says the opposite again, so
/// the confusion is upstream's and sits in three places.) Kept exactly as found: no test
/// distinguishes them - the only consumer matches both in one arm - so changing it here
/// would be an unreviewed behaviour change riding along in a refactor.
pub(crate) async fn wait_for_mailboxes<S>(
    subdevice: &SubDeviceRef<'_, S>,
) -> Result<(Mailbox, Mailbox), Error>
where
    S: Deref<Target = SubDevice>,
{
    let write_mailbox = subdevice
        .config
        .mailbox
        .write
        .ok_or(Error::Mailbox(MailboxError::NoReadMailbox))?;
    let read_mailbox = subdevice
        .config
        .mailbox
        .read
        .ok_or(Error::Mailbox(MailboxError::NoWriteMailbox))?;

    let mailbox_read_sm_status = RegisterAddress::sync_manager_status(read_mailbox.sync_manager);
    let mailbox_write_sm_status = RegisterAddress::sync_manager_status(write_mailbox.sync_manager);

    // Ensure SubDevice OUT (master IN) mailbox is empty. We'll retry this multiple times in
    // case the SubDevice is still busy or bugged or something.
    for i in 0..10 {
        let sm_status = subdevice
            .read(mailbox_read_sm_status)
            .receive::<crate::sync_manager_channel::Status>(subdevice.maindevice)
            .await?;

        // If flag is set, read entire mailbox to clear it
        if sm_status.mailbox_full {
            fmt::debug!(
                "SubDevice {:#06x} OUT mailbox not empty (status {:?}). Clearing.",
                subdevice.configured_address(),
                sm_status
            );

            subdevice
                .read(read_mailbox.address)
                .ignore_wkc()
                .receive_slice(subdevice.maindevice, read_mailbox.len)
                .await?;
        } else {
            break;
        }

        // Don't delay on first iteration
        if i > 0 {
            subdevice.maindevice.timeouts.loop_tick().await;
        }

        if i > 1 {
            fmt::debug!("--> Retrying clear");
        }
    }

    // Wait for SubDevice IN mailbox to be available to receive data from master
    async {
        loop {
            let sm_status = subdevice
                .read(mailbox_write_sm_status)
                .receive::<crate::sync_manager_channel::Status>(subdevice.maindevice)
                .await?;

            if !sm_status.mailbox_full {
                break Ok(());
            }

            subdevice.maindevice.timeouts.loop_tick().await;
        }
    }
    .timeout(subdevice.maindevice.timeouts.mailbox_echo())
    .await
    .inspect_err(|&e| {
        fmt::error!(
            "Mailbox IN ready error for SubDevice {:#06x}: {}",
            subdevice.configured_address(),
            e
        );
    })?;

    Ok((read_mailbox, write_mailbox))
}

/// Waits for a SubDevice's OUT mailbox to fill, then reads it.
///
/// The returned PDU borrows from the `MainDevice`, not from the `SubDeviceRef` handed in.
/// That is where it genuinely comes from - `receive_slice` derives it from
/// `subdevice.maindevice`, a `Copy` reference - and saying so is **weaker** than the
/// elided lifetime this had as a method, which tied it to `&self`. A caller may now hold
/// the PDU across a re-borrow of the SubDevice, which the old shape rejected. Nothing does
/// yet; it is written down because it is the one thing the move did change.
pub(crate) async fn wait_for_mailbox_response<'maindevice, S>(
    subdevice: &SubDeviceRef<'maindevice, S>,
    read_mailbox: &Mailbox,
) -> Result<ReceivedPdu<'maindevice>, Error>
where
    S: Deref<Target = SubDevice>,
{
    let mailbox_read_sm = RegisterAddress::sync_manager_status(read_mailbox.sync_manager);

    // Wait for SubDevice OUT mailbox to be ready
    async {
        loop {
            let sm_status = subdevice
                .read(mailbox_read_sm)
                .receive::<crate::sync_manager_channel::Status>(subdevice.maindevice)
                .await?;

            if sm_status.mailbox_full {
                break Ok(());
            }

            subdevice.maindevice.timeouts.loop_tick().await;
        }
    }
    .timeout(subdevice.maindevice.timeouts.mailbox_response())
    .await
    .inspect_err(|&e| {
        fmt::error!(
            "Response mailbox IN error for SubDevice {:#06x}: {}",
            subdevice.configured_address(),
            e
        );
    })?;

    // Read acknowledgement from SubDevice OUT mailbox
    let response = subdevice
        .read(read_mailbox.address)
        .receive_slice(subdevice.maindevice, read_mailbox.len)
        .await?;

    // TODO: Retries. Refer to SOEM's `ecx_mbxreceive` for inspiration

    Ok(response)
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Priority {
    #[default]
    Lowest = 0x00,
    Low = 0x01,
    High = 0x02,
    Highest = 0x03,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum MailboxType {
    /// error (ERR)
    Err = 0x00,
    /// ADS over EtherCAT (AoE)
    Aoe = 0x01,
    /// Ethernet over EtherCAT (EoE)
    Eoe = 0x02,
    /// CAN application protocol over EtherCAT (CoE)
    Coe = 0x03,
    /// File Access over EtherCAT (FoE)
    Foe = 0x04,
    /// Servo profile over EtherCAT (SoE)
    Soe = 0x05,
    // 0x06 -0x0e: reserved
    /// Vendor specific
    VendorSpecific = 0x0f,
}

/// Mailbox header.
///
/// Defined in ETG1000.6 under either `TMBXHEADER` or `MbxHeader` e.g. Table 29 - CoE Elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[wire(bytes = 6)]
pub struct MailboxHeader {
    /// Mailbox data payload length.
    #[wire(bytes = 2, post_skip_bytes = 2)]
    pub length: u16,
    // /// Address, always zero when master is in control.
    // This field is ignored to save some bytes as it's always zero for EtherCrab's use case.
    // #[wire(bytes = 2)]
    // pub address: u16,
    // reserved6: u8,
    #[wire(pre_skip = 6, bits = 2)]
    pub priority: Priority,
    // #[wire(bits = 4)]
    // pub type: u8
    #[wire(bits = 4)]
    pub mailbox_type: MailboxType,
    /// Mailbox counter from 1 to 7 inclusive. Wraps around to 1 when count exceeds 7. 0 is
    /// reserved.
    #[wire(bits = 3, post_skip = 1)]
    pub counter: u8,
    // _reserved1: u1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use ethercrab_wire::{EtherCrabWireRead, EtherCrabWireWriteSized};

    // Manual impl because `counter` field is a special case
    impl<'a> Arbitrary<'a> for MailboxHeader {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                length: Arbitrary::arbitrary(u)?,
                // address: Arbitrary::arbitrary(u)?,
                priority: Arbitrary::arbitrary(u)?,
                mailbox_type: Arbitrary::arbitrary(u)?,
                // 0..=6 shifted up by 1 so we get the valid range 1..=7
                counter: u.choose_index(7)? as u8 + 1,
            })
        }
    }

    // Keep this around so we can write test data to files for debugging
    // #[allow(unused)]
    // fn write_bytes_to_file(name: &str, data: &[u8]) {
    //     let mut frame = crate::pdu_loop::FrameElement::default();

    //     frame
    //         .replace(
    //             crate::command::Command::Fpwr {
    //                 address: 0x1001,
    //                 register: 0x1800,
    //             },
    //             data.len() as u16,
    //             0xaa,
    //         )
    //         .unwrap();

    //     let mut buffer = vec![0; 1536];

    //     frame
    //         .to_ethernet_frame(buffer.as_mut_slice(), data)
    //         .unwrap();

    //     // Epic haxx: force length header param to 1024. This should be the mailbox buffer size
    //     buffer.as_mut_slice()[0x16] = 0x00;
    //     buffer.as_mut_slice()[0x17] = 0x04;

    //     let packet = Packet {
    //         header: &PacketHeader {
    //             ts: libc::timeval {
    //                 tv_sec: Utc::now().timestamp().try_into().expect("Time overflow"),
    //                 tv_usec: 0,
    //             },
    //             // 64 bytes minimum frame size, minus 2x MAC address and 1x optional tag
    //             caplen: (buffer.len() as u32).max(46),
    //             len: buffer.len() as u32,
    //         },
    //         data: &buffer,
    //     };

    //     let cap = Capture::dead(Linktype::ETHERNET).expect("Open capture");

    //     let path = PathBuf::from(&name);

    //     let mut save = cap.savefile(&path).expect("Open save file");

    //     save.write(&packet);
    //     drop(save);
    // }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mailbox_header_fuzz() {
        heckcheck::check(|status: MailboxHeader| {
            let packed = status.pack();

            let unpacked = MailboxHeader::unpack_from_slice(&packed).expect("Unpack");

            pretty_assertions::assert_eq!(status, unpacked);

            Ok(())
        });
    }

    #[test]
    fn encode_header() {
        // From wireshark capture
        let expected = [0x0a, 0x00, 0x00, 0x00, 0x00, 0x33];

        let packed = MailboxHeader {
            length: 10,
            priority: Priority::Lowest,
            // address: 0x0000,
            counter: 3,
            mailbox_type: MailboxType::Coe,
        }
        .pack();

        assert_eq!(packed, expected);
    }

    #[test]
    fn decode_header() {
        // From Wireshark capture "soem-sdinfo-akd.pcapng", packet #296
        let raw = [0x0a, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x20];

        let expected = MailboxHeader {
            length: 10,
            // address: 0x0000,
            priority: Priority::Lowest,
            mailbox_type: MailboxType::Coe,
            counter: 2,
        };

        let parsed = MailboxHeader::unpack_from_slice(&raw).unwrap();

        assert_eq!(parsed, expected);
    }
}
