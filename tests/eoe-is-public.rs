//! The EoE surface has to be reachable from outside the crate.
//!
//! An **integration** test on purpose: it compiles against the public API, so it fails to
//! build while a method is missing or a type is `pub` without being exported. A unit test
//! inside the crate would pass either way and prove nothing - which is exactly what
//! happened twice in this module, with `Fragment` and with `IpParam`: both were `pub`,
//! neither was reachable, and only `cargo doc` noticed.
//!
//! **Naming a type is not enough.** The first version of this file listed ten types
//! through a `PhantomData` and left five separate demotions green - `abandon`,
//! `into_buffer`, `total_frame_size` and `fragment` each turned `pub(crate)`, and, worse,
//! `FragmentError` and `ReassemblyError` deleted from `error.rs`'s re-export. Those two
//! are the payloads of `Error::Fragment` and `Error::Reassembly`, which both new `# Errors`
//! sections tell a consumer to expect - the same `Fragment`/`IpParam` failure one level
//! up. So every member a consumer needs is *called* here, not merely named.

use ethercrab::{
    EoeHeader, EoeResult, Fragment, Fragments, FrameType, InProgress, IpParam, Reassembled,
    Reassembly, SecondWord, SubDevice, SubDeviceRef,
    error::{Error, FragmentError, ReassemblyError},
};

#[test]
fn the_wire_types_can_be_built_and_read_from_outside_the_crate() {
    // Constructors, accessors and fields, not just the type names: a `PhantomData` pins the
    // type and none of its members.
    let header = EoeHeader::new(FrameType::FragData, 3).with_fragment(0, 2, 1);

    assert_eq!(header.frame_type, FrameType::FragData);
    assert_eq!(header.port, 3);
    assert!(!header.last_fragment);
    assert!(!header.time_append);
    assert!(!header.time_request);

    let fragment: Fragment = header.fragment().expect("Fragment bookkeeping");

    assert_eq!(fragment.number, 0);
    assert_eq!(fragment.frame_number, 1);
    assert_eq!(fragment.total_frame_size(), Some(64));
    assert_eq!(fragment.offset(), None);

    // The union's three arms, and the result arm's payload type.
    assert!(matches!(header.second_word(), SecondWord::Fragment(_)));
    assert_eq!(header.result(), None);

    let refused = EoeHeader::new(FrameType::InitResp, 0).with_result(EoeResult::NoIpSupport);

    assert_eq!(refused.result(), Some(Ok(EoeResult::NoIpSupport)));

    // The IP parameter payload, which was `pub` and unreachable once already.
    let params = IpParam::default();

    assert!(params.mac.is_none());
    assert!(params.ip.is_none());
}

#[test]
fn a_frame_can_be_cut_and_put_back_together_from_outside_the_crate() {
    let frame = (0..70u8).collect::<Vec<_>>();

    let mut buffer = [0u8; 128];
    let mut reassembly = Reassembly::new(&mut buffer, 0).expect("A reassembly");

    assert_eq!(reassembly.port(), 0);

    let mut rebuilt = None;

    for (header, data) in Fragments::new(&frame, 32, 1, 0).expect("Fits") {
        match reassembly.push(header, data).expect("A fragment") {
            Reassembled::More => {
                let progress: InProgress = reassembly.in_progress().expect("Half a frame");

                assert_eq!(progress.frame_number, 1);
            }
            Reassembled::Frame(done) => rebuilt = Some(done.to_vec()),
        }
    }

    assert_eq!(rebuilt.as_deref(), Some(frame.as_slice()));

    // Giving up on a half assembled frame, and getting the memory back afterwards.
    let mut second = Reassembly::new(&mut buffer, 0).expect("A reassembly");
    let (header, data) = Fragments::new(&frame, 32, 2, 0)
        .expect("Fits")
        .next()
        .expect("One fragment");

    second.push(header, data).expect("A fragment");

    assert!(second.abandon().is_some());
    assert!(second.in_progress().is_none());
    assert_eq!(second.into_buffer().len(), 128);
}

#[test]
fn the_error_payloads_are_reachable_from_outside_the_crate() {
    // `Error::Fragment` and `Error::Reassembly` are what both public methods document, and
    // their payload enums live behind `ethercrab::error::`, never the crate root. Deleting
    // that re-export left the first version of this file green.
    let too_long = Fragments::new(&[0u8; 4096], 64, 0, 0).expect_err("Longer than the field");

    assert!(matches!(too_long, FragmentError::FrameTooLong { .. }));
    assert!(matches!(
        Error::from(too_long),
        Error::Fragment(FragmentError::FrameTooLong { .. })
    ));

    let mut buffer = [0u8; 16];
    let mut reassembly = Reassembly::new(&mut buffer, 0).expect("A reassembly");
    let header = EoeHeader::new(FrameType::FragData, 1).with_fragment(0, 1, 0);

    let wrong_port = reassembly
        .push(header, &[0u8; 4])
        .expect_err("Port 1 into a port 0 reassembly");

    assert!(matches!(wrong_port, ReassemblyError::WrongPort { .. }));
    assert!(matches!(
        Error::from(wrong_port),
        Error::Reassembly(ReassemblyError::WrongPort { .. })
    ));
}

/// The two mailbox paths, named but never called: reaching them needs a `MainDevice` and a
/// bus. What is pinned here is that they are `pub`, and that their futures are `Send` - a
/// `!Send` value held across an await inside them would break every `tokio::spawn`
/// consumer while every assertion above stayed green.
#[allow(dead_code)]
fn the_mailbox_paths_are_public_and_their_futures_are_send(
    subdevice: &SubDeviceRef<'_, &SubDevice>,
    buffer: &mut [u8],
) {
    fn assert_send<T: Send>(_: T) {}

    assert_send(subdevice.eoe_send(0, b"a frame"));
    assert_send(subdevice.eoe_receive(0, buffer));

    // And the accessor an EoE program starts with.
    let _: bool = subdevice.supports_eoe();
}
