//! Ethernet over EtherCAT (EoE), ETG.1000.6.
//!
//! Ported from SOEM's `ec_eoe.c` / `ec_eoe.h`. Every wire test below names the macro or
//! function it was derived from, and the byte sequences are computed from those macros
//! rather than read off a description of the protocol.

use core::net::Ipv4Addr;
use ethercrab_wire::{EtherCrabWireRead, EtherCrabWireWrite, WireError};

/// EoE frame type, the low four bits of the first header word.
///
/// Ported from `libs/SOEM/include/soem/ec_eoe.h`: the `EOE_FRAG_DATA` …
/// `EOE_GET_ADDR_FILTER_RESP` defines. Values 10 to 15 fit the field but are not defined;
/// decoding one is an error rather than a panic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum FrameType {
    /// A fragment of an Ethernet frame.
    FragData = 0x00,
    /// Initialisation response carrying a timestamp.
    InitRespTimestamp = 0x01,
    /// Set IP parameters request. Called `EOE_INIT_REQ` in SOEM, `Set IP Request` in the
    /// specification.
    InitReq = 0x02,
    /// Set IP parameters response.
    InitResp = 0x03,
    /// Set address filter request.
    SetAddrFilterReq = 0x04,
    /// Set address filter response.
    SetAddrFilterResp = 0x05,
    /// Get IP parameters request.
    GetIpParamReq = 0x06,
    /// Get IP parameters response.
    GetIpParamResp = 0x07,
    /// Get address filter request.
    GetAddrFilterReq = 0x08,
    /// Get address filter response.
    GetAddrFilterResp = 0x09,
}

/// Result code of an EoE request, as carried by a response frame.
///
/// Ported from the `EOE_RESULT_*` defines in `ec_eoe.h`. The gaps are real: the code is a
/// 16 bit value with no meaning between the listed points.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum EoeResult {
    /// The request succeeded.
    Success = 0x0000,
    /// The request failed for a reason the SubDevice did not name.
    UnspecifiedError = 0x0001,
    /// The SubDevice does not implement the frame type that was sent.
    UnsupportedFrameType = 0x0002,
    /// The SubDevice does not support setting IP parameters.
    NoIpSupport = 0x0201,
    /// The SubDevice does not support DHCP.
    NoDhcpSupport = 0x0202,
    /// The SubDevice does not support address filters.
    NoFilterSupport = 0x0401,
}

/// Fragment bookkeeping, the second header word of a frame that carries data.
///
/// The offset field is **overloaded**, which is easy to miss and expensive to get wrong:
/// `ec_eoe.c:387-391` writes the byte offset divided by 32 for every fragment after the
/// first, and the *total frame size* rounded up to 32 bytes for fragment zero. The receive
/// side mirrors it (`:480` takes the buffer size from fragment zero, `:502` compares the
/// offset for the rest). Hence two accessors, each `None` when the raw value does not mean
/// what it asks for.
///
/// Read from an [`EoeHeader`]; `raw_offset` is private, so one cannot be built or fully
/// destructured from outside the crate. Reading the public fields, and matching with a
/// trailing `..`, work as usual.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fragment {
    /// Index of this fragment within the frame, counting from zero.
    pub number: u8,
    /// The raw six bit field, in units of 32 bytes. Read it through [`Fragment::offset`]
    /// or [`Fragment::total_frame_size`].
    raw_offset: u8,
    /// Identifies the Ethernet frame these fragments belong to. Wraps after 16.
    pub frame_number: u8,
}

impl Fragment {
    /// Byte offset of this fragment within the frame.
    ///
    /// `None` for fragment zero, whose field carries the frame size instead.
    pub fn offset(&self) -> Option<u16> {
        (self.number > 0).then(|| u16::from(self.raw_offset) * 32)
    }

    /// Total size of the frame being carried, rounded up to a multiple of 32 bytes.
    ///
    /// `None` for every fragment but the first: only fragment zero carries it, and it is
    /// what tells a receiver how large a buffer it needs.
    pub fn total_frame_size(&self) -> Option<u16> {
        (self.number == 0).then(|| u16::from(self.raw_offset) * 32)
    }
}

/// EoE header: two 16 bit words directly behind the mailbox header. ETG.1000.6.
///
/// The second word is a **union** in the reference implementation (`ec_EOEt`):
///
/// ```c
/// union { uint16_t frameinfo2; uint16_t result; };
/// ```
///
/// Which arm applies is decided by `frame_type` and by nothing in the word itself, so it
/// is not exposed raw. Read it through [`EoeHeader::fragment`] or
/// [`EoeHeader::result`]; each answers `None` when the other one applies.
///
/// The first word is a plain bit field:
///
/// ```text
/// word 1:  type(4)  port(4)  last_fragment(1)  time_append(1)  time_request(1)  ...(5)
/// word 2:  fragment_no(6)    frame_offset(6)   frame_no(4)     -- or a result code
/// ```
///
/// `frameinfo2` is kept as one raw word rather than three `#[wire(bits)]` fields because
/// `frame_offset` spans bits 22 to 27 and `EtherCrabWireReadWrite` rejects a multi-byte
/// field that is not byte aligned.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[wire(bytes = 4)]
pub struct EoeHeader {
    /// What this frame is.
    #[wire(bits = 4)]
    pub frame_type: FrameType,
    /// Which port of the SubDevice the frame belongs to. Zero for devices with one port.
    #[wire(bits = 4)]
    pub port: u8,
    /// Whether this is the last fragment of the Ethernet frame being carried.
    #[wire(bits = 1)]
    pub last_fragment: bool,
    /// Whether a timestamp is appended to the data.
    ///
    /// `ec_eoe.c:520` shortens the payload by four bytes when this is set, so confusing it
    /// with [`time_request`](Self::time_request) silently truncates every frame.
    #[wire(bits = 1)]
    pub time_append: bool,
    /// Whether the sender wants a timestamp back.
    #[wire(bits = 1, post_skip = 5)]
    pub time_request: bool,

    /// The union: fragment bookkeeping or a result code. Never read directly.
    #[wire(bytes = 2)]
    second_word: u16,
}

/// What the second header word of an [`EoeHeader`] means.
///
/// It is a `union` in the reference implementation and has **three** states, not two:
///
/// | frame type | second word | evidence |
/// |---|---|---|
/// | `FragData` | fragment bookkeeping | `ec_eoe.c:384-394` writes it, `:465-502` reads it |
/// | `InitReq`, `GetIpParamReq` | unused, written as zero | `ec_eoe.c:97`, `:216` |
/// | `InitResp` | a result code | `ec_eoe.c:157` |
///
/// **The remaining four are not from the reference implementation.** They are listed
/// separately rather than blended into the rows above:
///
/// * `SetAddrFilterReq` and `GetAddrFilterReq` are treated as the other two requests.
///   `ec_eoe.h:114-119` names them, and a grep of the whole SOEM tree finds those four
///   constants used by no `.c` file at all - so there is a definition but no behaviour to
///   port. A request that carries neither fragments nor an answer leaves nothing else for
///   the word to be.
/// * `SetAddrFilterResp` and `GetAddrFilterResp` carry a result per ETG.1000.6. That
///   [`EoeResult::NoFilterSupport`] exists at all fits, but does not prove it: nothing
///   here or in the reference implementation stops a device from answering any response
///   with any code, and this type will happily report `NoFilterSupport` on an `InitResp`.
/// * `GetIpParamResp` carries a result. SOEM **does** implement this frame type
///   (`ecx_EOEgetIp`, `ec_eoe.c:238` onwards); it simply never reads the second word and
///   goes straight to the include flags in `data[0]` (`:244`).
/// * `InitRespTimestamp` is an **assumption**, and the weakest cell in this table. SOEM
///   neither sends nor recognises frame type 1 - `ecx_EOErecv` reads `frameinfo2` as
///   fragment bookkeeping without checking the type at all (`:465`) - and what timestamp
///   handling exists says only that the timestamp is 32 bits appended to the payload
///   (`:519-522`, and the same again at `:646-649`), which says nothing about this 16 bit
///   word. Treating it like the other responses is a guess, not evidence.
// The state count has already gone from two to three once, and a fourth would break every
// downstream `match`. `TxRxResponse` is the crate's only precedent for the attribute; it is
// a struct, so it carries it for the neighbouring reason - keeping room to add a field -
// rather than this one.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecondWord {
    /// Fragment bookkeeping. Only a data frame carries it.
    Fragment(Fragment),
    /// The result of the request this frame answers.
    ///
    /// `Err` carries the raw value when it matches no `EOE_RESULT_*` - worth reporting
    /// rather than discarding, and not a reason to fail decoding the header.
    Result(Result<EoeResult, u16>),
    /// Nothing. A request carries no second word; the reference implementation writes zero
    /// and never looks at it.
    Unused,
}

impl EoeHeader {
    const FRAGMENT_NO: (u16, u16) = (0x003F, 0);
    const FRAME_OFFSET: (u16, u16) = (0x003F, 6);
    const FRAME_NO: (u16, u16) = (0x000F, 12);

    /// A header for the given frame type and port, with an empty second word.
    pub fn new(frame_type: FrameType, port: u8) -> Self {
        Self {
            frame_type,
            port,
            last_fragment: false,
            time_append: false,
            time_request: false,
            second_word: 0,
        }
    }

    fn get(&self, (mask, shift): (u16, u16)) -> u8 {
        ((self.second_word >> shift) & mask) as u8
    }

    /// What the second word means for this frame, decided by the frame type alone.
    ///
    /// See [`SecondWord`] for the three states and where each one comes from.
    pub fn second_word(&self) -> SecondWord {
        use ethercrab_wire::EtherCrabWireRead as _;

        match self.frame_type {
            FrameType::FragData => SecondWord::Fragment(Fragment {
                number: self.get(Self::FRAGMENT_NO),
                raw_offset: self.get(Self::FRAME_OFFSET),
                frame_number: self.get(Self::FRAME_NO),
            }),

            FrameType::InitReq
            | FrameType::GetIpParamReq
            | FrameType::SetAddrFilterReq
            | FrameType::GetAddrFilterReq => SecondWord::Unused,

            FrameType::InitResp
            | FrameType::InitRespTimestamp
            | FrameType::SetAddrFilterResp
            | FrameType::GetIpParamResp
            | FrameType::GetAddrFilterResp => SecondWord::Result(
                EoeResult::unpack_from_slice(&self.second_word.to_le_bytes())
                    .map_err(|_| self.second_word),
            ),
        }
    }

    /// Fragment bookkeeping, or `None` if this frame carries none.
    ///
    /// A convenience over [`second_word`](Self::second_word) for the common case.
    pub fn fragment(&self) -> Option<Fragment> {
        match self.second_word() {
            SecondWord::Fragment(fragment) => Some(fragment),
            _ => None,
        }
    }

    /// The result of the request this frame answers, or `None` if it answers none.
    ///
    /// A convenience over [`second_word`](Self::second_word) for the common case.
    pub fn result(&self) -> Option<Result<EoeResult, u16>> {
        match self.second_word() {
            SecondWord::Result(result) => Some(result),
            _ => None,
        }
    }

    /// Set fragment number, offset-or-size and frame number.
    ///
    /// Ported from the `EOE_HDR_*_SET` macros: each value is masked to its own width, so a
    /// value too large for its field cannot spill into a neighbour. `raw_offset` is in
    /// units of 32 bytes and means the frame size on fragment zero - see [`Fragment`].
    pub fn with_fragment(mut self, number: u8, raw_offset: u8, frame_number: u8) -> Self {
        let put = |(mask, shift): (u16, u16), value: u8| (u16::from(value) & mask) << shift;

        self.second_word = put(Self::FRAGMENT_NO, number)
            | put(Self::FRAME_OFFSET, raw_offset)
            | put(Self::FRAME_NO, frame_number);

        self
    }

    /// Set the result code. Only meaningful on a frame type that carries one.
    pub fn with_result(mut self, result: EoeResult) -> Self {
        self.second_word = result as u16;

        self
    }
}

/// IP parameters of a SubDevice, as carried by a Set-IP request or a Get-IP response.
///
/// Ported from `ecx_EOEsetIp` and `ecx_EOEgetIp` (`libs/SOEM/src/ec_eoe.c:74-138`,
/// `:187-300`). The payload is a byte of include flags followed by exactly the fields
/// those flags name, in flag order:
///
/// ```text
/// data[0]      include flags        EOE_PARAM_*, ec_eoe.h:102-107
/// data[1..4]   reserved             fields start at EOE_PARAM_OFFSET = 4
/// data[4..]    MAC 6, IP 4, subnet 4, gateway 4, DNS IP 4, DNS name 32
/// ```
///
/// Two things about it are easy to get wrong and expensive to debug:
///
/// * **IPv4 addresses go on the wire backwards.** `EOE_ip_uint32_to_byte`
///   (`ec_eoe.c:26-32`) writes `byte_ip[3]` from the *first* octet, so `192.168.1.10` is
///   the bytes `10, 1, 168, 192`.
/// * **The DNS name always occupies 32 bytes**, zero padded, however short it is -
///   `ec_eoe.c:131` copies `EOE_DNS_NAME_LENGTH` unconditionally, with the comment
///   "TwinCAT include EOE_DNS_NAME_LENGTH chars even if name is shorter".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IpParam {
    /// MAC address.
    pub mac: Option<[u8; 6]>,
    /// IPv4 address.
    pub ip: Option<Ipv4Addr>,
    /// Subnet mask.
    pub subnet: Option<Ipv4Addr>,
    /// Default gateway.
    pub gateway: Option<Ipv4Addr>,
    /// DNS server address.
    pub dns_ip: Option<Ipv4Addr>,
    /// DNS name. At most [`IpParam::DNS_NAME_LENGTH`] bytes.
    pub dns_name: Option<heapless::String<{ IpParam::DNS_NAME_LENGTH }>>,
}

impl IpParam {
    /// `EOE_DNS_NAME_LENGTH`. The field is always this wide on the wire.
    pub const DNS_NAME_LENGTH: usize = 32;

    /// `EOE_PARAM_OFFSET`: the flags byte plus three reserved bytes.
    const FIELDS_START: usize = 4;

    const MAC: (u8, usize) = (0x01, 6);
    const IP: (u8, usize) = (0x02, 4);
    const SUBNET: (u8, usize) = (0x04, 4);
    const GATEWAY: (u8, usize) = (0x08, 4);
    const DNS_IP: (u8, usize) = (0x10, 4);
    const DNS_NAME: (u8, usize) = (0x20, Self::DNS_NAME_LENGTH);

    /// The fields this parameter set would write, in flag order.
    ///
    /// One source for both [`EtherCrabWireWrite::packed_len`] and the writing itself, so
    /// the length can never disagree with what is written.
    fn present(&self) -> impl Iterator<Item = ((u8, usize), Field<'_>)> {
        [
            self.mac.as_ref().map(|mac| (Self::MAC, Field::Bytes(mac))),
            self.ip.map(|ip| (Self::IP, Field::Address(ip))),
            self.subnet.map(|net| (Self::SUBNET, Field::Address(net))),
            self.gateway.map(|gw| (Self::GATEWAY, Field::Address(gw))),
            self.dns_ip.map(|dns| (Self::DNS_IP, Field::Address(dns))),
            self.dns_name
                .as_ref()
                .map(|name| (Self::DNS_NAME, Field::Bytes(name.as_bytes()))),
        ]
        .into_iter()
        .flatten()
    }
}

/// One field of an [`IpParam`] on its way to the wire.
///
/// An address cannot be borrowed as bytes because it has to be reversed first, and the
/// reversed copy would not outlive the borrow.
enum Field<'a> {
    Bytes(&'a [u8]),
    Address(Ipv4Addr),
}

impl EtherCrabWireWrite for IpParam {
    fn pack_to_slice_unchecked<'buf>(&self, buf: &'buf mut [u8]) -> &'buf [u8] {
        let length = self.packed_len();
        let buffer = &mut buf[..length];

        // Zero first: the reserved bytes behind the flags, and the padding behind a DNS
        // name shorter than its field, must be zero rather than whatever the caller's
        // buffer held.
        buffer.fill(0);

        let mut flags = 0u8;
        let mut at = Self::FIELDS_START;

        for ((flag, width), field) in self.present() {
            let bytes = match field {
                Field::Bytes(bytes) => {
                    buffer[at..at + bytes.len()].copy_from_slice(bytes);
                    bytes.len()
                }
                Field::Address(address) => {
                    let [a, b, c, d] = address.octets();
                    // Last octet first - see the note on `IpParam`.
                    buffer[at..at + 4].copy_from_slice(&[d, c, b, a]);
                    4
                }
            };

            debug_assert!(bytes <= width, "a field cannot be wider than its slot");
            flags |= flag;
            at += width;
        }

        buffer[0] = flags;

        buffer
    }

    fn packed_len(&self) -> usize {
        self.present()
            .fold(Self::FIELDS_START, |total, ((_, width), _)| total + width)
    }
}

impl EtherCrabWireRead for IpParam {
    /// Reads the payload of a Set-IP request or a Get-IP response.
    ///
    /// # Errors
    ///
    /// [`WireError::ReadBufferTooShort`] if the payload ends before a field its own flags
    /// promised, or [`WireError::InvalidUtf8`] if the DNS name is not valid UTF-8.
    fn unpack_from_slice(buf: &[u8]) -> Result<Self, WireError> {
        let flags = *buf.first().ok_or(WireError::ReadBufferTooShort)?;
        let mut at = IpParam::FIELDS_START;

        let mut take = |(flag, width): (u8, usize)| -> Result<Option<&[u8]>, WireError> {
            if flags & flag == 0 {
                return Ok(None);
            }

            let field = buf
                .get(at..at + width)
                .ok_or(WireError::ReadBufferTooShort)?;
            at += width;

            Ok(Some(field))
        };

        let mac = take(IpParam::MAC)?
            .map(|bytes| <[u8; 6]>::try_from(bytes).map_err(|_| WireError::ArrayLength))
            .transpose()?;

        let mut address = |field| -> Result<Option<Ipv4Addr>, WireError> {
            take(field)?
                .map(|bytes| {
                    <[u8; 4]>::try_from(bytes)
                        .map(|wire| Ipv4Addr::new(wire[3], wire[2], wire[1], wire[0]))
                        .map_err(|_| WireError::ArrayLength)
                })
                .transpose()
        };

        let ip = address(IpParam::IP)?;
        let subnet = address(IpParam::SUBNET)?;
        let gateway = address(IpParam::GATEWAY)?;
        let dns_ip = address(IpParam::DNS_IP)?;

        let dns_name = take(IpParam::DNS_NAME)?
            .map(|bytes| {
                // Zero padded on the wire, and SOEM notes "Assume ZERO terminated string"
                // (`ec_eoe.c:290`), so a name with an interior zero comes back truncated.
                // That is faithful to the reference rather than a loss of information.
                let end = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                let text = core::str::from_utf8(bytes.get(..end).ok_or(WireError::ArrayLength)?)
                    .map_err(|_| WireError::InvalidUtf8)?;

                heapless::String::try_from(text).map_err(|()| WireError::ArrayLength)
            })
            .transpose()?;

        Ok(IpParam {
            mac,
            ip,
            subnet,
            gateway,
            dns_ip,
            dns_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use ethercrab_wire::{EtherCrabWireRead, EtherCrabWireWrite};

    // Manual impl because `port` is a special case: it is a `u8` in a four bit field, so
    // an arbitrary value above 15 would be truncated on pack and the round trip could not
    // hold. Same reason and same shape as `MailboxHeader`'s impl one directory up, whose
    // `counter` is a `u8` in three bits.
    impl<'a> Arbitrary<'a> for EoeHeader {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                frame_type: Arbitrary::arbitrary(u)?,
                port: u.choose_index(16)? as u8,
                last_fragment: Arbitrary::arbitrary(u)?,
                time_append: Arbitrary::arbitrary(u)?,
                time_request: Arbitrary::arbitrary(u)?,
                second_word: Arbitrary::arbitrary(u)?,
            })
        }
    }

    /// A data fragment. Ported from `libs/SOEM/include/soem/ec_eoe.h`, EOE_HDR_* macros.
    ///
    /// ```text
    /// frameinfo1 = FRAME_TYPE_SET(0) | FRAME_PORT_SET(1) | LAST_FRAGMENT_SET(1)
    ///            = (0 & 0xF)  |  ((1 & 0xF) << 4)  |  ((1 & 0x1) << 8)
    ///            = 0x0000     |  0x0010            |  0x0100          = 0x0110
    ///
    /// frameinfo2 = FRAG_NO_SET(5) | FRAME_OFFSET_SET(2) | FRAME_NO_SET(7)
    ///            = (5 & 0x3F) |  ((2 & 0x3F) << 6) |  ((7 & 0xF) << 12)
    ///            = 0x0005     |  0x0080            |  0x7000          = 0x7085
    /// ```
    ///
    /// Both are 16 bit words, little-endian on the wire: `10 01 85 70`.
    ///
    /// `FragData` and not a response type: for `InitResp` the second word is a result code
    /// (`ec_eoe.c:157`), so fragment numbers read off one would be nonsense.
    const FRAGMENT: [u8; 4] = [0x10, 0x01, 0x85, 0x70];

    #[test]
    fn the_two_header_words_decode_field_by_field() {
        let header = EoeHeader::unpack_from_slice(&FRAGMENT).expect("a four byte EoE header");

        assert_eq!(header.frame_type, FrameType::FragData);
        assert_eq!(header.port, 1);
        assert!(header.last_fragment);
        assert!(!header.time_append);
        assert!(!header.time_request);

        let fragment = header
            .fragment()
            .expect("a data frame carries fragment info");
        assert_eq!(fragment.number, 5);
        assert_eq!(fragment.frame_number, 7);
        assert_eq!(fragment.offset(), Some(64), "2 * 32 bytes");
        assert_eq!(fragment.total_frame_size(), None, "not the first fragment");
        assert_eq!(header.result(), None, "a data frame carries no result");
    }

    #[test]
    fn fragment_zero_carries_the_frame_size_and_not_an_offset() {
        // `ec_eoe.c:391` writes (psize + 31) >> 5 into the offset field of fragment zero,
        // and `:480` reads it back as the buffer size. Reading it as an offset would place
        // the first fragment of a 1514 byte frame at byte 1536 instead of at zero.
        let header = EoeHeader::new(FrameType::FragData, 0).with_fragment(0, 48, 3);
        let fragment = header.fragment().expect("fragment info");

        assert_eq!(
            fragment.total_frame_size(),
            Some(1536),
            "48 * 32, 1514 rounded up"
        );
        assert_eq!(
            fragment.offset(),
            None,
            "fragment zero starts at zero by definition"
        );
    }

    #[test]
    fn every_frame_type_is_assigned_the_right_arm_of_the_union() {
        // Two of the ten used to be pinned. The other eight let the discrimination be
        // rewritten - "all *Resp carry a result", "everything but FragData" - without a
        // single test noticing, and `NoFilterSupport` was unreachable because the address
        // filter responses were on the fragment arm.
        use FrameType::*;

        for frame_type in [InitReq, GetIpParamReq, SetAddrFilterReq, GetAddrFilterReq] {
            assert_eq!(
                EoeHeader::new(frame_type, 0).second_word(),
                SecondWord::Unused,
                "{frame_type:?} is a request; ec_eoe.c writes zero and never reads it"
            );
        }

        assert_eq!(
            EoeHeader::new(FragData, 0).second_word(),
            SecondWord::Fragment(Fragment {
                number: 0,
                raw_offset: 0,
                frame_number: 0
            }),
            "only a data frame carries fragment bookkeeping"
        );

        for frame_type in [
            InitResp,
            InitRespTimestamp,
            SetAddrFilterResp,
            GetIpParamResp,
            GetAddrFilterResp,
        ] {
            assert_eq!(
                EoeHeader::new(frame_type, 0).second_word(),
                SecondWord::Result(Ok(EoeResult::Success)),
                "{frame_type:?} answers a request, so its second word is that answer"
            );
        }
    }

    #[test]
    fn a_refused_address_filter_is_reachable() {
        // If the address filter responses sat on the fragment arm, `NoFilterSupport` would
        // be a result code no caller could ever receive on the response it belongs to.
        // (It is not exclusive to them - nothing stops a device putting it on any
        // response - but this is the one it is defined for.) Bytes: type 5, result 0x0401.
        let raw = [0x05, 0x00, 0x01, 0x04];
        let header = EoeHeader::unpack_from_slice(&raw).expect("a header");

        assert_eq!(header.result(), Some(Ok(EoeResult::NoFilterSupport)));
        assert_eq!(header.fragment(), None);
    }

    #[test]
    fn a_request_claims_no_frame_size() {
        // The third state. With only two arms a request fell into the fragment one and
        // cheerfully reported a zero byte frame.
        let header = EoeHeader::new(FrameType::GetIpParamReq, 0);

        assert_eq!(header.fragment(), None);
        assert_eq!(header.result(), None);
        assert_eq!(header.second_word(), SecondWord::Unused);
    }

    #[test]
    fn a_response_carries_a_result_where_a_data_frame_carries_fragment_info() {
        // The union in `ec_EOEt`. A SubDevice refusing a Set-IP for lack of DHCP replies
        // with frame type 3 and result 0x0202: bytes `03 00 02 02`.
        let raw = [0x03, 0x00, 0x02, 0x02];
        let header = EoeHeader::unpack_from_slice(&raw).expect("a header");

        assert_eq!(header.frame_type, FrameType::InitResp);
        assert_eq!(header.result(), Some(Ok(EoeResult::NoDhcpSupport)));
        assert_eq!(
            header.fragment(),
            None,
            "reading fragment numbers off a result code would be nonsense"
        );
    }

    #[test]
    fn an_undefined_result_code_is_reported_and_does_not_fail_the_header() {
        // 0x0003 is no EOE_RESULT_*. The header itself is still well formed, and the raw
        // value is worth passing on rather than discarding.
        let raw = [0x03, 0x00, 0x03, 0x00];
        let header = EoeHeader::unpack_from_slice(&raw).expect("a header");

        assert_eq!(header.result(), Some(Err(0x0003)));
    }

    #[test]
    fn time_append_and_time_request_are_not_the_same_bit() {
        // Bits 9 and 10. `ec_eoe.c:520` shortens the payload by four bytes on time_append,
        // so swapping them truncates every frame of a SubDevice that only asks for a
        // timestamp. Two fixtures, because one with both bits clear pins neither.
        let only_append = EoeHeader::unpack_from_slice(&[0x00, 0x02, 0x00, 0x00]).expect("hdr");
        assert!(only_append.time_append);
        assert!(!only_append.time_request);

        let only_request = EoeHeader::unpack_from_slice(&[0x00, 0x04, 0x00, 0x00]).expect("hdr");
        assert!(!only_request.time_append);
        assert!(only_request.time_request);
    }

    #[test]
    fn every_frame_type_the_c_source_defines_round_trips() {
        // `ec_eoe.h` lines 110-119. All ten, in both directions, so neither an unhandled
        // value nor a one-sided encoding can hide.
        for (value, expected) in [
            (0u8, FrameType::FragData),
            (1, FrameType::InitRespTimestamp),
            (2, FrameType::InitReq),
            (3, FrameType::InitResp),
            (4, FrameType::SetAddrFilterReq),
            (5, FrameType::SetAddrFilterResp),
            (6, FrameType::GetIpParamReq),
            (7, FrameType::GetIpParamResp),
            (8, FrameType::GetAddrFilterReq),
            (9, FrameType::GetAddrFilterResp),
        ] {
            let raw = [value, 0x00, 0x00, 0x00];
            let header = EoeHeader::unpack_from_slice(&raw).expect("a header");
            assert_eq!(header.frame_type, expected, "decoding frame type {value}");

            let mut buffer = [0u8; 4];
            EoeHeader::new(expected, 0)
                .pack_to_slice(&mut buffer)
                .expect("four bytes");
            assert_eq!(buffer, raw, "encoding frame type {value}");
        }
    }

    #[test]
    fn an_undefined_frame_type_is_an_error_and_not_a_panic() {
        // 10..=15 fit in the four bit field but mean nothing. A SubDevice that sends one
        // must not take the MainDevice down with it.
        for value in 10u8..=15 {
            let raw = [value, 0x00, 0x00, 0x00];
            assert!(
                EoeHeader::unpack_from_slice(&raw).is_err(),
                "frame type {value} must be rejected"
            );
        }
    }

    #[test]
    fn every_result_code_the_c_source_defines_is_covered() {
        // `ec_eoe.h` lines 122-127.
        for (value, expected) in [
            (0x0000u16, EoeResult::Success),
            (0x0001, EoeResult::UnspecifiedError),
            (0x0002, EoeResult::UnsupportedFrameType),
            (0x0201, EoeResult::NoIpSupport),
            (0x0202, EoeResult::NoDhcpSupport),
            (0x0401, EoeResult::NoFilterSupport),
        ] {
            assert_eq!(
                EoeResult::unpack_from_slice(&value.to_le_bytes()),
                Ok(expected),
                "result {value:#06x}"
            );
            assert_eq!(
                EoeHeader::new(FrameType::InitResp, 0)
                    .with_result(expected)
                    .result(),
                Some(Ok(expected))
            );
        }
        assert!(EoeResult::unpack_from_slice(&0x0003u16.to_le_bytes()).is_err());
    }

    #[test]
    fn a_header_survives_being_written_and_read_back() {
        let original = EoeHeader {
            frame_type: FrameType::FragData,
            port: 0b1010,
            last_fragment: true,
            time_append: false,
            time_request: true,
            second_word: 0,
        }
        .with_fragment(0x3F, 0x2A, 0x0F);

        let mut buffer = [0u8; 4];
        original
            .pack_to_slice(&mut buffer)
            .expect("four bytes are enough");

        assert_eq!(
            EoeHeader::unpack_from_slice(&buffer),
            Ok(original),
            "wrote {buffer:02x?}"
        );
    }

    #[test]
    fn the_word_written_is_the_word_the_c_macros_would_write() {
        // The same numbers as FRAGMENT above, built instead of parsed. If the encoder and
        // the decoder ever agreed on a wrong layout, only a fixed byte sequence would
        // notice - a round trip would not.
        let header = EoeHeader {
            frame_type: FrameType::FragData,
            port: 1,
            last_fragment: true,
            time_append: false,
            time_request: false,
            second_word: 0,
        }
        .with_fragment(5, 2, 7);

        let mut buffer = [0u8; 4];
        header.pack_to_slice(&mut buffer).expect("four bytes");

        assert_eq!(buffer, FRAGMENT);
    }

    #[test]
    fn a_value_too_wide_for_its_field_cannot_spill_into_the_next_one() {
        // `EOE_HDR_FRAG_NO_SET` masks with 0x3F before shifting. Without the mask a
        // fragment number of 64 would land in the frame offset and silently move the
        // fragment somewhere else in the frame.
        let header = EoeHeader::new(FrameType::FragData, 0).with_fragment(64, 64, 16);
        let fragment = header.fragment().expect("fragment info");

        assert_eq!(fragment.number, 0);
        assert_eq!(fragment.raw_offset, 0);
        assert_eq!(fragment.frame_number, 0);
    }

    #[test]
    fn a_port_wider_than_its_field_is_truncated_and_not_rejected() {
        // `port` is a `u8` in a four bit field, the same shape the rest of this crate's
        // wire types use. A property test over arbitrary headers finds this immediately -
        // pack then unpack is NOT the identity for any value above 15 - so the edge is
        // written down here instead of being fuzzed away.
        let mut buffer = [0u8; 4];
        EoeHeader::new(FrameType::FragData, 0xAB)
            .pack_to_slice(&mut buffer)
            .expect("four bytes");

        let read_back = EoeHeader::unpack_from_slice(&buffer).expect("a header");

        assert_eq!(
            read_back.port, 0x0B,
            "the high nibble is dropped, not reported"
        );
    }

    #[test]
    fn eoe_header_fuzz() {
        // The convention every other wire type in this crate follows. The fixed byte
        // sequences above pin one value per field; this covers the rest of the space.
        heckcheck::check(|header: EoeHeader| {
            let mut packed = [0u8; 4];
            header.pack_to_slice(&mut packed).expect("Pack");

            let unpacked = EoeHeader::unpack_from_slice(&packed).expect("Unpack");

            pretty_assertions::assert_eq!(header, unpacked);
            // The comparison is implied by the line above - `second_word()` is a pure
            // function of fields that were just compared. What earns the line is the
            // *call*: without it this closure never enters the union at all, and a
            // `panic!()` in `second_word()` left it passing. Other tests in this module
            // do catch that, so this is a second lock, not the only one.
            pretty_assertions::assert_eq!(header.second_word(), unpacked.second_word());

            Ok(())
        });
    }
}

#[cfg(test)]
mod ip_param_tests {
    use super::*;

    /// Ported from `ecx_EOEsetIp`, `libs/SOEM/src/ec_eoe.c:74-138`.
    ///
    /// The payload of a Set-IP request:
    ///
    /// ```text
    /// data[0]      include flags     EOE_PARAM_* , ec_eoe.h:102-107
    /// data[1..4]   reserved          data_offset starts at EOE_PARAM_OFFSET = 4
    /// data[4..]    the included fields, in flag order:
    ///              MAC 6, IP 4, subnet 4, gateway 4, DNS IP 4, DNS name 32
    /// ```
    ///
    /// The DNS name always occupies 32 bytes even when shorter - `ec_eoe.c:131` copies
    /// `EOE_DNS_NAME_LENGTH` unconditionally, with the comment "TwinCAT include
    /// EOE_DNS_NAME_LENGTH chars even if name is shorter".
    #[test]
    fn an_ip_and_a_subnet_pack_into_the_payload_soem_would_write() {
        let param = IpParam {
            ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
            subnet: Some(Ipv4Addr::new(255, 255, 255, 0)),
            ..IpParam::default()
        };

        let mut buffer = [0u8; 12];
        let written = param
            .pack_to_slice(&mut buffer)
            .expect("room for flags plus two addresses");

        assert_eq!(
            written,
            &[
                0x06, // IP_INCLUDE | SUBNET_IP_INCLUDE
                0x00, 0x00, 0x00, // reserved up to EOE_PARAM_OFFSET
                10, 1, 168, 192, // 192.168.1.10, last octet first
                0, 255, 255, 255, // 255.255.255.0, last octet first
            ]
        );
    }

    #[test]
    fn an_address_goes_on_the_wire_backwards() {
        // `EOE_ip_uint32_to_byte` (`ec_eoe.c:26-32`) writes byte_ip[3] = 1st octet. Getting
        // this the usual way round turns 192.168.1.10 into 10.1.168.192 - a device that
        // answers on neither address and a fault nobody traces back to four bytes.
        let param = IpParam {
            ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            ..IpParam::default()
        };

        let mut buffer = [0u8; 8];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(&written[4..8], &[4, 3, 2, 1]);
    }

    #[test]
    fn a_dns_name_occupies_thirty_two_bytes_however_short_it_is() {
        let param = IpParam {
            dns_name: Some(heapless::String::try_from("edge").expect("fits")),
            ..IpParam::default()
        };

        let mut buffer = [0u8; 40];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(written.len(), 4 + 32, "flags word plus the full name field");
        assert_eq!(&written[4..8], b"edge");
        assert!(
            written[8..].iter().all(|byte| *byte == 0),
            "the rest of the field is zero, not omitted"
        );
    }

    #[test]
    fn nothing_set_is_a_flags_word_and_no_fields() {
        let mut buffer = [0u8; 8];
        let written = IpParam::default().pack_to_slice(&mut buffer).expect("room");

        assert_eq!(written, &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn what_was_packed_comes_back_out() {
        let param = IpParam {
            mac: Some([0x02, 0x00, 0x00, 0x11, 0x22, 0x33]),
            ip: Some(Ipv4Addr::new(10, 0, 0, 42)),
            subnet: Some(Ipv4Addr::new(255, 0, 0, 0)),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns_ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
            dns_name: Some(heapless::String::try_from("murr").expect("fits")),
        };

        let mut buffer = [0u8; 64];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(IpParam::unpack_from_slice(written), Ok(param));
    }

    #[test]
    fn a_payload_that_stops_short_is_an_error_and_not_a_panic() {
        // A device that sets a flag and then truncates the frame must not take us down.
        let claims_an_ip = [0x02, 0x00, 0x00, 0x00, 10, 0];

        assert!(IpParam::unpack_from_slice(&claims_an_ip).is_err());
        assert!(
            IpParam::unpack_from_slice(&[]).is_err(),
            "not even the flags word"
        );
    }

    #[test]
    fn a_buffer_too_small_to_write_into_is_an_error_and_not_a_panic() {
        let param = IpParam {
            ip: Some(Ipv4Addr::new(1, 1, 1, 1)),
            ..IpParam::default()
        };

        let mut buffer = [0u8; 7];
        assert!(param.pack_to_slice(&mut buffer).is_err());
    }

    #[test]
    fn all_six_fields_land_where_the_c_source_puts_them() {
        // The round trip cannot see a field pair that was swapped on both sides, and the
        // two-field fixture above pins only IP and subnet. This pins every flag bit and
        // every offset against absolute bytes.
        let param = IpParam {
            mac: Some([1, 2, 3, 4, 5, 6]),
            ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            subnet: Some(Ipv4Addr::new(255, 255, 0, 0)),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 254)),
            dns_ip: Some(Ipv4Addr::new(9, 9, 9, 9)),
            dns_name: Some(heapless::String::try_from("dns").expect("fits")),
        };

        let mut buffer = [0u8; 64];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(written[0], 0x3F, "all six include flags");
        assert_eq!(&written[1..4], &[0, 0, 0], "reserved");
        assert_eq!(&written[4..10], &[1, 2, 3, 4, 5, 6], "MAC");
        assert_eq!(&written[10..14], &[1, 0, 0, 10], "IP, last octet first");
        assert_eq!(&written[14..18], &[0, 0, 255, 255], "subnet");
        assert_eq!(&written[18..22], &[254, 0, 0, 10], "gateway");
        assert_eq!(&written[22..26], &[9, 9, 9, 9], "DNS server");
        assert_eq!(&written[26..29], b"dns", "DNS name");
        assert_eq!(written.len(), 4 + 6 + 4 + 4 + 4 + 4 + 32);
    }

    #[test]
    fn the_padding_is_zeroed_and_not_inherited_from_the_caller() {
        // Every other test hands in an already zeroed buffer, so neither the reserved
        // bytes nor the DNS padding were pinned by anything: deleting both `fill(0)` calls
        // left the suite green.
        let param = IpParam {
            dns_name: Some(heapless::String::try_from("hi").expect("fits")),
            ..IpParam::default()
        };

        let mut buffer = [0xAAu8; 64];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(&written[1..4], &[0, 0, 0], "reserved bytes, not 0xAA");
        assert_eq!(&written[4..6], b"hi");
        assert!(
            written[6..].iter().all(|byte| *byte == 0),
            "the rest of the name field is zero: {:02x?}",
            &written[6..]
        );
    }

    #[test]
    fn a_dns_name_that_is_not_utf8_says_so() {
        // Reporting this as "buffer too short" sends whoever reads the log looking for a
        // truncated frame that is not there.
        let mut payload = [0u8; 36];
        payload[0] = 0x20; // DNS_NAME_INCLUDE
        payload[4] = 0xFF;
        payload[5] = 0xFE;

        assert_eq!(
            IpParam::unpack_from_slice(&payload),
            Err(WireError::InvalidUtf8)
        );
    }

    #[test]
    fn a_name_that_fills_the_field_survives() {
        let long = "x".repeat(IpParam::DNS_NAME_LENGTH);
        let param = IpParam {
            dns_name: Some(heapless::String::try_from(long.as_str()).expect("exactly 32")),
            ..IpParam::default()
        };

        let mut buffer = [0u8; 64];
        let written = param.pack_to_slice(&mut buffer).expect("room");

        assert_eq!(IpParam::unpack_from_slice(written), Ok(param));
    }
}
