//! Ethernet over EtherCAT (EoE), ETG.1000.6.
//!
//! Ported from SOEM's `ec_eoe.c` / `ec_eoe.h`. Every wire test below names the macro or
//! function it was derived from, and the byte sequences are computed from those macros
//! rather than read off a description of the protocol.

use crate::fmt;
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

/// The largest port an EoE header can name: the field is four bits wide.
const MAX_PORT: u8 = 0x0F;

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

// Hand written because `core::net::Ipv4Addr` has no `defmt::Format`, so the derive cannot
// see through `Option<Ipv4Addr>`. Addresses go out as their four octets, which is what a
// reader wants anyway. Same shape as `EthernetAddress`'s impl in `ethernet.rs`.
#[cfg(feature = "defmt")]
impl defmt::Format for IpParam {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "IpParam {{ mac: {}, ip: {}, subnet: {}, gateway: {}, dns_ip: {}, dns_name: {} }}",
            self.mac,
            self.ip.map(|address| address.octets()),
            self.subnet.map(|address| address.octets()),
            self.gateway.map(|address| address.octets()),
            self.dns_ip.map(|address| address.octets()),
            self.dns_name.as_deref()
        );
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
    ///
    /// `port` is a four bit field. This is the raw header type, so nothing is checked
    /// here: the value is kept as given and only **the wire** truncates it, at pack time -
    /// a header built with port 255 still reads back 255 and goes out as 15.
    /// [`Fragments::new`](crate::Fragments::new) rejects such a port, and is the way to
    /// build fragments.
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
    /// value too large for its field cannot spill into a neighbour - but it is **not**
    /// reported either, so `frame_number` 16 goes out as 0. `raw_offset` is in units of 32
    /// bytes and means the frame size on fragment zero - see [`Fragment`].
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
            match field {
                Field::Bytes(bytes) => buffer[at..at + bytes.len()].copy_from_slice(bytes),
                Field::Address(address) => {
                    let [a, b, c, d] = address.octets();
                    // Last octet first - see the note on `IpParam`.
                    buffer[at..at + 4].copy_from_slice(&[d, c, b, a]);
                }
            }

            // No check that `bytes <= width`: both sources are bounded by their type -
            // a `[u8; 6]` MAC and a `heapless::String<32>` name against a 32 wide slot.
            //
            // A third source that is not bounded would be a real problem, and not a loud
            // one. Only for the *last* present field does an overlong write run off the
            // buffer and panic; for any field before it, `at` still advances by `width`,
            // so the next field simply overwrites the overflow and the frame goes out
            // silently wrong. Whoever adds a field checks its width here.
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

/// Why an Ethernet frame cannot be fragmented for a given mailbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum FragmentError {
    /// The mailbox cannot carry a whole 32 byte block of EoE payload.
    ///
    /// The reference implementation has an infinite loop here: `((maxdata >> 5) << 5)` is
    /// zero below 32, so a payload larger than the mailbox produces empty fragments for
    /// ever. Only `maxdata < 0` is guarded (`ec_eoe.c:351`).
    MailboxTooSmall {
        /// EoE payload capacity of the mailbox, in bytes.
        capacity: usize,
        /// Length of the frame that would have had to be split, in bytes.
        length: usize,
    },
    /// The frame is longer than a six bit offset can name.
    ///
    /// The offset field counts 32 byte blocks, so it stops at `63 * 32`. Fragment zero
    /// has to fit the *whole frame size* into that same field. Ethernet tops out well
    /// below it; a caller handing over more would otherwise get a frame whose offsets
    /// wrap silently.
    FrameTooLong {
        /// Length of the frame that was offered, in bytes.
        length: usize,
        /// The largest length that can be expressed.
        limit: usize,
    },
    /// The port does not fit the four bits EoE gives it.
    ///
    /// Unlike the frame number - a counter the reference implementation deliberately lets
    /// wrap - a port index above 15 is a mistake, and masking it would send the frame to
    /// a different port than the caller asked for.
    PortTooWide {
        /// The port that was asked for.
        port: u8,
    },
}

impl core::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MailboxTooSmall { capacity, length } => write!(
                f,
                "a {} byte frame must be split, and a mailbox of {} bytes cannot carry a whole 32 byte block",
                length, capacity
            ),
            Self::FrameTooLong { length, limit } => write!(
                f,
                "an ethernet frame of {} bytes is longer than the {} bytes an EoE offset can name",
                length, limit
            ),
            Self::PortTooWide { port } => {
                write!(f, "port {} does not fit the four bits EoE gives it", port)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FragmentError {}

/// Splits an Ethernet frame into EoE fragments.
///
/// Ported from `ecx_EOEsend` (`ec_eoe.c:333-430`). Every fragment but the last carries the
/// mailbox capacity rounded **down** to a multiple of 32 bytes; the last carries what is
/// left and sets [`EoeHeader::last_fragment`].
///
/// Pure: it borrows the frame and yields headers and slices of it, and does no I/O.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Fragments<'a> {
    frame: &'a [u8],
    /// Bytes of EoE payload one mailbox can carry: `mbx_l - 0x0A` (`ec_eoe.c:344`).
    capacity: usize,
    /// `capacity` rounded down to a whole number of 32 byte blocks.
    block: usize,
    frame_number: u8,
    port: u8,
    offset: usize,
    number: u8,
    done: bool,
}

impl<'a> Fragments<'a> {
    /// Blocks are 32 bytes, both for the fragment size and for the offset field.
    const BLOCK: usize = 32;

    /// The offset field is six bits, counting blocks.
    const MAX_BLOCKS: usize = 0x3F;
    const MAX_BLOCKS_U8: u8 = 0x3F;

    /// The longest frame whose size and offsets both fit the six bit field.
    pub const MAX_FRAME: usize = Self::MAX_BLOCKS * Self::BLOCK;

    /// Prepares to split `frame` for a mailbox that can carry `capacity` bytes of EoE
    /// payload.
    ///
    /// `frame_number` identifies this frame at the receiver and has to differ from the
    /// frame before it; it is **not** advanced here, because a counter is state and this
    /// is an iterator over borrowed data. In the reference implementation it is a `static
    /// uint8_t` bumped once per frame (`ec_eoe.c:341`, `:392`), so the caller now owns it.
    ///
    /// Only its low four bits reach the wire, so it repeats every 16 frames. That is the
    /// reference implementation's own behaviour - `:394` hands the unmasked counter to
    /// `EOE_HDR_FRAME_NO_SET`, which masks it - and it is harmless, because the fragments
    /// of one frame follow each other. A plain `u8` counter is therefore the right thing
    /// to pass, and is not rejected when it passes 15.
    ///
    /// # Errors
    ///
    /// [`FragmentError`] if the mailbox cannot carry a whole block of a frame that has to
    /// be split, the frame is longer than the offset field can name, or the port does not
    /// fit its four bit field. The frame number is masked, not rejected - see above.
    pub fn new(
        frame: &'a [u8],
        capacity: usize,
        frame_number: u8,
        port: u8,
    ) -> Result<Self, FragmentError> {
        if port > MAX_PORT {
            return Err(FragmentError::PortTooWide { port });
        }

        // Rounded down, as `((maxdata >> 5) << 5)` does - a fragment that is not a whole
        // number of blocks would give the next one an offset the field cannot express.
        let block = (capacity / Self::BLOCK) * Self::BLOCK;

        // Length first: it is the more specific answer. A 3000 byte frame offered to a
        // 31 byte mailbox is too long whatever the mailbox does.
        if frame.len() > Self::MAX_FRAME {
            return Err(FragmentError::FrameTooLong {
                length: frame.len(),
                limit: Self::MAX_FRAME,
            });
        }

        // Only a frame that actually has to be split needs whole blocks. A mailbox of 40
        // bytes carries a 10 byte frame perfectly well, and the reference implementation
        // sends it - rejecting it outright would make such a SubDevice unusable for EoE.
        if block == 0 && frame.len() > capacity {
            return Err(FragmentError::MailboxTooSmall {
                capacity,
                length: frame.len(),
            });
        }

        Ok(Self {
            frame,
            capacity,
            block,
            frame_number,
            port,
            offset: 0,
            number: 0,
            done: false,
        })
    }

    /// The number of 32 byte blocks `bytes` occupies, rounded up.
    ///
    /// `(psize + 31) >> 5` in the reference implementation.
    fn blocks(bytes: usize) -> u8 {
        // Cannot saturate: `new` caps the frame at `MAX_FRAME`, so this is at most 63.
        // Saturating to 255 would be worse than useless - the field masks it back to 63
        // and puts a wrong frame size on the wire.
        u8::try_from(bytes.div_ceil(Self::BLOCK)).unwrap_or(Self::MAX_BLOCKS_U8)
    }
}

impl<'a> Iterator for Fragments<'a> {
    type Item = (EoeHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let rest = self.frame.get(self.offset..)?;

        // `ec_eoe.c:367-372`: the rounding down to whole blocks applies **only** when the
        // remainder does not fit in the mailbox. A remainder that fits goes out whole,
        // even when it is not a multiple of 32 - it is the last fragment, so no later
        // offset has to name a boundary inside it. Rounding unconditionally would split a
        // 118 byte remainder into 96 + 22 and cost a mailbox round trip for nothing.
        let size = if rest.len() > self.capacity {
            self.block
        } else {
            rest.len()
        };
        let last = size == rest.len();

        let data = rest.get(..size)?;

        // Fragment zero names the whole frame; every other one names where it starts.
        // The overloading is `ec_eoe.c:387-391` - see `Fragment`.
        let raw_offset = if self.number == 0 {
            Self::blocks(self.frame.len())
        } else {
            Self::blocks(self.offset)
        };

        let mut header = EoeHeader::new(FrameType::FragData, self.port).with_fragment(
            self.number,
            raw_offset,
            self.frame_number,
        );
        header.last_fragment = last;

        self.offset += size;
        self.number += 1;
        self.done = last;

        Some((header, data))
    }
}

/// Why a fragment could not be added to the frame being reassembled.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ReassemblyError {
    /// The frame is not a data fragment, so it carries no part of an Ethernet frame.
    NotAFragment {
        /// What it was instead.
        frame_type: FrameType,
    },
    /// A fragment arrived out of order.
    OutOfOrder {
        /// The fragment number that was due.
        expected: u8,
        /// The one that arrived.
        received: u8,
    },
    /// A fragment belongs to a different frame than the one being reassembled.
    WrongFrame {
        /// The frame number being reassembled.
        expected: u8,
        /// The one the fragment named.
        received: u8,
    },
    /// A fragment named an offset other than where it has to go.
    WrongOffset {
        /// Where the fragment has to start, in bytes.
        expected: u16,
        /// Where it said it starts.
        received: u16,
    },
    /// Fragment zero announced a frame larger than the buffer.
    FrameTooLongForBuffer {
        /// The frame size the fragment announced, in bytes.
        announced: usize,
        /// The buffer's capacity, in bytes.
        capacity: usize,
    },
    /// The fragments add up to more than fragment zero announced.
    Overrun {
        /// The frame size fragment zero announced, in bytes.
        announced: usize,
        /// What the frame would grow to with this fragment, in bytes.
        would_be: usize,
    },
    /// The last fragment says a timestamp is appended, and the frame is too short for one.
    TimestampMissing {
        /// Bytes the frame had assembled to, in total.
        total: usize,
    },
    /// A fragment arrived for a different port of the SubDevice.
    ///
    /// Two ports fragmenting at the same time can otherwise splice into one frame, half of
    /// each: if their frame numbers happen to agree, fragment number, frame number and
    /// offset all line up and the halves fit together without a complaint.
    ///
    /// Checked on **every** fragment. The reference implementation checks it once, on
    /// fragment zero (`ec_eoe.c:487`), which leaves the same gap from fragment one onward -
    /// its `port` argument says which port the caller *wants*, not which one the arriving
    /// fragments carry.
    WrongPort {
        /// The port this reassembly is for.
        expected: u8,
        /// The port the fragment named.
        received: u8,
    },
}

impl core::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAFragment { frame_type } => {
                write!(f, "{:?} carries no ethernet fragment", frame_type)
            }
            Self::OutOfOrder { expected, received } => write!(
                f,
                "fragment {} arrived where fragment {} was due",
                received, expected
            ),
            Self::WrongFrame { expected, received } => write!(
                f,
                "a fragment of frame {} arrived while frame {} was being reassembled",
                received, expected
            ),
            Self::WrongOffset { expected, received } => write!(
                f,
                "a fragment says it starts at byte {} but has to start at {}",
                received, expected
            ),
            Self::FrameTooLongForBuffer {
                announced,
                capacity,
            } => write!(
                f,
                "an announced frame of {} bytes does not fit a buffer of {}",
                announced, capacity
            ),
            Self::Overrun {
                announced,
                would_be,
            } => write!(
                f,
                "the fragments add up to {} bytes where {} were announced",
                would_be, announced
            ),
            Self::TimestampMissing { total } => write!(
                f,
                "the last fragment promises an appended timestamp but the frame is only {} bytes",
                total
            ),
            Self::WrongPort { expected, received } => write!(
                f,
                "a fragment for port {} arrived while reassembling port {}",
                received, expected
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReassemblyError {}

/// What a fragment completed.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Reassembled<'a> {
    /// The frame is not finished; more fragments are due.
    More,
    /// A complete Ethernet frame.
    Frame(&'a [u8]),
}

/// Puts EoE fragments back together into an Ethernet frame.
///
/// Ported from `ecx_EOErecv` (`ec_eoe.c:437-557`), with one deliberate difference. When a
/// fragment does not fit the buffer, the reference implementation **drops it silently**
/// (`:509`) and does not advance its fragment counter, so the *next* fragment fails the
/// order check and the error names the wrong thing. Here an overrun is reported where it
/// happens.
///
/// The frame is assembled in a caller supplied buffer, so this does no allocation.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reassembly<'buf> {
    buffer: &'buf mut [u8],
    port: u8,
    frame: Option<Partial>,
}

/// The frame currently being put back together.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Partial {
    number: u8,
    next_fragment: u8,
    /// Bytes written so far, which is also where the next fragment has to start.
    filled: usize,
    /// What fragment zero announced, rounded up to 32 bytes.
    announced: usize,
}

impl<'buf> Reassembly<'buf> {
    /// A reassembly for one `port` of a SubDevice, writing into `buffer`.
    ///
    /// The buffer has to be large enough for the frames the SubDevice sends; a frame that
    /// announces more is refused before anything is written.
    ///
    /// The port is not decoration: a SubDevice with two ports can fragment on both at
    /// once, and without it the two frames splice into one, half of each.
    ///
    /// # Errors
    ///
    /// [`FragmentError::PortTooWide`] if `port` does not fit the four bits EoE gives it -
    /// such a reassembly would reject every fragment off the wire and never say why.
    /// [`Fragments::new`] refuses the same value.
    pub fn new(buffer: &'buf mut [u8], port: u8) -> Result<Self, FragmentError> {
        if port > MAX_PORT {
            return Err(FragmentError::PortTooWide { port });
        }

        Ok(Self {
            buffer,
            port,
            frame: None,
        })
    }

    /// Adds one fragment.
    ///
    /// # Errors
    ///
    /// [`ReassemblyError`] if the fragment is not a data fragment, does not belong to the
    /// frame being reassembled, or does not fit.
    pub fn push(
        &mut self,
        header: EoeHeader,
        data: &[u8],
    ) -> Result<Reassembled<'_>, ReassemblyError> {
        let Some(fragment) = header.fragment() else {
            return Err(ReassemblyError::NotAFragment {
                frame_type: header.frame_type,
            });
        };

        // Every fragment, not only fragment zero - see `ReassemblyError::WrongPort`.
        if header.port != self.port {
            return Err(ReassemblyError::WrongPort {
                expected: self.port,
                received: header.port,
            });
        }

        // A fragment zero always starts a new frame, even mid-reassembly: a SubDevice that
        // gives up on one simply begins the next. Refusing it would wedge the link, and
        // the reference implementation lets it through as well - only to fail it one check
        // later on the frame number, which names the wrong problem (`ec_eoe.c:467-476`).
        if fragment.number == 0 {
            let announced = usize::from(fragment.total_frame_size().unwrap_or_default());

            if announced > self.buffer.len() {
                return Err(ReassemblyError::FrameTooLongForBuffer {
                    announced,
                    capacity: self.buffer.len(),
                });
            }

            self.frame = Some(Partial {
                number: fragment.frame_number,
                next_fragment: 0,
                filled: 0,
                announced,
            });
        }

        let mut partial = self.frame.ok_or(ReassemblyError::OutOfOrder {
            expected: 0,
            received: fragment.number,
        })?;

        if fragment.number != partial.next_fragment {
            return Err(ReassemblyError::OutOfOrder {
                expected: partial.next_fragment,
                received: fragment.number,
            });
        }

        if fragment.frame_number != partial.number {
            return Err(ReassemblyError::WrongFrame {
                expected: partial.number,
                received: fragment.frame_number,
            });
        }

        // Fragment zero's field carries the size, not an offset, so there is nothing to
        // compare it against.
        if let Some(offset) = fragment.offset() {
            // `filled` never exceeds `announced`, which is at most 63 * 32.
            let expected = u16::try_from(partial.filled).unwrap_or(u16::MAX);

            if offset != expected {
                return Err(ReassemblyError::WrongOffset {
                    expected,
                    received: offset,
                });
            }
        }

        let end = partial.filled + data.len();

        // `announced` was checked against the buffer when fragment zero arrived, so this
        // one comparison covers both: the device cannot send more than it promised, and
        // what it promised fits.
        if end > partial.announced {
            return Err(ReassemblyError::Overrun {
                announced: partial.announced,
                would_be: end,
            });
        }

        // `end <= announced <= buffer.len()`, both checked above - the same reasoning as
        // at the end of this function, and the same crate idiom for it.
        fmt::unwrap_opt!(self.buffer.get_mut(partial.filled..end)).copy_from_slice(data);

        partial.filled = end;
        partial.next_fragment += 1;
        self.frame = Some(partial);

        if !header.last_fragment {
            return Ok(Reassembled::More);
        }

        // The frame is finished either way: the last fragment has been consumed, so
        // nothing can follow it. Clearing the state before the timestamp check keeps a
        // rejected frame from leaving a half consumed one behind.
        self.frame = None;

        // The timestamp is four bytes at the very end and is not part of the frame.
        let length = if header.time_append {
            partial
                .filled
                .checked_sub(4)
                .ok_or(ReassemblyError::TimestampMissing {
                    total: partial.filled,
                })?
        } else {
            partial.filled
        };

        // `length <= filled <= announced <= buffer.len()`, all checked above. The crate's
        // own idiom for a slice that cannot be out of range: an empty one would hand the
        // caller a zero length ethernet frame, and an `Overrun` would describe an
        // *under*run - `length` is never above `announced`.
        Ok(Reassembled::Frame(fmt::unwrap_opt!(
            self.buffer.get(..length)
        )))
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
            // Deliberately not 8.8.8.8: a palindromic address reads the same in both
            // byte orders, so it pins the offset and nothing else. No address in these
            // tests is a palindrome, for that reason.
            dns_ip: Some(Ipv4Addr::new(8, 7, 6, 5)),
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
            dns_ip: Some(Ipv4Addr::new(9, 8, 7, 6)),
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
        assert_eq!(
            &written[22..26],
            &[6, 7, 8, 9],
            "DNS server, last octet first"
        );
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

    #[test]
    fn a_dns_name_flag_over_a_short_payload_is_an_error() {
        // The truncation test above only covers the four byte IP field, so a reader that
        // clamped its bounds instead of rejecting them stayed green. Here the flag
        // promises 32 bytes and one arrives.
        let claims_a_name = [0x20, 0x00, 0x00, 0x00, b'a'];

        assert_eq!(
            IpParam::unpack_from_slice(&claims_a_name),
            Err(WireError::ReadBufferTooShort)
        );
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;

    /// The EoE payload capacity of a mailbox, from `ec_eoe.c:344`:
    /// `maxdata = mbx_l - 0x0A` - six bytes of mailbox header plus four of EoE header.
    const MAILBOX: usize = 128;
    const MAX_DATA: usize = MAILBOX - 0x0A;

    #[test]
    fn a_frame_that_fits_is_one_last_fragment() {
        let payload = [0xABu8; 40];
        let fragments: Vec<_> = Fragments::new(&payload, MAX_DATA, 3, 0)
            .expect("40 bytes fit")
            .collect();

        assert_eq!(fragments.len(), 1);

        let (header, data) = &fragments[0];
        assert!(header.last_fragment);
        assert_eq!(header.frame_type, FrameType::FragData);
        assert_eq!(data, &&payload[..]);

        let fragment = header.fragment().expect("a data frame");
        assert_eq!(fragment.number, 0);
        assert_eq!(fragment.frame_number, 3);
        assert_eq!(
            fragment.total_frame_size(),
            Some(64),
            "40 rounded up to a multiple of 32, as `(psize + 31) >> 5` does"
        );
    }

    #[test]
    fn a_longer_frame_is_cut_on_thirty_two_byte_boundaries() {
        // `ec_eoe.c:371`: txframesize = ((maxdata >> 5) << 5). 118 bytes of capacity
        // become 96, not 118 - a fragment that is not a multiple of 32 would make the
        // next one's offset unrepresentable.
        let payload = [0u8; 250];
        let fragments: Vec<_> = Fragments::new(&payload, MAX_DATA, 0, 0)
            .expect("fits")
            .collect();

        let sizes: Vec<_> = fragments.iter().map(|(_, data)| data.len()).collect();
        assert_eq!(sizes, vec![96, 96, 58], "96 = (118 >> 5) << 5");

        assert!(!fragments[0].0.last_fragment);
        assert!(!fragments[1].0.last_fragment);
        assert!(fragments[2].0.last_fragment);
    }

    #[test]
    fn only_the_first_fragment_carries_the_size_the_rest_carry_offsets() {
        let payload = [0u8; 250];
        let fragments: Vec<_> = Fragments::new(&payload, MAX_DATA, 7, 0)
            .expect("fits")
            .collect();

        let first = fragments[0].0.fragment().expect("data frame");
        assert_eq!(first.number, 0);
        assert_eq!(first.total_frame_size(), Some(256), "250 rounded up");
        assert_eq!(first.offset(), None);

        let second = fragments[1].0.fragment().expect("data frame");
        assert_eq!(second.number, 1);
        assert_eq!(second.offset(), Some(96));
        assert_eq!(second.total_frame_size(), None);

        let third = fragments[2].0.fragment().expect("data frame");
        assert_eq!(third.number, 2);
        assert_eq!(third.offset(), Some(192));

        for (header, _) in &fragments {
            assert_eq!(
                header.fragment().expect("data frame").frame_number,
                7,
                "the frame number is the same for every fragment of one frame"
            );
        }
    }

    #[test]
    fn the_fragments_put_back_together_are_the_original() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(1514).collect();
        let rejoined: Vec<u8> = Fragments::new(&payload, MAX_DATA, 0, 0)
            .expect("an ethernet frame fits")
            .flat_map(|(_, data)| data.iter().copied())
            .collect();

        assert_eq!(rejoined, payload);
    }

    #[test]
    fn an_empty_frame_is_still_one_fragment() {
        let fragments: Vec<_> = Fragments::new(&[], MAX_DATA, 0, 0)
            .expect("nothing fits too")
            .collect();

        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].0.last_fragment);
        assert!(fragments[0].1.is_empty());
    }

    #[test]
    fn a_remainder_that_fits_the_mailbox_goes_out_whole() {
        // The band where rounding to 32 would be wrong: 118 bytes fit the mailbox but are
        // not a multiple of 32. `ec_eoe.c:367` rounds ONLY when the remainder does not
        // fit, so this is one fragment, not 96 + 22. Rounding unconditionally costs a
        // mailbox round trip on roughly a quarter of all frame lengths at this size.
        for length in [97, 100, MAX_DATA] {
            let payload = vec![0u8; length];
            let sizes: Vec<_> = Fragments::new(&payload, MAX_DATA, 0, 0)
                .expect("fits")
                .map(|(_, data)| data.len())
                .collect();

            assert_eq!(sizes, vec![length], "a {length} byte frame is one fragment");
        }

        // And 214 bytes, where the first fragment must still be rounded.
        let payload = [0u8; 214];
        let sizes: Vec<_> = Fragments::new(&payload, MAX_DATA, 0, 0)
            .expect("fits")
            .map(|(_, data)| data.len())
            .collect();

        assert_eq!(sizes, vec![96, 118], "round the first, send the rest whole");
    }

    #[test]
    fn a_small_mailbox_still_carries_a_frame_that_fits_in_it() {
        // Rejecting every small mailbox outright would make a SubDevice with a 40 byte
        // mailbox unusable for EoE, although the reference implementation sends short
        // frames through it perfectly well.
        let sizes: Vec<_> = Fragments::new(&[0u8; 10], 31, 0, 0)
            .expect("ten bytes fit thirty one")
            .map(|(_, data)| data.len())
            .collect();

        assert_eq!(sizes, vec![10]);
    }

    #[test]
    fn a_port_that_does_not_fit_four_bits_is_rejected() {
        // Masking would send the frame to a different port than the caller asked for.
        assert_eq!(
            Fragments::new(&[0u8; 4], 64, 0, 255).unwrap_err(),
            FragmentError::PortTooWide { port: 255 }
        );
        assert!(
            Fragments::new(&[0u8; 4], 64, 0, 15).is_ok(),
            "15 still fits"
        );
        // The first rejected value. Without it a five bit limit passes: port 16 is
        // accepted and then packs to port 0 on the wire.
        assert_eq!(
            Fragments::new(&[0u8; 4], 64, 0, 16).unwrap_err(),
            FragmentError::PortTooWide { port: 16 }
        );
    }

    #[test]
    fn a_frame_number_past_fifteen_is_masked_and_not_rejected() {
        // `ec_eoe.c:341` declares `static uint8_t txframeno`, `:392` bumps it without
        // bound and `:394` hands it UNMASKED to EOE_HDR_FRAME_NO_SET. So a plain `u8`
        // counter is exactly what a caller should pass, and rejecting it on the
        // seventeenth frame would break the obvious port of the reference loop.
        let (header, _) = Fragments::new(&[0u8; 4], 64, 17, 0)
            .expect("a counter is allowed to pass fifteen")
            .next()
            .expect("one fragment");

        assert_eq!(
            header.fragment().expect("data frame").frame_number,
            1,
            "17 wraps to 1, as the field is four bits wide"
        );
    }

    #[test]
    fn a_frame_exactly_the_size_of_a_small_mailbox_is_sent_whole() {
        // The boundary the earlier test missed: `frame.len() == capacity` needs no
        // splitting, so a mailbox that holds no whole block is still fine.
        let sizes: Vec<_> = Fragments::new(&[0u8; 31], 31, 0, 0)
            .expect("exactly fits")
            .map(|(_, data)| data.len())
            .collect();

        assert_eq!(sizes, vec![31]);
        assert!(
            Fragments::new(&[0u8; 32], 31, 0, 0).is_err(),
            "one byte more has to be split, and cannot be"
        );
    }

    #[test]
    fn the_error_says_which_frame_could_not_be_split() {
        assert_eq!(
            Fragments::new(&[0u8; 100], 31, 0, 0).unwrap_err(),
            FragmentError::MailboxTooSmall {
                capacity: 31,
                length: 100
            }
        );
        // Length is checked first: too long is the more specific answer.
        assert!(matches!(
            Fragments::new(&[0u8; 3000], 31, 0, 0).unwrap_err(),
            FragmentError::FrameTooLong { .. }
        ));
    }

    #[test]
    fn the_port_reaches_every_fragment() {
        let payload = [0u8; 250];

        for (header, _) in Fragments::new(&payload, MAX_DATA, 0, 5).expect("fits") {
            assert_eq!(header.port, 5);
        }
    }

    #[test]
    fn a_mailbox_too_small_to_carry_a_block_is_rejected() {
        // The trap in the C loop: with maxdata < 32, ((maxdata >> 5) << 5) is zero, so a
        // payload larger than the mailbox produces zero length fragments for ever.
        // `ec_eoe.c:351` only guards `maxdata < 0`.
        assert!(Fragments::new(&[0u8; 100], 31, 0, 0).is_err());
        assert!(
            Fragments::new(&[0u8; 100], 32, 0, 0).is_ok(),
            "32 is enough"
        );
    }

    #[test]
    fn a_frame_too_long_for_a_six_bit_offset_is_rejected() {
        // The offset field is six bits in units of 32 bytes, so it cannot name anything
        // beyond 63 * 32 = 2016 - and fragment zero has to fit the *total size* in it.
        // Ethernet tops out at 1514, but a caller handing over more must be told, not
        // silently given a frame whose offsets wrap.
        assert!(Fragments::new(&[0u8; 2016], MAX_DATA, 0, 0).is_ok());
        assert!(Fragments::new(&[0u8; 2017], MAX_DATA, 0, 0).is_err());
    }

    #[test]
    fn the_fragment_number_is_six_bits_and_is_not_allowed_to_wrap() {
        // 63 fragments of 32 bytes is 2016 bytes, which the size limit above already
        // covers - but a small mailbox reaches the fragment limit first.
        let payload = [0u8; 2016];
        let fragments: Vec<_> = Fragments::new(&payload, 32, 0, 0).expect("fits").collect();

        assert_eq!(fragments.len(), 63);
        assert_eq!(
            fragments
                .last()
                .expect("some")
                .0
                .fragment()
                .expect("data")
                .number,
            62
        );
    }
}

#[cfg(test)]
mod reassembly_tests {
    use super::*;

    /// Splits `frame` the way a SubDevice would, so the receive side can be fed exactly
    /// what the send side produces.
    fn sent(frame: &[u8], capacity: usize, number: u8) -> Vec<(EoeHeader, Vec<u8>)> {
        Fragments::new(frame, capacity, number, 0)
            .expect("fits")
            .map(|(header, data)| (header, data.to_vec()))
            .collect()
    }

    fn feed(reassembly: &mut Reassembly<'_>, parts: &[(EoeHeader, Vec<u8>)]) -> Option<Vec<u8>> {
        let mut out = None;

        for (header, data) in parts {
            if let Reassembled::Frame(frame) = reassembly.push(*header, data).expect("valid") {
                out = Some(frame.to_vec());
            }
        }

        out
    }

    #[test]
    fn what_the_sender_split_the_receiver_puts_back() {
        let frame: Vec<u8> = (0..=255u8).cycle().take(1514).collect();
        let mut buffer = [0u8; 2048];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        assert_eq!(feed(&mut reassembly, &sent(&frame, 118, 3)), Some(frame));
    }

    #[test]
    fn a_single_fragment_frame_is_complete_at_once() {
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(b"hello", 118, 0);

        assert_eq!(parts.len(), 1);
        match reassembly.push(parts[0].0, &parts[0].1) {
            Ok(Reassembled::Frame(frame)) => assert_eq!(frame, b"hello"),
            other => panic!("expected a complete frame, got {other:?}"),
        }
    }

    #[test]
    fn a_fragment_out_of_order_is_rejected() {
        // A SubDevice that skips fragment 1 must not have fragment 2 written at the wrong
        // place. The reference implementation checks this too (`ec_eoe.c:467`).
        let frame = [0u8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");

        assert_eq!(
            reassembly.push(parts[2].0, &parts[2].1),
            Err(ReassemblyError::OutOfOrder {
                expected: 1,
                received: 2
            })
        );
    }

    #[test]
    fn a_fragment_from_another_frame_is_rejected() {
        // `ec_eoe.c:496`: mid-frame, the frame number has to keep matching.
        let frame = [0u8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let ours = sent(&frame, 118, 3);
        let theirs = sent(&frame, 118, 4);

        reassembly
            .push(ours[0].0, &ours[0].1)
            .expect("fragment zero");

        assert_eq!(
            reassembly.push(theirs[1].0, &theirs[1].1),
            Err(ReassemblyError::WrongFrame {
                expected: 3,
                received: 4
            })
        );
    }

    #[test]
    fn a_fragment_that_claims_the_wrong_offset_is_rejected() {
        // `ec_eoe.c:502`. Trusting it would leave a hole in the frame.
        let frame = [0u8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");

        let lying = parts[1].0.with_fragment(1, 9, 0);

        assert_eq!(
            reassembly.push(lying, &parts[1].1),
            Err(ReassemblyError::WrongOffset {
                expected: 96,
                received: 288
            })
        );
    }

    #[test]
    fn a_frame_larger_than_the_buffer_is_refused_before_anything_is_written() {
        // `ec_eoe.c:481` checks this on fragment zero, which is the only fragment that
        // announces the size - so it can be refused before a single byte is copied.
        let frame = [0u8; 250];
        let mut buffer = [0u8; 64];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        assert_eq!(
            reassembly.push(parts[0].0, &parts[0].1),
            Err(ReassemblyError::FrameTooLongForBuffer {
                announced: 256,
                capacity: 64
            })
        );
    }

    #[test]
    fn a_fragment_that_overruns_what_was_announced_is_rejected() {
        // The size is announced once, in fragment zero. A device that then sends more
        // than it promised is lying about one of the two, and the reference
        // implementation silently DROPS the fragment (`ec_eoe.c:509`) without advancing
        // its counter - so the next fragment fails the order check instead, and the error
        // names the wrong thing.
        let frame = [0u8; 200];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");

        let too_much = vec![0u8; 300];

        assert_eq!(
            reassembly.push(parts[1].0, &too_much),
            Err(ReassemblyError::Overrun {
                announced: 224,
                would_be: 396
            })
        );
    }

    #[test]
    fn a_new_fragment_zero_starts_over() {
        // A SubDevice that gives up on a frame simply starts the next one. Dropping the
        // half assembled frame is right; refusing the new one would wedge the link.
        let frame = [1u8; 250];
        let other = [2u8; 40];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let abandoned = sent(&frame, 118, 3);
        let fresh = sent(&other, 118, 4);

        reassembly
            .push(abandoned[0].0, &abandoned[0].1)
            .expect("fragment zero");

        match reassembly.push(fresh[0].0, &fresh[0].1) {
            Ok(Reassembled::Frame(complete)) => assert_eq!(complete, &other[..]),
            other => panic!("expected the new frame, got {other:?}"),
        }
    }

    #[test]
    fn an_appended_timestamp_is_not_part_of_the_frame() {
        // `ec_eoe.c:519-522`: with TIME_APPEND set, the last four bytes are a timestamp
        // and the frame is that much shorter.
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let mut header = EoeHeader::new(FrameType::FragData, 0).with_fragment(0, 1, 0);
        header.last_fragment = true;
        header.time_append = true;

        match reassembly.push(header, b"payload!TIME") {
            Ok(Reassembled::Frame(frame)) => assert_eq!(frame, b"payload!"),
            other => panic!("expected the frame without its timestamp, got {other:?}"),
        }
    }

    #[test]
    fn a_timestamp_that_is_not_there_is_an_error() {
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let mut header = EoeHeader::new(FrameType::FragData, 0).with_fragment(0, 1, 0);
        header.last_fragment = true;
        header.time_append = true;

        assert_eq!(
            reassembly.push(header, b"abc"),
            Err(ReassemblyError::TimestampMissing { total: 3 })
        );
    }

    #[test]
    fn a_frame_that_is_a_whole_number_of_blocks_is_still_accepted() {
        // The minimum ethernet frame is 64 bytes, exactly two blocks, so `filled` reaches
        // `announced` exactly. An overrun check written with `>=` accepts every frame in
        // these tests but rejects the shortest real one.
        let frame = [7u8; 64];
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        assert_eq!(
            feed(&mut reassembly, &sent(&frame, 118, 0)),
            Some(frame.to_vec())
        );
    }

    #[test]
    fn a_fragment_after_the_frame_is_finished_starts_nothing() {
        // The state has to be cleared when a frame completes: otherwise a stray fragment
        // is taken as the continuation of a frame that is already gone.
        let frame = [0u8; 40];
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("the whole frame");

        let stray = EoeHeader::new(FrameType::FragData, 0).with_fragment(1, 2, 0);

        assert_eq!(
            reassembly.push(stray, b""),
            Err(ReassemblyError::OutOfOrder {
                expected: 0,
                received: 1
            })
        );
    }

    #[test]
    fn a_fragment_with_nothing_in_progress_is_rejected() {
        // The ninth check: a device that starts in the middle.
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let orphan = EoeHeader::new(FrameType::FragData, 0).with_fragment(1, 3, 0);

        assert_eq!(
            reassembly.push(orphan, b"data"),
            Err(ReassemblyError::OutOfOrder {
                expected: 0,
                received: 1
            })
        );
    }

    #[test]
    fn a_fragment_that_claims_an_offset_behind_us_is_rejected_too() {
        // Not only a too-large offset: a retransmitted fragment 1 arriving where fragment
        // 2 is due names an offset *below* what has been filled.
        let frame = [0u8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");
        reassembly
            .push(parts[1].0, &parts[1].1)
            .expect("fragment one");

        let backwards = parts[2].0.with_fragment(2, 1, 0);

        assert_eq!(
            reassembly.push(backwards, &parts[2].1),
            Err(ReassemblyError::WrongOffset {
                expected: 192,
                received: 32
            })
        );
    }

    #[test]
    fn a_fragment_for_another_port_is_rejected() {
        // `ec_eoe.c:487`. Two ports fragmenting at once would otherwise splice into one
        // frame, half of each.
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let other_port = EoeHeader::new(FrameType::FragData, 1).with_fragment(0, 4, 0);

        assert_eq!(
            reassembly.push(other_port, &[0u8; 96]),
            Err(ReassemblyError::WrongPort {
                expected: 0,
                received: 1
            })
        );
    }

    #[test]
    fn a_second_port_cannot_finish_a_frame_the_first_one_started() {
        // The splice this guard exists to prevent. Here both ports are given frame number
        // zero, so fragment number, frame number and offset all line up: without a port
        // check on EVERY fragment, port 1's tail completes port 0's head and a frame goes
        // out that is half of each, with no error anywhere. Two ports need not agree on
        // the frame number - SOEM's sender shares one counter across ports - but nothing
        // stops them from agreeing, and then only the port tells them apart.
        let ours = [0xAAu8; 250];
        let theirs = [0xBBu8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");

        let mine = sent(&ours, 118, 0);
        let other: Vec<_> = Fragments::new(&theirs, 118, 0, 1)
            .expect("fits")
            .map(|(header, data)| (header, data.to_vec()))
            .collect();

        reassembly
            .push(mine[0].0, &mine[0].1)
            .expect("our fragment zero");

        assert_eq!(
            reassembly.push(other[1].0, &other[1].1),
            Err(ReassemblyError::WrongPort {
                expected: 0,
                received: 1
            })
        );
    }

    #[test]
    fn a_wrong_port_leaves_the_frame_in_progress_alone() {
        // The check has to come before the state is touched. A stray fragment from another
        // port must not destroy a frame that is halfway assembled.
        let frame = [0x11u8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");

        let intruder = EoeHeader::new(FrameType::FragData, 1).with_fragment(0, 8, 0);
        assert!(reassembly.push(intruder, &[0u8; 96]).is_err());

        // Ours continues as if nothing happened.
        assert_eq!(
            feed(&mut reassembly, &parts[1..]),
            Some(frame.to_vec()),
            "the interrupted frame still completes"
        );
    }

    #[test]
    fn one_byte_more_than_announced_is_already_an_overrun() {
        // Every other overrun test overshoots hugely, so nothing pinned the boundary from
        // above. A 200 byte frame announces 224; after 96 bytes, 129 more is one too many.
        let frame = [0u8; 200];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let parts = sent(&frame, 118, 0);

        reassembly
            .push(parts[0].0, &parts[0].1)
            .expect("fragment zero");

        assert_eq!(
            reassembly.push(parts[1].0, &[0u8; 129]),
            Err(ReassemblyError::Overrun {
                announced: 224,
                would_be: 225
            })
        );
    }

    #[test]
    fn a_reassembly_for_a_port_other_than_zero_accepts_its_own_traffic() {
        // Every other test here uses port 0, which makes `header.port != self.port`
        // indistinguishable from `header.port != 0`. With that mistake a reassembly for
        // port 1 rejects its own fragments and lets port 0's straight in - the very splice
        // the check exists to stop, inverted.
        let frame = [0x5Au8; 250];
        let mut buffer = [0u8; 512];
        let mut reassembly = Reassembly::new(&mut buffer, 1).expect("a real port");

        let ours: Vec<_> = Fragments::new(&frame, 118, 0, 1)
            .expect("fits")
            .map(|(header, data)| (header, data.to_vec()))
            .collect();

        assert_eq!(feed(&mut reassembly, &ours), Some(frame.to_vec()));

        // And port 0 is now the foreign one.
        let stranger = EoeHeader::new(FrameType::FragData, 0).with_fragment(0, 8, 0);
        assert_eq!(
            reassembly.push(stranger, &[0u8; 96]),
            Err(ReassemblyError::WrongPort {
                expected: 1,
                received: 0
            })
        );
    }

    #[test]
    fn a_reassembly_for_a_port_that_cannot_exist_is_refused() {
        let mut buffer = [0u8; 64];

        assert_eq!(
            Reassembly::new(&mut buffer, 200).unwrap_err(),
            FragmentError::PortTooWide { port: 200 }
        );
        // The upper boundary, which `Fragments::new`'s test pins and this one did not:
        // with `>=` instead of `>`, port 15 - a legal EoE port - becomes unusable and no
        // test notices.
        assert!(
            Reassembly::new(&mut buffer, 15).is_ok(),
            "15 is a real port"
        );
        // The first rejected value, which neither this test nor its twin covered: with a
        // five bit limit, port 16 is accepted here and then packs to port 0 on the wire.
        assert_eq!(
            Reassembly::new(&mut buffer, 16).unwrap_err(),
            FragmentError::PortTooWide { port: 16 }
        );
    }

    #[test]
    fn only_a_data_frame_carries_fragments() {
        let mut buffer = [0u8; 128];
        let mut reassembly = Reassembly::new(&mut buffer, 0).expect("a real port");
        let header = EoeHeader::new(FrameType::InitResp, 0);

        assert_eq!(
            reassembly.push(header, b""),
            Err(ReassemblyError::NotAFragment {
                frame_type: FrameType::InitResp
            })
        );
    }
}
