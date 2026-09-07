//! Ethernet over EtherCAT (EoE), ETG.1000.6.
//!
//! Ported from SOEM's `ec_eoe.c` / `ec_eoe.h`. Every wire test below names the macro or
//! function it was derived from, and the byte sequences are computed from those macros
//! rather than read off a description of the protocol.

/// EoE frame type, the low four bits of the first header word.
///
/// Ported from `libs/SOEM/include/soem/ec_eoe.h`: the `EOE_FRAG_DATA` …
/// `EOE_GET_ADDR_FILTER_RESP` defines. Values 10 to 15 fit the field but are not defined;
/// decoding one is an error rather than a panic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ethercrab_wire::EtherCrabWireReadWrite)]
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

    /// Whether this frame type's second word is a result code rather than fragment info.
    ///
    /// Only `InitResp`: it is the one type the reference implementation reads a result for
    /// (`ec_eoe.c:157`). `GetIpParamResp` carries its status in the payload instead and
    /// SOEM skips the word entirely (`:238`).
    fn carries_result(self) -> bool {
        matches!(self.frame_type, FrameType::InitResp)
    }

    /// Fragment bookkeeping, or `None` if this frame type's second word is a result code.
    pub fn fragment(&self) -> Option<Fragment> {
        (!self.carries_result()).then(|| Fragment {
            number: self.get(Self::FRAGMENT_NO),
            raw_offset: self.get(Self::FRAME_OFFSET),
            frame_number: self.get(Self::FRAME_NO),
        })
    }

    /// The result code, or `None` if this frame type's second word is fragment info.
    ///
    /// `Some(Err(raw))` when the SubDevice sent a value no `EOE_RESULT_*` defines - worth
    /// reporting rather than discarding, and not a reason to fail decoding the header.
    pub fn result(&self) -> Option<Result<EoeResult, u16>> {
        use ethercrab_wire::EtherCrabWireRead as _;

        self.carries_result().then(|| {
            EoeResult::unpack_from_slice(&self.second_word.to_le_bytes())
                .map_err(|_| self.second_word)
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ethercrab_wire::{EtherCrabWireRead, EtherCrabWireWrite};

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
}
