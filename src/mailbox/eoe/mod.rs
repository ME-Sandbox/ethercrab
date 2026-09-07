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
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
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

/// EoE header: two 16 bit words directly behind the mailbox header. ETG.1000.6.
///
/// The first word is a bit field and is decoded as one. The second is kept as the raw word
/// SOEM calls `frameinfo2` and read through the accessors below, because its three fields
/// do not sit on byte boundaries - `frame_offset` spans bits 22 to 27 - and
/// `EtherCrabWireReadWrite` rejects a multi-byte field that is not byte aligned. Splitting
/// it by hand would mean two encodings of the same word; one word with named accessors is
/// the same shape `ec_eoe.c` uses.
///
/// ```text
/// word 1:  type(4)  port(4)  last_fragment(1)  time_append(1)  time_request(1)  ...(5)
/// word 2:  fragment_no(6)    frame_offset(6)   frame_no(4)
/// ```
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
    #[wire(bits = 1)]
    pub time_append: bool,
    /// Whether the sender wants a timestamp back.
    #[wire(bits = 1, post_skip = 5)]
    pub time_request: bool,

    /// `frameinfo2`: fragment number, frame offset and frame number packed into one word.
    #[wire(bytes = 2)]
    frame_info2: u16,
}

impl EoeHeader {
    const FRAGMENT_NO: (u16, u16) = (0x003F, 0);
    const FRAME_OFFSET: (u16, u16) = (0x003F, 6);
    const FRAME_NO: (u16, u16) = (0x000F, 12);

    fn get(&self, (mask, shift): (u16, u16)) -> u8 {
        ((self.frame_info2 >> shift) & mask) as u8
    }

    /// Index of this fragment within the frame, counting from zero.
    ///
    /// Ported from `EOE_HDR_FRAG_NO_GET`.
    pub fn fragment_no(&self) -> u8 {
        self.get(Self::FRAGMENT_NO)
    }

    /// Offset of this fragment in the frame, **in multiples of 32 bytes**.
    ///
    /// Ported from `EOE_HDR_FRAME_OFFSET_GET`. Six bits, so the largest offset a fragment
    /// can name is 63 * 32 = 2016 bytes.
    pub fn frame_offset(&self) -> u8 {
        self.get(Self::FRAME_OFFSET)
    }

    /// Identifies the Ethernet frame these fragments belong to. Four bits, so it wraps
    /// after 16 frames.
    ///
    /// Ported from `EOE_HDR_FRAME_NO_GET`.
    pub fn frame_no(&self) -> u8 {
        self.get(Self::FRAME_NO)
    }

    /// Set fragment number, frame offset and frame number.
    ///
    /// Ported from the `EOE_HDR_*_SET` macros: each value is masked to its own width, so a
    /// value that is too large cannot spill into a neighbouring field.
    pub fn with_fragment(mut self, fragment_no: u8, frame_offset: u8, frame_no: u8) -> Self {
        let put = |(mask, shift): (u16, u16), value: u8| (u16::from(value) & mask) << shift;

        self.frame_info2 = put(Self::FRAGMENT_NO, fragment_no)
            | put(Self::FRAME_OFFSET, frame_offset)
            | put(Self::FRAME_NO, frame_no);

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethercrab_wire::{EtherCrabWireRead, EtherCrabWireWrite};

    /// Ported from `libs/SOEM/include/soem/ec_eoe.h`, EOE_HDR_* macros.
    ///
    /// ```text
    /// frameinfo1 = FRAME_TYPE_SET(3) | FRAME_PORT_SET(1) | LAST_FRAGMENT_SET(1)
    ///            = (3 & 0xF)  |  ((1 & 0xF) << 4)  |  ((1 & 0x1) << 8)
    ///            = 0x0003     |  0x0010            |  0x0100          = 0x0113
    ///
    /// frameinfo2 = FRAG_NO_SET(5) | FRAME_OFFSET_SET(2) | FRAME_NO_SET(7)
    ///            = (5 & 0x3F) |  ((2 & 0x3F) << 6) |  ((7 & 0xF) << 12)
    ///            = 0x0005     |  0x0080            |  0x7000          = 0x7085
    /// ```
    ///
    /// Both are 16 bit words, little-endian on the wire: `13 01 85 70`.
    const HEADER: [u8; 4] = [0x13, 0x01, 0x85, 0x70];

    #[test]
    fn the_two_header_words_decode_field_by_field() {
        let header = EoeHeader::unpack_from_slice(&HEADER).expect("a four byte EoE header");

        assert_eq!(header.frame_type, FrameType::InitResp);
        assert_eq!(header.port, 1);
        assert!(header.last_fragment);
        assert!(!header.time_append);
        assert!(!header.time_request);

        assert_eq!(header.fragment_no(), 5);
        assert_eq!(header.frame_offset(), 2);
        assert_eq!(header.frame_no(), 7);
    }

    #[test]
    fn every_frame_type_the_c_source_defines_round_trips() {
        // `ec_eoe.h` lines 110-119. All ten, so an unhandled one cannot hide.
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
            assert_eq!(header.frame_type, expected, "frame type {value}");
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
            frame_info2: 0,
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
        // The same numbers as HEADER above, built instead of parsed. If the encoder and
        // the decoder ever agreed on a wrong layout, only a fixed byte sequence would
        // notice - a round trip would not.
        let header = EoeHeader {
            frame_type: FrameType::InitResp,
            port: 1,
            last_fragment: true,
            time_append: false,
            time_request: false,
            frame_info2: 0,
        }
        .with_fragment(5, 2, 7);

        let mut buffer = [0u8; 4];
        header.pack_to_slice(&mut buffer).expect("four bytes");

        assert_eq!(buffer, HEADER);
    }

    #[test]
    fn a_value_too_wide_for_its_field_cannot_spill_into_the_next_one() {
        // `EOE_HDR_FRAG_NO_SET` masks with 0x3F before shifting. Without the mask a
        // fragment number of 64 would land in the frame offset and silently move the
        // fragment somewhere else in the frame.
        let header = EoeHeader {
            frame_type: FrameType::FragData,
            port: 0,
            last_fragment: false,
            time_append: false,
            time_request: false,
            frame_info2: 0,
        }
        .with_fragment(64, 64, 16);

        assert_eq!(header.fragment_no(), 0);
        assert_eq!(header.frame_offset(), 0);
        assert_eq!(header.frame_no(), 0);
    }
}
