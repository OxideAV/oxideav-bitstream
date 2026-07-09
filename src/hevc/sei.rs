//! HEVC SEI (supplemental enhancement information) parsing.
//!
//! Implements the `sei_rbsp()` / `sei_message()` framing of §7.3.5
//! (byte-identical to the H.264 §7.3.2.3.1 rule: 0xFF run-length
//! accumulation of `payloadType` and `payloadSize`) plus typed
//! decoders for the payload families a playback / HDR pipeline
//! consumes:
//!
//! * `user_data_registered_itu_t_t35()` — §D.2.6.
//! * `user_data_unregistered()` — §D.2.7.
//! * `recovery_point()` — §D.2.8.
//! * `mastering_display_colour_volume()` — §D.2.28 (payload type 137).
//! * `content_light_level_info()` — §D.2.35 (payload type 144).
//!
//! Everything else is surfaced raw as [`HevcSei::Unknown`] — §D.3.1
//! requires decoders to skip unrecognised SEI payloads.
//!
//! SEI NALs come in two flavours: prefix (type 39, before the slices
//! of the access unit) and suffix (type 40, after). Both carry the
//! same `sei_rbsp()`; [`parse_sei_nal`] accepts either.

use super::{ebsp_to_rbsp, nal_header};
use crate::bit_reader::BitReader;
use crate::BitstreamError;

/// 7.4.2.2 — PREFIX_SEI_NUT.
pub const NAL_TYPE_PREFIX_SEI: u8 = 39;
/// 7.4.2.2 — SUFFIX_SEI_NUT.
pub const NAL_TYPE_SUFFIX_SEI: u8 = 40;

/// §D.2.1 payloadType values for the decoded families.
pub const SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35: u32 = 4;
pub const SEI_TYPE_USER_DATA_UNREGISTERED: u32 = 5;
pub const SEI_TYPE_RECOVERY_POINT: u32 = 6;
pub const SEI_TYPE_MASTERING_DISPLAY_COLOUR_VOLUME: u32 = 137;
pub const SEI_TYPE_CONTENT_LIGHT_LEVEL_INFO: u32 = 144;

/// One raw `sei_message()` (§7.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeiMessage {
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

/// Split an SEI RBSP into raw messages (§7.3.5 framing). Identical
/// accumulation rule to H.264; declared sizes are validated against
/// the remaining bytes before slicing.
pub fn parse_sei_rbsp(rbsp: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let mut payload_type: u64 = 0;
        while i < rbsp.len() && rbsp[i] == 0xFF {
            payload_type += 255;
            i += 1;
        }
        if i >= rbsp.len() {
            return Err(BitstreamError::unexpected_end(
                "SEI message truncated in payloadType",
            ));
        }
        payload_type += rbsp[i] as u64;
        i += 1;

        let mut payload_size: u64 = 0;
        while i < rbsp.len() && rbsp[i] == 0xFF {
            payload_size += 255;
            i += 1;
        }
        if i >= rbsp.len() {
            return Err(BitstreamError::unexpected_end(
                "SEI message truncated in payloadSize",
            ));
        }
        payload_size += rbsp[i] as u64;
        i += 1;

        let end = i
            .checked_add(payload_size as usize)
            .ok_or_else(|| BitstreamError::invalid("SEI payloadSize overflow"))?;
        if end > rbsp.len() {
            return Err(BitstreamError::unexpected_end(format!(
                "SEI payloadSize={payload_size} overruns RBSP ({} bytes left)",
                rbsp.len() - i
            )));
        }
        let payload_type = u32::try_from(payload_type)
            .map_err(|_| BitstreamError::invalid("SEI payloadType exceeds u32"))?;
        out.push(SeiMessage {
            payload_type,
            payload: rbsp[i..end].to_vec(),
        });
        i = end;

        // more_rbsp_data(): stop when only the trailing-bits byte
        // (0x80) — possibly followed by zero padding — remains.
        let rest = &rbsp[i..];
        let significant = rest.iter().rev().skip_while(|&&b| b == 0).count();
        if significant == 0 || (significant == 1 && rest[0] == 0x80) {
            break;
        }
    }
    Ok(out)
}

/// Parse a prefix- or suffix-SEI NAL (two-byte NAL header at index
/// 0..1) into raw messages.
pub fn parse_sei_nal(nal: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    if nal.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "SEI NAL shorter than 2 bytes",
        ));
    }
    let (_, nal_type, _, _) = nal_header(nal[0], nal[1]);
    if nal_type != NAL_TYPE_PREFIX_SEI && nal_type != NAL_TYPE_SUFFIX_SEI {
        return Err(BitstreamError::invalid(format!(
            "expected SEI NAL (type=39/40), got type={nal_type}"
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal[2..]);
    parse_sei_rbsp(&rbsp)
}

/// Emit one `sei_message()` framing (§7.3.5) into `out`.
pub fn write_sei_message(out: &mut Vec<u8>, msg: &SeiMessage) {
    let mut t = msg.payload_type;
    while t >= 255 {
        out.push(0xFF);
        t -= 255;
    }
    out.push(t as u8);
    let mut s = msg.payload.len();
    while s >= 255 {
        out.push(0xFF);
        s -= 255;
    }
    out.push(s as u8);
    out.extend_from_slice(&msg.payload);
}

/// Emit a full SEI RBSP (§7.3.5 + `rbsp_trailing_bits()`) — the
/// byte-exact inverse of [`parse_sei_rbsp`].
pub fn write_sei_rbsp(messages: &[SeiMessage]) -> Result<Vec<u8>, BitstreamError> {
    if messages.is_empty() {
        return Err(BitstreamError::invalid(
            "sei_rbsp() requires at least one sei_message() (§7.3.5)",
        ));
    }
    let mut out = Vec::new();
    for m in messages {
        write_sei_message(&mut out, m);
    }
    out.push(0x80);
    Ok(out)
}

// ─────────────────────────── Typed payloads ─────────────────────────────────

/// `mastering_display_colour_volume()` — §D.2.28 / §D.3.28.
/// Chromaticities are in 0.00002 units; luminances in 0.0001 cd/m².
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiMasteringDisplayColourVolume {
    /// `(display_primaries_x[c], display_primaries_y[c])` for c = 0..3
    /// (G/B/R order per §D.3.28).
    pub display_primaries: [(u16, u16); 3],
    pub white_point: (u16, u16),
    pub max_display_mastering_luminance: u32,
    pub min_display_mastering_luminance: u32,
}

/// `content_light_level_info()` — §D.2.35 / §D.3.35, in cd/m².
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiContentLightLevel {
    pub max_content_light_level: u16,
    pub max_pic_average_light_level: u16,
}

/// `recovery_point()` — §D.2.8. Unlike H.264, `recovery_poc_cnt` is
/// signed (`se(v)`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiRecoveryPoint {
    pub recovery_poc_cnt: i32,
    pub exact_match_flag: bool,
    pub broken_link_flag: bool,
}

/// `user_data_registered_itu_t_t35()` — §D.2.6.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiUserDataRegisteredItuTT35 {
    pub country_code: u8,
    pub country_code_extension: Option<u8>,
    pub payload: Vec<u8>,
}

/// `user_data_unregistered()` — §D.2.7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiUserDataUnregistered {
    pub uuid: [u8; 16],
    pub payload: Vec<u8>,
}

/// A decoded HEVC SEI payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HevcSei {
    UserDataRegisteredItuTT35(SeiUserDataRegisteredItuTT35),
    UserDataUnregistered(SeiUserDataUnregistered),
    RecoveryPoint(SeiRecoveryPoint),
    MasteringDisplayColourVolume(SeiMasteringDisplayColourVolume),
    ContentLightLevel(SeiContentLightLevel),
    /// Any payload type this crate does not decode (§D.3.1 requires
    /// decoders to skip unrecognised SEI payloads).
    Unknown {
        payload_type: u32,
        payload: Vec<u8>,
    },
}

/// Decode one raw [`SeiMessage`] into a typed [`HevcSei`]. All the
/// decoded families are SPS-independent, so no context argument is
/// needed (the HRD-coupled families — buffering_period, pic_timing —
/// are surfaced as [`HevcSei::Unknown`] for now).
pub fn decode_sei_message(msg: &SeiMessage) -> Result<HevcSei, BitstreamError> {
    match msg.payload_type {
        SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35 => {
            let p = &msg.payload;
            if p.is_empty() {
                return Err(BitstreamError::unexpected_end(
                    "itu_t_t35 SEI payload empty",
                ));
            }
            let country_code = p[0];
            let (ext, rest) = if country_code != 0xFF {
                (None, &p[1..])
            } else {
                if p.len() < 2 {
                    return Err(BitstreamError::unexpected_end(
                        "itu_t_t35 SEI missing country_code_extension_byte",
                    ));
                }
                (Some(p[1]), &p[2..])
            };
            Ok(HevcSei::UserDataRegisteredItuTT35(
                SeiUserDataRegisteredItuTT35 {
                    country_code,
                    country_code_extension: ext,
                    payload: rest.to_vec(),
                },
            ))
        }
        SEI_TYPE_USER_DATA_UNREGISTERED => {
            if msg.payload.len() < 16 {
                return Err(BitstreamError::unexpected_end(
                    "user_data_unregistered SEI shorter than the 16-byte UUID",
                ));
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&msg.payload[..16]);
            Ok(HevcSei::UserDataUnregistered(SeiUserDataUnregistered {
                uuid,
                payload: msg.payload[16..].to_vec(),
            }))
        }
        SEI_TYPE_RECOVERY_POINT => {
            let mut r = BitReader::new(&msg.payload);
            let rp = SeiRecoveryPoint {
                recovery_poc_cnt: r.se()?,
                exact_match_flag: r.u(1) != 0,
                broken_link_flag: r.u(1) != 0,
            };
            if r.bit_pos() > r.total_bits() {
                return Err(BitstreamError::unexpected_end(
                    "recovery_point SEI payload too short",
                ));
            }
            Ok(HevcSei::RecoveryPoint(rp))
        }
        SEI_TYPE_MASTERING_DISPLAY_COLOUR_VOLUME => {
            if msg.payload.len() < 24 {
                return Err(BitstreamError::unexpected_end(
                    "mastering_display_colour_volume needs 24 payload bytes",
                ));
            }
            let mut r = BitReader::new(&msg.payload);
            let mut m = SeiMasteringDisplayColourVolume::default();
            for p in &mut m.display_primaries {
                *p = (r.u(16) as u16, r.u(16) as u16);
            }
            m.white_point = (r.u(16) as u16, r.u(16) as u16);
            m.max_display_mastering_luminance = r.u(32);
            m.min_display_mastering_luminance = r.u(32);
            Ok(HevcSei::MasteringDisplayColourVolume(m))
        }
        SEI_TYPE_CONTENT_LIGHT_LEVEL_INFO => {
            if msg.payload.len() < 4 {
                return Err(BitstreamError::unexpected_end(
                    "content_light_level_info needs 4 payload bytes",
                ));
            }
            let mut r = BitReader::new(&msg.payload);
            Ok(HevcSei::ContentLightLevel(SeiContentLightLevel {
                max_content_light_level: r.u(16) as u16,
                max_pic_average_light_level: r.u(16) as u16,
            }))
        }
        other => Ok(HevcSei::Unknown {
            payload_type: other,
            payload: msg.payload.clone(),
        }),
    }
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrips_across_size_classes() {
        for &(t, len) in &[
            (SEI_TYPE_RECOVERY_POINT, 2usize),
            (SEI_TYPE_MASTERING_DISPLAY_COLOUR_VOLUME, 24),
            (300, 700),
        ] {
            let msg = SeiMessage {
                payload_type: t,
                payload: (0..len).map(|i| (i % 249 + 1) as u8).collect(),
            };
            let rbsp = write_sei_rbsp(std::slice::from_ref(&msg)).unwrap();
            assert_eq!(parse_sei_rbsp(&rbsp).unwrap(), vec![msg], "t={t} len={len}");
        }
    }

    #[test]
    fn framing_rejects_overrun_and_truncation() {
        assert!(matches!(
            parse_sei_rbsp(&[0x06, 0x0A, 0xAA]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        assert!(matches!(
            parse_sei_rbsp(&[]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        assert!(matches!(
            parse_sei_rbsp(&[0xFF]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
    }

    #[test]
    fn mdcv_decodes() {
        let mut w = crate::bit_writer::BitWriter::new();
        // G/B/R primaries in 0.00002 units.
        for &(x, y) in &[(13250u32, 34500u32), (7500, 3000), (34000, 16000)] {
            w.write_bits(x, 16);
            w.write_bits(y, 16);
        }
        w.write_bits(15635, 16); // white_point_x
        w.write_bits(16450, 16); // white_point_y
        w.write_bits(10_000_000, 32); // 1000 cd/m² in 0.0001 units
        w.write_bits(50, 32); // 0.005 cd/m²
        let msg = SeiMessage {
            payload_type: SEI_TYPE_MASTERING_DISPLAY_COLOUR_VOLUME,
            payload: w.finish(),
        };
        let HevcSei::MasteringDisplayColourVolume(m) = decode_sei_message(&msg).unwrap() else {
            panic!("expected MDCV");
        };
        assert_eq!(m.display_primaries[0], (13250, 34500));
        assert_eq!(m.display_primaries[2], (34000, 16000));
        assert_eq!(m.white_point, (15635, 16450));
        assert_eq!(m.max_display_mastering_luminance, 10_000_000);
        assert_eq!(m.min_display_mastering_luminance, 50);
    }

    #[test]
    fn cll_decodes_and_rejects_short() {
        let msg = SeiMessage {
            payload_type: SEI_TYPE_CONTENT_LIGHT_LEVEL_INFO,
            payload: vec![0x03, 0xE8, 0x01, 0x90],
        };
        let HevcSei::ContentLightLevel(c) = decode_sei_message(&msg).unwrap() else {
            panic!("expected CLL");
        };
        assert_eq!(c.max_content_light_level, 1000);
        assert_eq!(c.max_pic_average_light_level, 400);

        let short = SeiMessage {
            payload_type: SEI_TYPE_CONTENT_LIGHT_LEVEL_INFO,
            payload: vec![0x00; 3],
        };
        assert!(matches!(
            decode_sei_message(&short).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
    }

    #[test]
    fn recovery_point_signed_poc_decodes() {
        // recovery_poc_cnt = -2 (se), exact_match=1, broken_link=0.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_se(-2).unwrap();
        w.write_bit(1);
        w.write_bit(0);
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_RECOVERY_POINT,
            payload: w.finish(),
        };
        let HevcSei::RecoveryPoint(rp) = decode_sei_message(&msg).unwrap() else {
            panic!("expected RecoveryPoint");
        };
        assert_eq!(rp.recovery_poc_cnt, -2);
        assert!(rp.exact_match_flag);
        assert!(!rp.broken_link_flag);
    }

    #[test]
    fn sei_nal_accepts_prefix_and_suffix_types() {
        // Minimal user-data-unregistered message body.
        let mut body = vec![0x05, 16];
        body.extend_from_slice(&[0x42; 16]);
        body.push(0x80);
        for t in [NAL_TYPE_PREFIX_SEI, NAL_TYPE_SUFFIX_SEI] {
            let mut nal = vec![t << 1, 0x01];
            nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&body));
            let msgs = parse_sei_nal(&nal).unwrap_or_else(|e| panic!("type {t}: {e}"));
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].payload_type, SEI_TYPE_USER_DATA_UNREGISTERED);
        }
        // A VPS NAL is rejected.
        let nal = [super::super::NAL_TYPE_VPS << 1, 0x01, 0x05, 0x00, 0x80];
        assert!(matches!(
            parse_sei_nal(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn unknown_type_surfaced_raw() {
        let msg = SeiMessage {
            payload_type: 1, // pic_timing — HRD-coupled, not decoded yet
            payload: vec![1, 2, 3],
        };
        let HevcSei::Unknown { payload_type, .. } = decode_sei_message(&msg).unwrap() else {
            panic!("expected Unknown");
        };
        assert_eq!(payload_type, 1);
    }
}
