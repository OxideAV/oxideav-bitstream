//! H.264 SEI (supplemental enhancement information) parsing.
//!
//! Implements the `sei_rbsp()` / `sei_message()` framing of
//! §7.3.2.3 / §7.3.2.3.1 (the 0xFF run-length accumulation of
//! `payloadType` and `payloadSize`) plus typed decoders for the
//! payload families a playback/HW-bridge stack actually consumes:
//!
//! * `buffering_period()` — §D.1.2 (needs the active SPS's HRD for
//!   the `u(v)` delay field widths).
//! * `pic_timing()` — §D.1.3 (needs `CpbDpbDelaysPresentFlag`,
//!   `pic_struct_present_flag` and `time_offset_length` from the
//!   active SPS's VUI/HRD; `NumClockTS` per Table D-1).
//! * `user_data_registered_itu_t_t35()` — §D.1.6.
//! * `user_data_unregistered()` — §D.1.7.
//! * `recovery_point()` — §D.1.8.
//!
//! Every other payload type is surfaced raw as
//! [`H264Sei::Unknown`] so callers can route or ignore it; the
//! framing layer never rejects an unknown type (§D.2.1 requires
//! decoders to skip unrecognised SEI payloads).

use super::{nal_header, H264Sps};
use crate::bit_reader::BitReader;
use crate::BitstreamError;

/// H.264 NAL unit type 6 — SEI (§7.4.1 Table 7-1).
pub const NAL_TYPE_SEI: u8 = 6;

/// §D.1.1 payloadType values for the decoded families.
pub const SEI_TYPE_BUFFERING_PERIOD: u32 = 0;
pub const SEI_TYPE_PIC_TIMING: u32 = 1;
pub const SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35: u32 = 4;
pub const SEI_TYPE_USER_DATA_UNREGISTERED: u32 = 5;
pub const SEI_TYPE_RECOVERY_POINT: u32 = 6;

/// One raw `sei_message()` (§7.3.2.3.1): the accumulated
/// `payloadType` and the payload bytes (still RBSP-level — emulation
/// prevention was stripped before framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeiMessage {
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

/// Split an SEI RBSP into its raw messages (§7.3.2.3 framing:
/// repeat `sei_message()` while `more_rbsp_data()`).
///
/// `payloadType` / `payloadSize` are accumulated 255-at-a-time from
/// `ff_byte` runs per §7.3.2.3.1. A declared `payloadSize` that
/// overruns the remaining RBSP bytes yields
/// [`BitstreamError::UnexpectedEnd`] — declared sizes are validated
/// against actual bytes before slicing.
pub fn parse_sei_rbsp(rbsp: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    let mut out = Vec::new();
    let mut i = 0usize;

    // more_rbsp_data(): at least one message must be present; the
    // loop ends when only the rbsp_trailing_bits byte (0x80) — or
    // nothing — remains.
    loop {
        // Accumulate payloadType.
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

        // Accumulate payloadSize.
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

        // §7.3.2.3: continue while more_rbsp_data(). At the byte level
        // that means: stop when the remaining bytes are exhausted or
        // consist solely of the trailing-bits byte 0x80 (possibly
        // followed by cabac_zero_words-style zero padding).
        let rest = &rbsp[i..];
        let significant = rest.iter().rev().skip_while(|&&b| b == 0).count();
        if significant == 0 || (significant == 1 && rest[0] == 0x80) {
            break;
        }
    }
    Ok(out)
}

/// Parse an SEI NAL — including the NAL header byte at index 0 —
/// into raw messages. Errors out unless the NAL type is 6.
pub fn parse_sei_nal(nal: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    if nal.is_empty() {
        return Err(BitstreamError::unexpected_end("empty SEI NAL"));
    }
    let (_, _, nal_type) = nal_header(nal[0]);
    if nal_type != NAL_TYPE_SEI {
        return Err(BitstreamError::invalid(format!(
            "expected SEI NAL (type=6), got type={nal_type}"
        )));
    }
    let rbsp = super::ebsp_to_rbsp(&nal[1..]);
    parse_sei_rbsp(&rbsp)
}

/// Emit the `sei_message()` framing (§7.3.2.3.1) for one message
/// into `out`: 0xFF runs + final byte for both `payloadType` and
/// `payloadSize`, followed by the payload bytes.
pub fn write_sei_message(out: &mut Vec<u8>, msg: &SeiMessage) -> Result<(), BitstreamError> {
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
    Ok(())
}

/// Emit a full SEI RBSP (§7.3.2.3): every message's framing followed
/// by `rbsp_trailing_bits()` (the byte-aligned 0x80 stop marker).
/// The inverse of [`parse_sei_rbsp`] — byte-exact round-trip.
pub fn write_sei_rbsp(messages: &[SeiMessage]) -> Result<Vec<u8>, BitstreamError> {
    if messages.is_empty() {
        return Err(BitstreamError::invalid(
            "sei_rbsp() requires at least one sei_message() (§7.3.2.3)",
        ));
    }
    let mut out = Vec::new();
    for m in messages {
        write_sei_message(&mut out, m)?;
    }
    out.push(0x80); // rbsp_stop_one_bit + alignment zeros
    Ok(out)
}

// ─────────────────────────── Typed payloads ─────────────────────────────────

/// `buffering_period()` — §D.1.2. One initial-delay pair per CPB
/// schedule entry, for whichever of the NAL / VCL HRD blocks the
/// active SPS carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiBufferingPeriod {
    pub seq_parameter_set_id: u32,
    /// `(initial_cpb_removal_delay, initial_cpb_removal_delay_offset)`
    /// per SchedSelIdx when the SPS has NAL HRD parameters.
    pub nal_initial_delays: Vec<(u32, u32)>,
    /// Same for the VCL HRD block.
    pub vcl_initial_delays: Vec<(u32, u32)>,
}

/// One clock timestamp set from `pic_timing()` (§D.1.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiClockTimestamp {
    pub ct_type: u8,
    pub nuit_field_based_flag: bool,
    pub counting_type: u8,
    pub full_timestamp_flag: bool,
    pub discontinuity_flag: bool,
    pub cnt_dropped_flag: bool,
    pub n_frames: u8,
    pub seconds: Option<u8>,
    pub minutes: Option<u8>,
    pub hours: Option<u8>,
    /// Present when the HRD's `time_offset_length > 0`; two's
    /// complement `i(v)`.
    pub time_offset: Option<i32>,
}

/// `pic_timing()` — §D.1.3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiPicTiming {
    /// Present when `CpbDpbDelaysPresentFlag` (HRD in the SPS).
    pub cpb_removal_delay: Option<u32>,
    pub dpb_output_delay: Option<u32>,
    /// Present when `pic_struct_present_flag` in the VUI. Table D-1.
    pub pic_struct: Option<u8>,
    /// Up to `NumClockTS` (Table D-1) decoded timestamp sets — one
    /// entry per `clock_timestamp_flag[i] == 1`.
    pub clock_timestamps: Vec<SeiClockTimestamp>,
}

/// `user_data_registered_itu_t_t35()` — §D.1.6.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiUserDataRegisteredItuTT35 {
    pub country_code: u8,
    /// Present when `country_code == 0xFF`.
    pub country_code_extension: Option<u8>,
    pub payload: Vec<u8>,
}

/// `user_data_unregistered()` — §D.1.7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiUserDataUnregistered {
    pub uuid: [u8; 16],
    pub payload: Vec<u8>,
}

/// `recovery_point()` — §D.1.8.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiRecoveryPoint {
    pub recovery_frame_cnt: u32,
    pub exact_match_flag: bool,
    pub broken_link_flag: bool,
    pub changing_slice_group_idc: u8,
}

/// A decoded SEI payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H264Sei {
    BufferingPeriod(SeiBufferingPeriod),
    PicTiming(SeiPicTiming),
    UserDataRegisteredItuTT35(SeiUserDataRegisteredItuTT35),
    UserDataUnregistered(SeiUserDataUnregistered),
    RecoveryPoint(SeiRecoveryPoint),
    /// Any payload type this crate does not decode — surfaced raw
    /// per §D.2.1 (decoders skip unrecognised SEI payloads).
    Unknown {
        payload_type: u32,
        payload: Vec<u8>,
    },
}

/// `NumClockTS` per Table D-1, indexed by `pic_struct` 0..=8.
const NUM_CLOCK_TS: [usize; 9] = [1, 1, 1, 2, 2, 3, 3, 2, 3];

/// Decode one raw [`SeiMessage`] into a typed [`H264Sei`].
///
/// `sps` provides the variable-width context: `buffering_period()`
/// and `pic_timing()` read `u(v)` fields whose widths come from the
/// active SPS's HRD (§D.1.2 / §D.1.3), and `pic_timing()`'s
/// `pic_struct` presence is gated by the VUI. Passing `None` decodes
/// the SPS-independent payloads and returns
/// [`BitstreamError::Unsupported`] for the two HRD-coupled families.
pub fn decode_sei_message(
    msg: &SeiMessage,
    sps: Option<&H264Sps>,
) -> Result<H264Sei, BitstreamError> {
    match msg.payload_type {
        SEI_TYPE_BUFFERING_PERIOD => {
            let sps = sps.ok_or_else(|| {
                BitstreamError::unsupported("buffering_period SEI needs SPS context (§D.1.2)")
            })?;
            decode_buffering_period(&msg.payload, sps).map(H264Sei::BufferingPeriod)
        }
        SEI_TYPE_PIC_TIMING => {
            let sps = sps.ok_or_else(|| {
                BitstreamError::unsupported("pic_timing SEI needs SPS context (§D.1.3)")
            })?;
            decode_pic_timing(&msg.payload, sps).map(H264Sei::PicTiming)
        }
        SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35 => {
            decode_itu_t_t35(&msg.payload).map(H264Sei::UserDataRegisteredItuTT35)
        }
        SEI_TYPE_USER_DATA_UNREGISTERED => {
            decode_user_data_unregistered(&msg.payload).map(H264Sei::UserDataUnregistered)
        }
        SEI_TYPE_RECOVERY_POINT => decode_recovery_point(&msg.payload).map(H264Sei::RecoveryPoint),
        other => Ok(H264Sei::Unknown {
            payload_type: other,
            payload: msg.payload.clone(),
        }),
    }
}

fn decode_buffering_period(
    payload: &[u8],
    sps: &H264Sps,
) -> Result<SeiBufferingPeriod, BitstreamError> {
    let vui = sps.vui.as_ref().ok_or_else(|| {
        BitstreamError::unsupported("buffering_period SEI with no VUI in the SPS")
    })?;
    let mut r = BitReader::new(payload);
    let mut bp = SeiBufferingPeriod {
        seq_parameter_set_id: r.ue()?,
        ..SeiBufferingPeriod::default()
    };
    // §D.1.2: field width is initial_cpb_removal_delay_length_minus1+1
    // from the corresponding HRD block; one pair per schedule entry.
    if let Some(hrd) = &vui.nal_hrd_parameters {
        let n = hrd.initial_cpb_removal_delay_length_minus1 as u32 + 1;
        for _ in 0..=hrd.cpb_cnt_minus1 {
            bp.nal_initial_delays.push((r.u(n), r.u(n)));
        }
    }
    if let Some(hrd) = &vui.vcl_hrd_parameters {
        let n = hrd.initial_cpb_removal_delay_length_minus1 as u32 + 1;
        for _ in 0..=hrd.cpb_cnt_minus1 {
            bp.vcl_initial_delays.push((r.u(n), r.u(n)));
        }
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "buffering_period SEI payload too short",
        ));
    }
    Ok(bp)
}

fn decode_pic_timing(payload: &[u8], sps: &H264Sps) -> Result<SeiPicTiming, BitstreamError> {
    let vui = sps
        .vui
        .as_ref()
        .ok_or_else(|| BitstreamError::unsupported("pic_timing SEI with no VUI in the SPS"))?;
    // CpbDpbDelaysPresentFlag: set when either HRD block is present
    // (§E.2.2). Both blocks are constrained to carry identical
    // lengths for these fields, so consulting whichever exists is
    // per-spec.
    let hrd = vui
        .nal_hrd_parameters
        .as_ref()
        .or(vui.vcl_hrd_parameters.as_ref());
    let mut r = BitReader::new(payload);
    let mut pt = SeiPicTiming::default();
    if let Some(hrd) = hrd {
        pt.cpb_removal_delay = Some(r.u(hrd.cpb_removal_delay_length_minus1 as u32 + 1));
        pt.dpb_output_delay = Some(r.u(hrd.dpb_output_delay_length_minus1 as u32 + 1));
    }
    if vui.pic_struct_present_flag {
        let pic_struct = r.u(4) as u8;
        // Table D-1: values 9..15 are reserved; NumClockTS is defined
        // only for 0..=8, so reserved values cannot be walked further.
        if pic_struct > 8 {
            return Err(BitstreamError::invalid(format!(
                "pic_timing pic_struct={pic_struct} is reserved (Table D-1)"
            )));
        }
        pt.pic_struct = Some(pic_struct);
        for _ in 0..NUM_CLOCK_TS[pic_struct as usize] {
            let clock_timestamp_flag = r.u(1) != 0;
            if !clock_timestamp_flag {
                continue;
            }
            let mut ts = SeiClockTimestamp {
                ct_type: r.u(2) as u8,
                nuit_field_based_flag: r.u(1) != 0,
                counting_type: r.u(5) as u8,
                full_timestamp_flag: r.u(1) != 0,
                discontinuity_flag: r.u(1) != 0,
                cnt_dropped_flag: r.u(1) != 0,
                n_frames: r.u(8) as u8,
                ..SeiClockTimestamp::default()
            };
            if ts.full_timestamp_flag {
                ts.seconds = Some(r.u(6) as u8);
                ts.minutes = Some(r.u(6) as u8);
                ts.hours = Some(r.u(5) as u8);
            } else {
                if r.u(1) != 0 {
                    // seconds_flag
                    ts.seconds = Some(r.u(6) as u8);
                    if r.u(1) != 0 {
                        // minutes_flag
                        ts.minutes = Some(r.u(6) as u8);
                        if r.u(1) != 0 {
                            // hours_flag
                            ts.hours = Some(r.u(5) as u8);
                        }
                    }
                }
            }
            if let Some(hrd) = hrd {
                if hrd.time_offset_length > 0 {
                    ts.time_offset = Some(r.i(hrd.time_offset_length as u32)?);
                }
            }
            pt.clock_timestamps.push(ts);
        }
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "pic_timing SEI payload too short",
        ));
    }
    Ok(pt)
}

fn decode_itu_t_t35(payload: &[u8]) -> Result<SeiUserDataRegisteredItuTT35, BitstreamError> {
    if payload.is_empty() {
        return Err(BitstreamError::unexpected_end(
            "itu_t_t35 SEI payload empty",
        ));
    }
    let country_code = payload[0];
    let (country_code_extension, rest) = if country_code != 0xFF {
        (None, &payload[1..])
    } else {
        if payload.len() < 2 {
            return Err(BitstreamError::unexpected_end(
                "itu_t_t35 SEI missing country_code_extension_byte",
            ));
        }
        (Some(payload[1]), &payload[2..])
    };
    Ok(SeiUserDataRegisteredItuTT35 {
        country_code,
        country_code_extension,
        payload: rest.to_vec(),
    })
}

fn decode_user_data_unregistered(
    payload: &[u8],
) -> Result<SeiUserDataUnregistered, BitstreamError> {
    if payload.len() < 16 {
        return Err(BitstreamError::unexpected_end(
            "user_data_unregistered SEI shorter than the 16-byte UUID",
        ));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&payload[..16]);
    Ok(SeiUserDataUnregistered {
        uuid,
        payload: payload[16..].to_vec(),
    })
}

fn decode_recovery_point(payload: &[u8]) -> Result<SeiRecoveryPoint, BitstreamError> {
    let mut r = BitReader::new(payload);
    let rp = SeiRecoveryPoint {
        recovery_frame_cnt: r.ue()?,
        exact_match_flag: r.u(1) != 0,
        broken_link_flag: r.u(1) != 0,
        changing_slice_group_idc: r.u(2) as u8,
    };
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "recovery_point SEI payload too short",
        ));
    }
    Ok(rp)
}

// ─────────────────────────── Tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h264::{H264HrdParameters, H264Vui};

    fn sps_with_hrd(pic_struct_present: bool, time_offset_length: u8) -> H264Sps {
        H264Sps {
            vui: Some(H264Vui {
                pic_struct_present_flag: pic_struct_present,
                nal_hrd_parameters: Some(H264HrdParameters {
                    cpb_cnt_minus1: 1,
                    initial_cpb_removal_delay_length_minus1: 23,
                    cpb_removal_delay_length_minus1: 15,
                    dpb_output_delay_length_minus1: 5,
                    time_offset_length,
                    ..H264HrdParameters::default()
                }),
                ..H264Vui::default()
            }),
            ..H264Sps::default()
        }
    }

    #[test]
    fn sei_framing_roundtrips_single_and_multi_byte_type_size() {
        // payload_type 0 (1 byte), 254, 255 (FF 00), 300 (FF 2D);
        // sizes crossing the 255 boundary too.
        for &(t, len) in &[(0u32, 3usize), (254, 255), (255, 256), (300, 700)] {
            let msg = SeiMessage {
                payload_type: t,
                payload: (0..len).map(|i| (i % 251) as u8).collect(),
            };
            let rbsp = write_sei_rbsp(std::slice::from_ref(&msg)).unwrap();
            let parsed = parse_sei_rbsp(&rbsp).unwrap();
            assert_eq!(parsed.len(), 1, "t={t} len={len}");
            assert_eq!(parsed[0], msg, "t={t} len={len}");
        }
    }

    #[test]
    fn sei_framing_roundtrips_multiple_messages() {
        let msgs = vec![
            SeiMessage {
                payload_type: SEI_TYPE_RECOVERY_POINT,
                payload: vec![0xA8], // ue(0)=1, flags, idc + stop bits
            },
            SeiMessage {
                payload_type: 100,
                payload: vec![1, 2, 3, 4],
            },
        ];
        let rbsp = write_sei_rbsp(&msgs).unwrap();
        let parsed = parse_sei_rbsp(&rbsp).unwrap();
        assert_eq!(parsed, msgs);
    }

    #[test]
    fn sei_framing_rejects_size_overrun() {
        // Declares 10 payload bytes but provides 2.
        let rbsp = [0x06u8, 0x0A, 0xAA, 0xBB];
        let err = parse_sei_rbsp(&rbsp).expect_err("overrun rejected");
        assert!(matches!(err, BitstreamError::UnexpectedEnd(_)));
    }

    #[test]
    fn sei_framing_rejects_truncated_type_and_size() {
        assert!(matches!(
            parse_sei_rbsp(&[]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        // 0xFF run that never terminates.
        assert!(matches!(
            parse_sei_rbsp(&[0xFF, 0xFF]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        // Type present, size missing.
        assert!(matches!(
            parse_sei_rbsp(&[0x05]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
    }

    #[test]
    fn recovery_point_decodes() {
        // recovery_frame_cnt=3 (ue: 00100), exact_match=1,
        // broken_link=0, changing_slice_group_idc=0, then alignment.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_ue(3).unwrap();
        w.write_bit(1);
        w.write_bit(0);
        w.write_bits(0, 2);
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_RECOVERY_POINT,
            payload: w.finish(),
        };
        let H264Sei::RecoveryPoint(rp) = decode_sei_message(&msg, None).unwrap() else {
            panic!("expected RecoveryPoint");
        };
        assert_eq!(rp.recovery_frame_cnt, 3);
        assert!(rp.exact_match_flag);
        assert!(!rp.broken_link_flag);
        assert_eq!(rp.changing_slice_group_idc, 0);
    }

    #[test]
    fn user_data_unregistered_decodes_uuid_and_body() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x11; 16]);
        payload.extend_from_slice(b"hello");
        let msg = SeiMessage {
            payload_type: SEI_TYPE_USER_DATA_UNREGISTERED,
            payload,
        };
        let H264Sei::UserDataUnregistered(u) = decode_sei_message(&msg, None).unwrap() else {
            panic!("expected UserDataUnregistered");
        };
        assert_eq!(u.uuid, [0x11; 16]);
        assert_eq!(u.payload, b"hello");
    }

    #[test]
    fn user_data_unregistered_rejects_short_uuid() {
        let msg = SeiMessage {
            payload_type: SEI_TYPE_USER_DATA_UNREGISTERED,
            payload: vec![0; 15],
        };
        assert!(matches!(
            decode_sei_message(&msg, None).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
    }

    #[test]
    fn itu_t_t35_decodes_plain_and_extended_country_code() {
        let msg = SeiMessage {
            payload_type: SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35,
            payload: vec![0xB5, 0xAA, 0xBB],
        };
        let H264Sei::UserDataRegisteredItuTT35(t) = decode_sei_message(&msg, None).unwrap() else {
            panic!("expected ItuTT35");
        };
        assert_eq!(t.country_code, 0xB5);
        assert_eq!(t.country_code_extension, None);
        assert_eq!(t.payload, [0xAA, 0xBB]);

        let msg = SeiMessage {
            payload_type: SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35,
            payload: vec![0xFF, 0x01, 0xCC],
        };
        let H264Sei::UserDataRegisteredItuTT35(t) = decode_sei_message(&msg, None).unwrap() else {
            panic!("expected ItuTT35");
        };
        assert_eq!(t.country_code, 0xFF);
        assert_eq!(t.country_code_extension, Some(0x01));
        assert_eq!(t.payload, [0xCC]);
    }

    #[test]
    fn buffering_period_decodes_against_sps_hrd() {
        let sps = sps_with_hrd(false, 0);
        // seq_parameter_set_id=0 (ue), then 2 schedule entries × 2
        // u(24) fields for the NAL HRD block.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_ue(0).unwrap();
        for v in [90000u32, 45000, 180000, 90000] {
            w.write_bits(v, 24);
        }
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_BUFFERING_PERIOD,
            payload: w.finish(),
        };
        let H264Sei::BufferingPeriod(bp) = decode_sei_message(&msg, Some(&sps)).unwrap() else {
            panic!("expected BufferingPeriod");
        };
        assert_eq!(bp.seq_parameter_set_id, 0);
        assert_eq!(bp.nal_initial_delays, vec![(90000, 45000), (180000, 90000)]);
        assert!(bp.vcl_initial_delays.is_empty());
    }

    #[test]
    fn buffering_period_without_sps_context_is_unsupported() {
        let msg = SeiMessage {
            payload_type: SEI_TYPE_BUFFERING_PERIOD,
            payload: vec![0x80],
        };
        assert!(matches!(
            decode_sei_message(&msg, None).unwrap_err(),
            BitstreamError::Unsupported(_)
        ));
    }

    #[test]
    fn pic_timing_decodes_delays_and_full_timestamp() {
        let sps = sps_with_hrd(true, 24);
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(7, 16); // cpb_removal_delay u(16)
        w.write_bits(3, 6); // dpb_output_delay u(6)
        w.write_bits(0, 4); // pic_struct = 0 (frame) → NumClockTS = 1
        w.write_bit(1); // clock_timestamp_flag[0]
        w.write_bits(1, 2); // ct_type
        w.write_bit(0); // nuit_field_based_flag
        w.write_bits(4, 5); // counting_type
        w.write_bit(1); // full_timestamp_flag
        w.write_bit(0); // discontinuity_flag
        w.write_bit(0); // cnt_dropped_flag
        w.write_bits(12, 8); // n_frames
        w.write_bits(59, 6); // seconds
        w.write_bits(58, 6); // minutes
        w.write_bits(23, 5); // hours
        w.write_i(-5, 24).unwrap(); // time_offset i(24)
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_PIC_TIMING,
            payload: w.finish(),
        };
        let H264Sei::PicTiming(pt) = decode_sei_message(&msg, Some(&sps)).unwrap() else {
            panic!("expected PicTiming");
        };
        assert_eq!(pt.cpb_removal_delay, Some(7));
        assert_eq!(pt.dpb_output_delay, Some(3));
        assert_eq!(pt.pic_struct, Some(0));
        assert_eq!(pt.clock_timestamps.len(), 1);
        let ts = &pt.clock_timestamps[0];
        assert_eq!(ts.ct_type, 1);
        assert_eq!(ts.counting_type, 4);
        assert!(ts.full_timestamp_flag);
        assert_eq!(ts.n_frames, 12);
        assert_eq!(ts.seconds, Some(59));
        assert_eq!(ts.minutes, Some(58));
        assert_eq!(ts.hours, Some(23));
        assert_eq!(ts.time_offset, Some(-5));
    }

    #[test]
    fn pic_timing_partial_timestamp_ladder() {
        // full_timestamp_flag=0 with seconds only.
        let sps = sps_with_hrd(true, 0);
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(1, 16); // cpb_removal_delay
        w.write_bits(1, 6); // dpb_output_delay
        w.write_bits(1, 4); // pic_struct = 1 (top field) → NumClockTS = 1
        w.write_bit(1); // clock_timestamp_flag[0]
        w.write_bits(0, 2); // ct_type
        w.write_bit(1); // nuit_field_based_flag
        w.write_bits(0, 5); // counting_type
        w.write_bit(0); // full_timestamp_flag
        w.write_bit(0); // discontinuity_flag
        w.write_bit(0); // cnt_dropped_flag
        w.write_bits(0, 8); // n_frames
        w.write_bit(1); // seconds_flag
        w.write_bits(30, 6); // seconds
        w.write_bit(0); // minutes_flag
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_PIC_TIMING,
            payload: w.finish(),
        };
        let H264Sei::PicTiming(pt) = decode_sei_message(&msg, Some(&sps)).unwrap() else {
            panic!("expected PicTiming");
        };
        let ts = &pt.clock_timestamps[0];
        assert_eq!(ts.seconds, Some(30));
        assert_eq!(ts.minutes, None);
        assert_eq!(ts.hours, None);
        assert_eq!(ts.time_offset, None, "time_offset_length == 0");
    }

    #[test]
    fn pic_timing_rejects_reserved_pic_struct() {
        let sps = sps_with_hrd(true, 0);
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(0, 16);
        w.write_bits(0, 6);
        w.write_bits(9, 4); // pic_struct = 9 — reserved per Table D-1
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_PIC_TIMING,
            payload: w.finish(),
        };
        assert!(matches!(
            decode_sei_message(&msg, Some(&sps)).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn unknown_payload_type_is_surfaced_raw() {
        let msg = SeiMessage {
            payload_type: 999,
            payload: vec![1, 2, 3],
        };
        let H264Sei::Unknown {
            payload_type,
            payload,
        } = decode_sei_message(&msg, None).unwrap()
        else {
            panic!("expected Unknown");
        };
        assert_eq!(payload_type, 999);
        assert_eq!(payload, [1, 2, 3]);
    }
}
