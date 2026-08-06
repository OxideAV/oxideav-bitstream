//! HEVC SEI (supplemental enhancement information) parsing.
//!
//! Implements the `sei_rbsp()` / `sei_message()` framing of §7.3.5
//! (byte-identical to the H.264 §7.3.2.3.1 rule: 0xFF run-length
//! accumulation of `payloadType` and `payloadSize`) plus typed
//! decoders **and encoders** for the payload families a playback /
//! HDR pipeline consumes:
//!
//! * `buffering_period()` — §D.2.2 (payload type 0, HRD-coupled —
//!   decode/encode against a [`SeiHrdContext`]).
//! * `pic_timing()` — §D.2.3 (payload type 1, ditto, including the
//!   sub-picture decoding-unit block).
//! * `user_data_registered_itu_t_t35()` — §D.2.6.
//! * `user_data_unregistered()` — §D.2.7.
//! * `recovery_point()` — §D.2.8.
//! * `mastering_display_colour_volume()` — §D.2.28 (payload type 137).
//! * `content_light_level_info()` — §D.2.35 (payload type 144).
//!
//! The context-free families round-trip through
//! [`decode_sei_message`] / [`encode_sei_message`]; everything else is
//! surfaced raw as [`HevcSei::Unknown`] — §D.3.1 requires decoders to
//! skip unrecognised SEI payloads.
//!
//! SEI NALs come in two flavours: prefix (type 39, before the slices
//! of the access unit) and suffix (type 40, after). Both carry the
//! same `sei_rbsp()`; [`parse_sei_nal`] accepts either.

use super::{ebsp_to_rbsp, nal_header, HevcHrdParameters};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

/// 7.4.2.2 — PREFIX_SEI_NUT.
pub const NAL_TYPE_PREFIX_SEI: u8 = 39;
/// 7.4.2.2 — SUFFIX_SEI_NUT.
pub const NAL_TYPE_SUFFIX_SEI: u8 = 40;

/// §D.2.1 payloadType values for the decoded families.
pub const SEI_TYPE_BUFFERING_PERIOD: u32 = 0;
pub const SEI_TYPE_PIC_TIMING: u32 = 1;
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
/// have their own [`decode_buffering_period`] / [`decode_pic_timing`]
/// entry points taking a [`SeiHrdContext`], and surface here as
/// [`HevcSei::Unknown`]).
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

/// Encode a typed [`HevcSei`] back into a raw [`SeiMessage`] — the
/// inverse of [`decode_sei_message`] for every context-free family
/// (the HRD-coupled buffering_period / pic_timing pair has its own
/// [`encode_buffering_period`] / [`encode_pic_timing`] entry points).
/// `Unknown` payloads pass through verbatim.
pub fn encode_sei_message(sei: &HevcSei) -> Result<SeiMessage, BitstreamError> {
    match sei {
        HevcSei::UserDataRegisteredItuTT35(t35) => {
            let mut payload = Vec::with_capacity(2 + t35.payload.len());
            payload.push(t35.country_code);
            match (t35.country_code == 0xFF, t35.country_code_extension) {
                (true, Some(ext)) => payload.push(ext),
                (false, None) => {}
                _ => {
                    return Err(BitstreamError::invalid(
                        "itu_t_t35: country_code_extension present iff country_code == 0xFF \
                         (D.2.6)",
                    ));
                }
            }
            payload.extend_from_slice(&t35.payload);
            Ok(SeiMessage {
                payload_type: SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35,
                payload,
            })
        }
        HevcSei::UserDataUnregistered(u) => {
            let mut payload = Vec::with_capacity(16 + u.payload.len());
            payload.extend_from_slice(&u.uuid);
            payload.extend_from_slice(&u.payload);
            Ok(SeiMessage {
                payload_type: SEI_TYPE_USER_DATA_UNREGISTERED,
                payload,
            })
        }
        HevcSei::RecoveryPoint(rp) => {
            let mut w = BitWriter::new();
            w.write_se(rp.recovery_poc_cnt)?;
            w.write_bit(u32::from(rp.exact_match_flag));
            w.write_bit(u32::from(rp.broken_link_flag));
            w.write_rbsp_trailing_bits(); // payload_bit_equal_to_one + alignment
            Ok(SeiMessage {
                payload_type: SEI_TYPE_RECOVERY_POINT,
                payload: w.finish(),
            })
        }
        HevcSei::MasteringDisplayColourVolume(m) => {
            let mut w = BitWriter::new();
            for &(x, y) in &m.display_primaries {
                w.write_bits(x as u32, 16);
                w.write_bits(y as u32, 16);
            }
            w.write_bits(m.white_point.0 as u32, 16);
            w.write_bits(m.white_point.1 as u32, 16);
            w.write_bits(m.max_display_mastering_luminance, 32);
            w.write_bits(m.min_display_mastering_luminance, 32);
            Ok(SeiMessage {
                payload_type: SEI_TYPE_MASTERING_DISPLAY_COLOUR_VOLUME,
                payload: w.finish(),
            })
        }
        HevcSei::ContentLightLevel(c) => Ok(SeiMessage {
            payload_type: SEI_TYPE_CONTENT_LIGHT_LEVEL_INFO,
            payload: vec![
                (c.max_content_light_level >> 8) as u8,
                c.max_content_light_level as u8,
                (c.max_pic_average_light_level >> 8) as u8,
                c.max_pic_average_light_level as u8,
            ],
        }),
        HevcSei::Unknown {
            payload_type,
            payload,
        } => Ok(SeiMessage {
            payload_type: *payload_type,
            payload: payload.clone(),
        }),
    }
}

// ──────────────── HRD-coupled payloads: BP / PT (§D.2.2 / §D.2.3) ───────────

/// Context threaded into the buffering_period / pic_timing decoders:
/// the active SPS VUI `hrd_parameters()` plus the sub-layer the SEI
/// applies to (`HighestTid`, selecting `cpb_cnt_minus1[i]`) and the
/// VUI `frame_field_info_present_flag` gate for pic_timing's
/// `pic_struct` triple.
#[derive(Debug, Clone, Copy)]
pub struct SeiHrdContext<'a> {
    /// The SPS-VUI `hrd_parameters()` (§E.2.2).
    pub hrd: &'a HevcHrdParameters,
    /// Sub-layer index the SEI applies to (0-based `HighestTid`);
    /// selects `cpb_cnt_minus1[i]` per §E.3.3.
    pub sub_layer_id: usize,
    /// VUI `frame_field_info_present_flag` (§E.2.1) — gates the
    /// `pic_struct` / `source_scan_type` / `duplicate_flag` triple in
    /// pic_timing.
    pub frame_field_info_present_flag: bool,
}

impl SeiHrdContext<'_> {
    fn cpb_cnt(&self) -> Result<u32, BitstreamError> {
        self.hrd
            .sub_layers
            .get(self.sub_layer_id)
            .map(|sl| sl.cpb_cnt_minus1 + 1)
            .ok_or_else(|| {
                BitstreamError::invalid(format!(
                    "sub_layer_id {} outside the hrd_parameters() sub-layer list (len {})",
                    self.sub_layer_id,
                    self.hrd.sub_layers.len()
                ))
            })
    }

    /// `CpbDpbDelaysPresentFlag` (§D.3.3).
    fn cpb_dpb_delays_present(&self) -> bool {
        self.hrd.nal_hrd_parameters_present_flag || self.hrd.vcl_hrd_parameters_present_flag
    }
}

/// One CPB's initial-removal pair in a buffering_period (§D.2.2).
/// `alt` carries `(initial_alt_cpb_removal_delay,
/// initial_alt_cpb_removal_offset)` — coded only when
/// `sub_pic_hrd_params_present_flag` or `irap_cpb_params_present_flag`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiInitialCpbDelays {
    pub initial_cpb_removal_delay: u32,
    pub initial_cpb_removal_offset: u32,
    pub alt: Option<(u32, u32)>,
}

/// `buffering_period()` — §D.2.2 / §D.3.2. All `u(v)` field widths
/// come from the [`SeiHrdContext`]'s `hrd_parameters()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiBufferingPeriod {
    /// `bp_seq_parameter_set_id` ue(v) — 0..=15.
    pub bp_seq_parameter_set_id: u32,
    /// `irap_cpb_params_present_flag` — coded only when
    /// `!sub_pic_hrd_params_present_flag`; inferred 0.
    pub irap_cpb_params_present_flag: bool,
    /// `cpb_delay_offset` u(v) (`au_cpb_removal_delay_length_minus1 +
    /// 1` bits) — coded only with IRAP CPB params; inferred 0.
    pub cpb_delay_offset: u32,
    /// `dpb_delay_offset` u(v) (`dpb_output_delay_length_minus1 + 1`
    /// bits) — ditto.
    pub dpb_delay_offset: u32,
    /// `concatenation_flag` — ditto.
    pub concatenation_flag: bool,
    /// `au_cpb_removal_delay_delta_minus1` u(v) — ditto.
    pub au_cpb_removal_delay_delta_minus1: u32,
    /// `nal_initial_cpb_removal_delay/offset[i]` — `CpbCnt` entries
    /// iff `NalHrdBpPresentFlag`.
    pub nal_delays: Vec<SeiInitialCpbDelays>,
    /// The VCL twin.
    pub vcl_delays: Vec<SeiInitialCpbDelays>,
    /// `use_alt_cpb_params_flag` — the §D.2.2 payload-extension
    /// position; `Some` iff the coded payload carried it.
    pub use_alt_cpb_params_flag: Option<bool>,
}

fn read_initial_delays(
    r: &mut BitReader<'_>,
    cpb_cnt: u32,
    init_len: u32,
    alt_present: bool,
) -> Vec<SeiInitialCpbDelays> {
    (0..cpb_cnt)
        .map(|_| {
            let initial_cpb_removal_delay = r.u(init_len);
            let initial_cpb_removal_offset = r.u(init_len);
            let alt = if alt_present {
                Some((r.u(init_len), r.u(init_len)))
            } else {
                None
            };
            SeiInitialCpbDelays {
                initial_cpb_removal_delay,
                initial_cpb_removal_offset,
                alt,
            }
        })
        .collect()
}

/// Position of the last set bit in `payload`, if any.
fn last_one_bit(payload: &[u8]) -> Option<usize> {
    for (byte_idx, &b) in payload.iter().enumerate().rev() {
        if b != 0 {
            return Some(byte_idx * 8 + (7 - b.trailing_zeros() as usize));
        }
    }
    None
}

/// Validate + consume the SEI payload tail after the last syntax
/// field: either the reader sits exactly at the payload end
/// (byte-aligned), or the remaining bits are an optional 1-bit
/// extension slot followed by `payload_bit_equal_to_one` + zero
/// padding (§D.1.1). Returns the extension bit when present.
fn read_payload_tail(
    r: &mut BitReader<'_>,
    payload: &[u8],
    what: &str,
) -> Result<Option<bool>, BitstreamError> {
    let total = payload.len() * 8;
    let pos = r.bit_pos();
    if pos > total {
        return Err(BitstreamError::unexpected_end(format!(
            "{what} payload too short"
        )));
    }
    if pos == total {
        return Ok(None);
    }
    let last_one = last_one_bit(payload).ok_or_else(|| {
        BitstreamError::invalid(format!("{what}: missing payload_bit_equal_to_one"))
    })?;
    if last_one < pos {
        return Err(BitstreamError::invalid(format!(
            "{what}: payload_bit_equal_to_one precedes the last syntax field"
        )));
    }
    match last_one - pos {
        0 => Ok(None),
        1 => {
            let bit = r.u(1) != 0;
            Ok(Some(bit))
        }
        _ => Err(BitstreamError::unsupported(format!(
            "{what}: reserved_payload_extension_data longer than the 1-bit extension slot"
        ))),
    }
}

/// Decode a `buffering_period()` SEI (§D.2.2) against its HRD
/// context.
pub fn decode_buffering_period(
    msg: &SeiMessage,
    ctx: &SeiHrdContext<'_>,
) -> Result<SeiBufferingPeriod, BitstreamError> {
    if msg.payload_type != SEI_TYPE_BUFFERING_PERIOD {
        return Err(BitstreamError::invalid(format!(
            "expected buffering_period (payloadType 0), got {}",
            msg.payload_type
        )));
    }
    let hrd = ctx.hrd;
    let cpb_cnt = ctx.cpb_cnt()?;
    let au_len = hrd.au_cpb_removal_delay_length_minus1 as u32 + 1;
    let dpb_len = hrd.dpb_output_delay_length_minus1 as u32 + 1;
    let init_len = hrd.initial_cpb_removal_delay_length_minus1 as u32 + 1;
    let mut r = BitReader::new(&msg.payload);
    let mut bp = SeiBufferingPeriod {
        bp_seq_parameter_set_id: r.ue()?,
        ..Default::default()
    };
    if bp.bp_seq_parameter_set_id > 15 {
        return Err(BitstreamError::invalid(format!(
            "bp_seq_parameter_set_id = {} > 15 (D.3.2)",
            bp.bp_seq_parameter_set_id
        )));
    }
    if !hrd.sub_pic_hrd_params_present_flag {
        bp.irap_cpb_params_present_flag = r.u(1) != 0;
    }
    if bp.irap_cpb_params_present_flag {
        bp.cpb_delay_offset = r.u(au_len);
        bp.dpb_delay_offset = r.u(dpb_len);
        bp.concatenation_flag = r.u(1) != 0;
        bp.au_cpb_removal_delay_delta_minus1 = r.u(au_len);
    }
    let alt_present = hrd.sub_pic_hrd_params_present_flag || bp.irap_cpb_params_present_flag;
    if hrd.nal_hrd_parameters_present_flag {
        bp.nal_delays = read_initial_delays(&mut r, cpb_cnt, init_len, alt_present);
    }
    if hrd.vcl_hrd_parameters_present_flag {
        bp.vcl_delays = read_initial_delays(&mut r, cpb_cnt, init_len, alt_present);
    }
    bp.use_alt_cpb_params_flag = read_payload_tail(&mut r, &msg.payload, "buffering_period")?;
    Ok(bp)
}

fn write_uv(w: &mut BitWriter, value: u32, bits: u32, name: &str) -> Result<(), BitstreamError> {
    if bits < 32 && value >= (1u32 << bits) {
        return Err(BitstreamError::invalid(format!(
            "{name} = {value} does not fit u({bits})"
        )));
    }
    w.write_bits(value, bits);
    Ok(())
}

fn finish_sei_payload(mut w: BitWriter) -> Vec<u8> {
    if !w.byte_aligned() {
        w.write_rbsp_trailing_bits(); // payload_bit_equal_to_one + zeros
    }
    w.finish()
}

/// Encode a [`SeiBufferingPeriod`] against its HRD context — the
/// inverse of [`decode_buffering_period`].
pub fn encode_buffering_period(
    bp: &SeiBufferingPeriod,
    ctx: &SeiHrdContext<'_>,
) -> Result<SeiMessage, BitstreamError> {
    let hrd = ctx.hrd;
    let cpb_cnt = ctx.cpb_cnt()?;
    let au_len = hrd.au_cpb_removal_delay_length_minus1 as u32 + 1;
    let dpb_len = hrd.dpb_output_delay_length_minus1 as u32 + 1;
    let init_len = hrd.initial_cpb_removal_delay_length_minus1 as u32 + 1;
    if bp.bp_seq_parameter_set_id > 15 {
        return Err(BitstreamError::invalid(
            "bp_seq_parameter_set_id > 15 (D.3.2)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_ue(bp.bp_seq_parameter_set_id)?;
    if !hrd.sub_pic_hrd_params_present_flag {
        w.write_bit(u32::from(bp.irap_cpb_params_present_flag));
    } else if bp.irap_cpb_params_present_flag {
        return Err(BitstreamError::invalid(
            "irap_cpb_params_present_flag cannot be set with sub-pic HRD params (D.2.2 NOTE 2)",
        ));
    }
    if bp.irap_cpb_params_present_flag {
        write_uv(&mut w, bp.cpb_delay_offset, au_len, "cpb_delay_offset")?;
        write_uv(&mut w, bp.dpb_delay_offset, dpb_len, "dpb_delay_offset")?;
        w.write_bit(u32::from(bp.concatenation_flag));
        write_uv(
            &mut w,
            bp.au_cpb_removal_delay_delta_minus1,
            au_len,
            "au_cpb_removal_delay_delta_minus1",
        )?;
    }
    let alt_present = hrd.sub_pic_hrd_params_present_flag || bp.irap_cpb_params_present_flag;
    for (delays, present, name) in [
        (&bp.nal_delays, hrd.nal_hrd_parameters_present_flag, "NAL"),
        (&bp.vcl_delays, hrd.vcl_hrd_parameters_present_flag, "VCL"),
    ] {
        if !present {
            if !delays.is_empty() {
                return Err(BitstreamError::invalid(format!(
                    "{name} initial-delay list present without the matching \
                     hrd_parameters() presence flag (D.2.2)"
                )));
            }
            continue;
        }
        if delays.len() != cpb_cnt as usize {
            return Err(BitstreamError::invalid(format!(
                "{name} initial-delay list has {} entries, CpbCnt is {cpb_cnt} (D.2.2)",
                delays.len()
            )));
        }
        for d in delays {
            write_uv(
                &mut w,
                d.initial_cpb_removal_delay,
                init_len,
                "initial_cpb_removal_delay",
            )?;
            write_uv(
                &mut w,
                d.initial_cpb_removal_offset,
                init_len,
                "initial_cpb_removal_offset",
            )?;
            match (d.alt, alt_present) {
                (Some((ad, ao)), true) => {
                    write_uv(&mut w, ad, init_len, "initial_alt_cpb_removal_delay")?;
                    write_uv(&mut w, ao, init_len, "initial_alt_cpb_removal_offset")?;
                }
                (None, false) => {}
                _ => {
                    return Err(BitstreamError::invalid(
                        "alt CPB delays present iff sub-pic HRD or IRAP CPB params (D.2.2)",
                    ));
                }
            }
        }
    }
    let payload = if let Some(flag) = bp.use_alt_cpb_params_flag {
        // With the extension bit written, the payload stop bit is
        // mandatory even at a byte boundary — otherwise a set flag
        // would masquerade as payload_bit_equal_to_one on re-parse.
        w.write_bit(u32::from(flag));
        w.write_rbsp_trailing_bits();
        w.finish()
    } else {
        finish_sei_payload(w)
    };
    Ok(SeiMessage {
        payload_type: SEI_TYPE_BUFFERING_PERIOD,
        payload,
    })
}

/// One decoding unit's entry in pic_timing's sub-picture block
/// (§D.2.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeiPicTimingDu {
    /// `num_nalus_in_du_minus1[i]` ue(v).
    pub num_nalus_in_du_minus1: u32,
    /// `du_cpb_removal_delay_increment_minus1[i]` u(v) — coded only
    /// when `!du_common_cpb_removal_delay_flag` and `i` is not the
    /// last DU.
    pub du_cpb_removal_delay_increment_minus1: Option<u32>,
}

/// `pic_timing()` — §D.2.3 / §D.3.3. All `u(v)` field widths and
/// presence gates come from the [`SeiHrdContext`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeiPicTiming {
    /// `(pic_struct, source_scan_type, duplicate_flag)` — present iff
    /// the VUI `frame_field_info_present_flag`. `pic_struct` 0..=12
    /// (Table D.2).
    pub frame_field_info: Option<(u8, u8, bool)>,
    /// `au_cpb_removal_delay_minus1` u(v) — present iff
    /// `CpbDpbDelaysPresentFlag`.
    pub au_cpb_removal_delay_minus1: u32,
    /// `pic_dpb_output_delay` u(v) — ditto.
    pub pic_dpb_output_delay: u32,
    /// `pic_dpb_output_du_delay` u(v) — present iff sub-pic HRD
    /// params are present.
    pub pic_dpb_output_du_delay: u32,
    /// `du_common_cpb_removal_delay_increment_minus1` u(v) — `Some`
    /// iff `du_common_cpb_removal_delay_flag`.
    pub du_common_cpb_removal_delay_increment_minus1: Option<u32>,
    /// The decoding-unit list — `Some` iff sub-pic HRD params are
    /// present AND `sub_pic_cpb_params_in_pic_timing_sei_flag`.
    pub decoding_units: Option<Vec<SeiPicTimingDu>>,
}

/// Decode a `pic_timing()` SEI (§D.2.3) against its HRD context.
pub fn decode_pic_timing(
    msg: &SeiMessage,
    ctx: &SeiHrdContext<'_>,
) -> Result<SeiPicTiming, BitstreamError> {
    if msg.payload_type != SEI_TYPE_PIC_TIMING {
        return Err(BitstreamError::invalid(format!(
            "expected pic_timing (payloadType 1), got {}",
            msg.payload_type
        )));
    }
    let hrd = ctx.hrd;
    let au_len = hrd.au_cpb_removal_delay_length_minus1 as u32 + 1;
    let dpb_len = hrd.dpb_output_delay_length_minus1 as u32 + 1;
    let dpb_du_len = hrd.dpb_output_delay_du_length_minus1 as u32 + 1;
    let du_len = hrd.du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
    let mut r = BitReader::new(&msg.payload);
    let mut pt = SeiPicTiming::default();
    if ctx.frame_field_info_present_flag {
        let pic_struct = r.u(4) as u8;
        if pic_struct > 12 {
            return Err(BitstreamError::invalid(format!(
                "pic_struct = {pic_struct} > 12 (Table D.2)"
            )));
        }
        pt.frame_field_info = Some((pic_struct, r.u(2) as u8, r.u(1) != 0));
    }
    if ctx.cpb_dpb_delays_present() {
        pt.au_cpb_removal_delay_minus1 = r.u(au_len);
        pt.pic_dpb_output_delay = r.u(dpb_len);
        if hrd.sub_pic_hrd_params_present_flag {
            pt.pic_dpb_output_du_delay = r.u(dpb_du_len);
        }
        if hrd.sub_pic_hrd_params_present_flag && hrd.sub_pic_cpb_params_in_pic_timing_sei_flag {
            let num_du_minus1 = r.ue()?;
            // Each DU entry costs at least one bit; bound the loop by
            // the remaining payload so a hostile count cannot spin.
            if num_du_minus1 as usize >= r.bits_remaining() {
                return Err(BitstreamError::unexpected_end(
                    "num_decoding_units_minus1 exceeds the remaining pic_timing payload",
                ));
            }
            let du_common = r.u(1) != 0;
            if du_common {
                pt.du_common_cpb_removal_delay_increment_minus1 = Some(r.u(du_len));
            }
            let mut dus = Vec::with_capacity(num_du_minus1 as usize + 1);
            for i in 0..=num_du_minus1 {
                let num_nalus_in_du_minus1 = r.ue()?;
                let du_cpb_removal_delay_increment_minus1 = if !du_common && i < num_du_minus1 {
                    Some(r.u(du_len))
                } else {
                    None
                };
                dus.push(SeiPicTimingDu {
                    num_nalus_in_du_minus1,
                    du_cpb_removal_delay_increment_minus1,
                });
            }
            pt.decoding_units = Some(dus);
        }
    }
    if read_payload_tail(&mut r, &msg.payload, "pic_timing")?.is_some() {
        return Err(BitstreamError::unsupported(
            "pic_timing: unexpected payload-extension bit",
        ));
    }
    Ok(pt)
}

/// Encode a [`SeiPicTiming`] against its HRD context — the inverse of
/// [`decode_pic_timing`].
pub fn encode_pic_timing(
    pt: &SeiPicTiming,
    ctx: &SeiHrdContext<'_>,
) -> Result<SeiMessage, BitstreamError> {
    let hrd = ctx.hrd;
    let au_len = hrd.au_cpb_removal_delay_length_minus1 as u32 + 1;
    let dpb_len = hrd.dpb_output_delay_length_minus1 as u32 + 1;
    let dpb_du_len = hrd.dpb_output_delay_du_length_minus1 as u32 + 1;
    let du_len = hrd.du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
    let mut w = BitWriter::new();
    match (pt.frame_field_info, ctx.frame_field_info_present_flag) {
        (Some((pic_struct, source_scan_type, duplicate_flag)), true) => {
            if pic_struct > 12 || source_scan_type > 3 {
                return Err(BitstreamError::invalid(
                    "pic_struct > 12 or source_scan_type > 3 (Table D.2)",
                ));
            }
            w.write_bits(pic_struct as u32, 4);
            w.write_bits(source_scan_type as u32, 2);
            w.write_bit(u32::from(duplicate_flag));
        }
        (None, false) => {}
        _ => {
            return Err(BitstreamError::invalid(
                "frame_field_info present iff the VUI frame_field_info_present_flag (D.2.3)",
            ));
        }
    }
    if ctx.cpb_dpb_delays_present() {
        write_uv(
            &mut w,
            pt.au_cpb_removal_delay_minus1,
            au_len,
            "au_cpb_removal_delay_minus1",
        )?;
        write_uv(
            &mut w,
            pt.pic_dpb_output_delay,
            dpb_len,
            "pic_dpb_output_delay",
        )?;
        if hrd.sub_pic_hrd_params_present_flag {
            write_uv(
                &mut w,
                pt.pic_dpb_output_du_delay,
                dpb_du_len,
                "pic_dpb_output_du_delay",
            )?;
        }
        let du_list_expected =
            hrd.sub_pic_hrd_params_present_flag && hrd.sub_pic_cpb_params_in_pic_timing_sei_flag;
        match (&pt.decoding_units, du_list_expected) {
            (Some(dus), true) => {
                if dus.is_empty() {
                    return Err(BitstreamError::invalid(
                        "pic_timing decoding-unit list cannot be empty (D.2.3)",
                    ));
                }
                let num_du_minus1 = dus.len() as u32 - 1;
                w.write_ue(num_du_minus1)?;
                let du_common = pt.du_common_cpb_removal_delay_increment_minus1.is_some();
                w.write_bit(u32::from(du_common));
                if let Some(v) = pt.du_common_cpb_removal_delay_increment_minus1 {
                    write_uv(
                        &mut w,
                        v,
                        du_len,
                        "du_common_cpb_removal_delay_increment_minus1",
                    )?;
                }
                for (i, du) in dus.iter().enumerate() {
                    w.write_ue(du.num_nalus_in_du_minus1)?;
                    let expected = !du_common && (i as u32) < num_du_minus1;
                    match (du.du_cpb_removal_delay_increment_minus1, expected) {
                        (Some(v), true) => {
                            write_uv(&mut w, v, du_len, "du_cpb_removal_delay_increment_minus1")?
                        }
                        (None, false) => {}
                        _ => {
                            return Err(BitstreamError::invalid(
                                "du_cpb_removal_delay_increment_minus1 present iff \
                                 !du_common_cpb_removal_delay_flag and not the last DU (D.2.3)",
                            ));
                        }
                    }
                }
            }
            (None, false) => {}
            _ => {
                return Err(BitstreamError::invalid(
                    "decoding_units present iff sub-pic HRD params are signalled in \
                     pic_timing SEIs (D.2.3)",
                ));
            }
        }
    } else if pt.decoding_units.is_some() {
        return Err(BitstreamError::invalid(
            "decoding_units require CpbDpbDelaysPresentFlag (D.2.3)",
        ));
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_PIC_TIMING,
        payload: finish_sei_payload(w),
    })
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

    // ──────────── typed encoder + BP/PT round-trips ────────────

    use super::super::{HevcCpbEntry, HevcHrdSubLayer};

    fn hrd_ctx_template(
        nal: bool,
        vcl: bool,
        sub_pic: bool,
        cpb_cnt_minus1: u32,
    ) -> HevcHrdParameters {
        HevcHrdParameters {
            nal_hrd_parameters_present_flag: nal,
            vcl_hrd_parameters_present_flag: vcl,
            sub_pic_hrd_params_present_flag: sub_pic,
            tick_divisor_minus2: 0,
            du_cpb_removal_delay_increment_length_minus1: 7,
            sub_pic_cpb_params_in_pic_timing_sei_flag: sub_pic,
            dpb_output_delay_du_length_minus1: 11,
            bit_rate_scale: 0,
            cpb_size_scale: 0,
            cpb_size_du_scale: 0,
            initial_cpb_removal_delay_length_minus1: 23,
            au_cpb_removal_delay_length_minus1: 15,
            dpb_output_delay_length_minus1: 9,
            sub_layers: vec![HevcHrdSubLayer {
                fixed_pic_rate_general_flag: true,
                fixed_pic_rate_within_cvs_flag: true,
                elemental_duration_in_tc_minus1: Some(0),
                low_delay_hrd_flag: false,
                cpb_cnt_minus1,
                nal_cpb: vec![HevcCpbEntry::default(); cpb_cnt_minus1 as usize + 1],
                vcl_cpb: vec![],
            }],
        }
    }

    #[test]
    fn typed_encoders_roundtrip_through_decode() {
        let cases = vec![
            HevcSei::UserDataRegisteredItuTT35(SeiUserDataRegisteredItuTT35 {
                country_code: 0xB5,
                country_code_extension: None,
                payload: vec![1, 2, 3],
            }),
            HevcSei::UserDataRegisteredItuTT35(SeiUserDataRegisteredItuTT35 {
                country_code: 0xFF,
                country_code_extension: Some(0x10),
                payload: vec![9],
            }),
            HevcSei::UserDataUnregistered(SeiUserDataUnregistered {
                uuid: [0xAB; 16],
                payload: vec![0, 1, 2, 3, 4],
            }),
            HevcSei::RecoveryPoint(SeiRecoveryPoint {
                recovery_poc_cnt: -3,
                exact_match_flag: true,
                broken_link_flag: false,
            }),
            HevcSei::MasteringDisplayColourVolume(SeiMasteringDisplayColourVolume {
                display_primaries: [(13250, 34500), (7500, 3000), (34000, 16000)],
                white_point: (15635, 16450),
                max_display_mastering_luminance: 10_000_000,
                min_display_mastering_luminance: 50,
            }),
            HevcSei::ContentLightLevel(SeiContentLightLevel {
                max_content_light_level: 1000,
                max_pic_average_light_level: 400,
            }),
        ];
        for sei in cases {
            let msg = encode_sei_message(&sei).expect("encodes");
            let back = decode_sei_message(&msg).expect("decodes");
            assert_eq!(back, sei);
            // And the framing survives a full RBSP round-trip.
            let rbsp = write_sei_rbsp(std::slice::from_ref(&msg)).unwrap();
            assert_eq!(parse_sei_rbsp(&rbsp).unwrap(), vec![msg]);
        }
    }

    #[test]
    fn t35_extension_presence_is_enforced() {
        let bad = HevcSei::UserDataRegisteredItuTT35(SeiUserDataRegisteredItuTT35 {
            country_code: 0xB5,
            country_code_extension: Some(1),
            payload: vec![],
        });
        assert!(encode_sei_message(&bad).is_err());
    }

    #[test]
    fn buffering_period_roundtrips_nal_only() {
        let hrd = hrd_ctx_template(true, false, false, 1);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: false,
        };
        let bp = SeiBufferingPeriod {
            bp_seq_parameter_set_id: 0,
            irap_cpb_params_present_flag: false,
            nal_delays: vec![
                SeiInitialCpbDelays {
                    initial_cpb_removal_delay: 90_000,
                    initial_cpb_removal_offset: 0,
                    alt: None,
                },
                SeiInitialCpbDelays {
                    initial_cpb_removal_delay: 45_000,
                    initial_cpb_removal_offset: 100,
                    alt: None,
                },
            ],
            ..Default::default()
        };
        let msg = encode_buffering_period(&bp, &ctx).expect("BP encodes");
        let back = decode_buffering_period(&msg, &ctx).expect("BP decodes");
        assert_eq!(back, bp);
        // Byte fixed point: re-encoding the decode reproduces the bytes.
        assert_eq!(encode_buffering_period(&back, &ctx).unwrap(), msg);
    }

    #[test]
    fn buffering_period_irap_alt_delays_and_use_alt_flag() {
        let hrd = hrd_ctx_template(true, true, false, 0);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: false,
        };
        let mk = |d| SeiInitialCpbDelays {
            initial_cpb_removal_delay: d,
            initial_cpb_removal_offset: 7,
            alt: Some((d / 2, 3)),
        };
        let bp = SeiBufferingPeriod {
            bp_seq_parameter_set_id: 2,
            irap_cpb_params_present_flag: true,
            cpb_delay_offset: 0x1234,
            dpb_delay_offset: 0x3A,
            concatenation_flag: true,
            au_cpb_removal_delay_delta_minus1: 5,
            nal_delays: vec![mk(1000)],
            vcl_delays: vec![mk(2000)],
            use_alt_cpb_params_flag: Some(true),
        };
        let msg = encode_buffering_period(&bp, &ctx).expect("BP encodes");
        let back = decode_buffering_period(&msg, &ctx).expect("BP decodes");
        assert_eq!(back, bp);
        assert_eq!(encode_buffering_period(&back, &ctx).unwrap(), msg);
    }

    #[test]
    fn buffering_period_rejects_wrong_cpb_count_and_oversized_fields() {
        let hrd = hrd_ctx_template(true, false, false, 1);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: false,
        };
        let bp = SeiBufferingPeriod {
            nal_delays: vec![SeiInitialCpbDelays::default()], // CpbCnt is 2
            ..Default::default()
        };
        assert!(encode_buffering_period(&bp, &ctx).is_err());
        // dpb_delay_offset u(10) cannot carry 0x400.
        let bp = SeiBufferingPeriod {
            irap_cpb_params_present_flag: true,
            dpb_delay_offset: 0x400,
            nal_delays: vec![
                SeiInitialCpbDelays {
                    alt: Some((0, 0)),
                    ..Default::default()
                };
                2
            ],
            ..Default::default()
        };
        assert!(encode_buffering_period(&bp, &ctx).is_err());
        // sub_layer_id outside the HRD's sub-layer list.
        let ctx_bad = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 3,
            frame_field_info_present_flag: false,
        };
        assert!(decode_buffering_period(
            &SeiMessage {
                payload_type: SEI_TYPE_BUFFERING_PERIOD,
                payload: vec![0x80],
            },
            &ctx_bad
        )
        .is_err());
    }

    #[test]
    fn pic_timing_roundtrips_frame_field_and_delays() {
        let hrd = hrd_ctx_template(true, false, false, 0);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: true,
        };
        let pt = SeiPicTiming {
            frame_field_info: Some((3, 1, false)), // top field first, interlaced
            au_cpb_removal_delay_minus1: 0x1FF,
            pic_dpb_output_delay: 0x155,
            ..Default::default()
        };
        let msg = encode_pic_timing(&pt, &ctx).expect("PT encodes");
        let back = decode_pic_timing(&msg, &ctx).expect("PT decodes");
        assert_eq!(back, pt);
        assert_eq!(encode_pic_timing(&back, &ctx).unwrap(), msg);
    }

    #[test]
    fn pic_timing_decoding_units_roundtrip_common_and_per_du() {
        let hrd = hrd_ctx_template(true, false, true, 0);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: false,
        };
        // Per-DU increments (no common delay): last DU has none.
        let pt = SeiPicTiming {
            au_cpb_removal_delay_minus1: 9,
            pic_dpb_output_delay: 4,
            pic_dpb_output_du_delay: 0x321,
            du_common_cpb_removal_delay_increment_minus1: None,
            decoding_units: Some(vec![
                SeiPicTimingDu {
                    num_nalus_in_du_minus1: 0,
                    du_cpb_removal_delay_increment_minus1: Some(17),
                },
                SeiPicTimingDu {
                    num_nalus_in_du_minus1: 2,
                    du_cpb_removal_delay_increment_minus1: Some(3),
                },
                SeiPicTimingDu {
                    num_nalus_in_du_minus1: 1,
                    du_cpb_removal_delay_increment_minus1: None,
                },
            ]),
            ..Default::default()
        };
        let msg = encode_pic_timing(&pt, &ctx).expect("PT encodes");
        let back = decode_pic_timing(&msg, &ctx).expect("PT decodes");
        assert_eq!(back, pt);
        assert_eq!(encode_pic_timing(&back, &ctx).unwrap(), msg);

        // Common delay: no per-DU increments at all.
        let pt = SeiPicTiming {
            au_cpb_removal_delay_minus1: 1,
            pic_dpb_output_delay: 2,
            pic_dpb_output_du_delay: 3,
            du_common_cpb_removal_delay_increment_minus1: Some(41),
            decoding_units: Some(vec![
                SeiPicTimingDu {
                    num_nalus_in_du_minus1: 5,
                    du_cpb_removal_delay_increment_minus1: None,
                };
                2
            ]),
            ..Default::default()
        };
        let msg = encode_pic_timing(&pt, &ctx).expect("PT encodes");
        let back = decode_pic_timing(&msg, &ctx).expect("PT decodes");
        assert_eq!(back, pt);
    }

    #[test]
    fn pic_timing_bounds_hostile_du_count() {
        let hrd = hrd_ctx_template(true, false, true, 0);
        let ctx = SeiHrdContext {
            hrd: &hrd,
            sub_layer_id: 0,
            frame_field_info_present_flag: false,
        };
        // Build a payload declaring a huge num_decoding_units_minus1
        // with almost no bytes behind it.
        let mut w = crate::bit_writer::BitWriter::new();
        w.write_bits(0, 16); // au_cpb_removal_delay_minus1 u(16)
        w.write_bits(0, 10); // pic_dpb_output_delay u(10)
        w.write_bits(0, 12); // pic_dpb_output_du_delay u(12)
        w.write_ue(1_000_000).unwrap(); // num_decoding_units_minus1
        w.write_rbsp_trailing_bits();
        let msg = SeiMessage {
            payload_type: SEI_TYPE_PIC_TIMING,
            payload: w.finish(),
        };
        assert!(matches!(
            decode_pic_timing(&msg, &ctx),
            Err(BitstreamError::UnexpectedEnd(_))
        ));
    }
}
