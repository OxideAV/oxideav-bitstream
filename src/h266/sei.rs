//! H.266 / VVC SEI (supplemental enhancement information) — framing
//! plus the payload families defined inside H.266 itself.
//!
//! Implements the `sei_rbsp()` / `sei_message()` framing of §7.3.2.9
//! / §7.3.6 (byte-identical 0xFF run-length accumulation rule to
//! H.264 / HEVC) and typed decode + byte-exact encode for every SEI
//! payload whose syntax lives in H.266 Annex D:
//!
//! * `buffering_period()` — §D.3 (payload type 0) — self-contained
//!   (all `u(v)` widths come from its own length fields).
//! * `pic_timing()` — §D.4 (type 1) — widths and loop bounds come
//!   from the applicable buffering period, so decode/encode take a
//!   [`VvcBufferingPeriod`] + `TemporalId` context.
//! * `decoding_unit_info()` — §D.5 (type 130) — same context.
//! * `scalable_nesting()` — §D.6 (type 133) — carries nested
//!   `sei_message()`s, surfaced as raw [`SeiMessage`]s.
//! * `subpic_level_info()` — §D.7 (type 203).
//! * `sei_manifest()` — §D.8 (type 200).
//! * `sei_prefix_indication()` — §D.9 (type 201).
//! * `constrained_rasl_encoding_indication()` — §D.10 (type 207) —
//!   an intentionally empty payload.
//!
//! Payload types delegated to other specifications by the §D.2.1
//! dispatch table are surfaced raw as [`VvcSei::Unknown`] — §D.2.2
//! requires decoders to skip unrecognised SEI payloads.

use super::{ebsp_to_rbsp, parse_nal_header, NAL_TYPE_PREFIX_SEI, NAL_TYPE_SUFFIX_SEI};
use crate::bit_reader::BitReader;
use crate::bit_writer::BitWriter;
use crate::BitstreamError;

/// §D.2.1 payloadType values for the in-H.266 families.
pub const SEI_TYPE_BUFFERING_PERIOD: u32 = 0;
pub const SEI_TYPE_PIC_TIMING: u32 = 1;
pub const SEI_TYPE_DECODING_UNIT_INFO: u32 = 130;
pub const SEI_TYPE_SCALABLE_NESTING: u32 = 133;
pub const SEI_TYPE_SEI_MANIFEST: u32 = 200;
pub const SEI_TYPE_SEI_PREFIX_INDICATION: u32 = 201;
pub const SEI_TYPE_SUBPIC_LEVEL_INFO: u32 = 203;
pub const SEI_TYPE_CONSTRAINED_RASL_ENCODING: u32 = 207;

// ─────────────────────────── Framing (§7.3.6) ────────────────────────────────

/// One raw `sei_message()` (§7.3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeiMessage {
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

/// Parse one `sei_message()` starting at `*i`, advancing `*i` past
/// it.
fn parse_one_sei_message(rbsp: &[u8], i: &mut usize) -> Result<SeiMessage, BitstreamError> {
    let mut payload_type: u64 = 0;
    while *i < rbsp.len() && rbsp[*i] == 0xFF {
        payload_type += 255;
        *i += 1;
    }
    if *i >= rbsp.len() {
        return Err(BitstreamError::unexpected_end(
            "SEI message truncated in payloadType",
        ));
    }
    payload_type += rbsp[*i] as u64;
    *i += 1;

    let mut payload_size: u64 = 0;
    while *i < rbsp.len() && rbsp[*i] == 0xFF {
        payload_size += 255;
        *i += 1;
    }
    if *i >= rbsp.len() {
        return Err(BitstreamError::unexpected_end(
            "SEI message truncated in payloadSize",
        ));
    }
    payload_size += rbsp[*i] as u64;
    *i += 1;

    let end = i
        .checked_add(payload_size as usize)
        .ok_or_else(|| BitstreamError::invalid("SEI payloadSize overflow"))?;
    if end > rbsp.len() {
        return Err(BitstreamError::unexpected_end(format!(
            "SEI payloadSize={payload_size} overruns RBSP ({} bytes left)",
            rbsp.len() - *i
        )));
    }
    let payload_type = u32::try_from(payload_type)
        .map_err(|_| BitstreamError::invalid("SEI payloadType exceeds u32"))?;
    let msg = SeiMessage {
        payload_type,
        payload: rbsp[*i..end].to_vec(),
    };
    *i = end;
    Ok(msg)
}

/// Split an SEI RBSP into raw messages (§7.3.2.9 / §7.3.6 framing).
/// Identical accumulation rule to H.264 / HEVC; declared sizes are
/// validated against the remaining bytes before slicing.
pub fn parse_sei_rbsp(rbsp: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        out.push(parse_one_sei_message(rbsp, &mut i)?);
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
pub fn parse_sei_nal(nal_body: &[u8]) -> Result<Vec<SeiMessage>, BitstreamError> {
    if nal_body.len() < 2 {
        return Err(BitstreamError::unexpected_end(
            "H.266 SEI NAL needs at least the 2-byte header",
        ));
    }
    let header = parse_nal_header(nal_body)?;
    if header.nal_unit_type != NAL_TYPE_PREFIX_SEI && header.nal_unit_type != NAL_TYPE_SUFFIX_SEI {
        return Err(BitstreamError::invalid(format!(
            "expected SEI NAL (type {NAL_TYPE_PREFIX_SEI}/{NAL_TYPE_SUFFIX_SEI}), got {}",
            header.nal_unit_type
        )));
    }
    let rbsp = ebsp_to_rbsp(&nal_body[2..]);
    parse_sei_rbsp(&rbsp)
}

/// Emit one `sei_message()` framing (§7.3.6) into `out`.
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

/// Emit a full SEI RBSP (§7.3.2.9 + `rbsp_trailing_bits()`) — the
/// byte-exact inverse of [`parse_sei_rbsp`].
pub fn write_sei_rbsp(messages: &[SeiMessage]) -> Result<Vec<u8>, BitstreamError> {
    if messages.is_empty() {
        return Err(BitstreamError::invalid(
            "sei_rbsp() requires at least one sei_message() (§7.3.2.9)",
        ));
    }
    let mut out = Vec::new();
    for m in messages {
        write_sei_message(&mut out, m);
    }
    out.push(0x80);
    Ok(out)
}

// ─────────────────────────── Payload alignment (§D.2.1) ─────────────────────

/// Consume the `sei_payload()` tail: when the syntax left the reader
/// off a byte boundary, a `payload_bit_equal_to_one` plus
/// `payload_bit_equal_to_zero` padding must follow; either way the
/// payload must then be fully consumed. Reserved
/// payload-extension data is rejected (its length is unrecoverable
/// without the future specification that defines it).
fn read_payload_alignment(r: &mut BitReader<'_>) -> Result<(), BitstreamError> {
    if !r.byte_aligned() {
        if r.read_bit() != 1 {
            return Err(BitstreamError::invalid(
                "sei_payload: payload_bit_equal_to_one was 0 (§D.2.1)",
            ));
        }
        while !r.byte_aligned() {
            if r.read_bit() != 0 {
                return Err(BitstreamError::invalid(
                    "sei_payload: payload_bit_equal_to_zero was 1 (§D.2.1)",
                ));
            }
        }
    }
    if !r.at_end() {
        return Err(BitstreamError::invalid(
            "sei_payload: trailing bytes after the payload syntax (unsupported \
             payload-extension data, §D.2.1)",
        ));
    }
    Ok(())
}

/// Close an encoded `sei_payload()`: append the §D.2.1 alignment
/// (`1` + zero padding) when the syntax ended off a byte boundary.
fn finish_payload(mut w: BitWriter) -> Vec<u8> {
    if !w.byte_aligned() {
        w.write_bit(1);
        w.align_to_byte();
    }
    w.finish()
}

// ─────────────────────────── Buffering period (§D.3) ────────────────────────

/// One initial-CPB-delay schedule entry (`j` loop body of §D.3.1).
/// All four values are `u(bp_cpb_initial_removal_delay_length_minus1
/// + 1)`-bit fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VvcInitialCpbDelays {
    pub removal_delay: u32,
    pub removal_offset: u32,
    /// `(alt_removal_delay, alt_removal_offset)` — coded iff
    /// `bp_du_hrd_params_present_flag`.
    pub alt: Option<(u32, u32)>,
}

/// `buffering_period()` (§D.3.1). Sublayer-indexed arrays hold coded
/// entries at the §D.3.1 loop indices
/// (`bp_sublayer_initial_cpb_removal_delay_present_flag ? 0 :
/// bp_max_sublayers_minus1 ..= bp_max_sublayers_minus1`) and stay
/// empty elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcBufferingPeriod {
    pub bp_nal_hrd_params_present_flag: bool,
    pub bp_vcl_hrd_params_present_flag: bool,
    pub bp_cpb_initial_removal_delay_length_minus1: u8,
    pub bp_cpb_removal_delay_length_minus1: u8,
    pub bp_dpb_output_delay_length_minus1: u8,
    pub bp_du_hrd_params_present_flag: bool,
    pub bp_du_cpb_removal_delay_increment_length_minus1: u8,
    pub bp_dpb_output_delay_du_length_minus1: u8,
    pub bp_du_cpb_params_in_pic_timing_sei_flag: bool,
    pub bp_du_dpb_params_in_pic_timing_sei_flag: bool,
    pub bp_concatenation_flag: bool,
    pub bp_additional_concatenation_info_present_flag: bool,
    /// `u(bp_cpb_initial_removal_delay_length_minus1 + 1)`; coded iff
    /// the additional-concatenation flag is set.
    pub bp_max_initial_removal_delay_for_concatenation: u32,
    /// `u(bp_cpb_removal_delay_length_minus1 + 1)`.
    pub bp_cpb_removal_delay_delta_minus1: u32,
    /// 0..=7 as coded u(3); §D.3.2 further bounds it by
    /// `vps_max_sublayers_minus1`.
    pub bp_max_sublayers_minus1: u8,
    /// Coded iff `bp_max_sublayers_minus1 > 0`; inferred 0 otherwise.
    pub bp_cpb_removal_delay_deltas_present_flag: bool,
    /// 1..=16 entries (§D.3.2), each
    /// `u(bp_cpb_removal_delay_length_minus1 + 1)`.
    pub bp_cpb_removal_delay_delta_vals: Vec<u32>,
    /// 0..=31 (§D.3.2).
    pub bp_cpb_cnt_minus1: u32,
    /// Coded iff `bp_max_sublayers_minus1 > 0`; inferred 0 otherwise.
    pub bp_sublayer_initial_cpb_removal_delay_present_flag: bool,
    /// `bp_cpb_cnt_minus1 + 1` entries per coded sublayer, iff the
    /// NAL HRD flag is set.
    pub nal_initial_cpb: [Vec<VvcInitialCpbDelays>; 8],
    /// Same for the VCL HRD.
    pub vcl_initial_cpb: [Vec<VvcInitialCpbDelays>; 8],
    /// Coded iff `bp_max_sublayers_minus1 > 0`; inferred 0 otherwise.
    pub bp_sublayer_dpb_output_offsets_present_flag: bool,
    /// `bp_max_sublayers_minus1` entries iff the offsets flag is set.
    pub bp_dpb_output_tid_offsets: Vec<u32>,
    pub bp_alt_cpb_params_present_flag: bool,
    pub bp_use_alt_cpb_params_flag: bool,
}

impl VvcBufferingPeriod {
    /// First coded sublayer index of the initial-CPB loops (§D.3.1).
    pub fn first_coded_sublayer(&self) -> usize {
        if self.bp_sublayer_initial_cpb_removal_delay_present_flag {
            0
        } else {
            self.bp_max_sublayers_minus1 as usize
        }
    }
}

/// Decode a `buffering_period()` payload (§D.3.1).
pub fn decode_buffering_period(msg: &SeiMessage) -> Result<VvcBufferingPeriod, BitstreamError> {
    if msg.payload_type != SEI_TYPE_BUFFERING_PERIOD {
        return Err(BitstreamError::invalid(format!(
            "expected buffering_period payloadType 0, got {}",
            msg.payload_type
        )));
    }
    let mut r = BitReader::new(&msg.payload);
    let mut bp = VvcBufferingPeriod {
        bp_nal_hrd_params_present_flag: r.u(1) != 0,
        bp_vcl_hrd_params_present_flag: r.u(1) != 0,
        bp_cpb_initial_removal_delay_length_minus1: r.u(5) as u8,
        bp_cpb_removal_delay_length_minus1: r.u(5) as u8,
        bp_dpb_output_delay_length_minus1: r.u(5) as u8,
        bp_du_hrd_params_present_flag: r.u(1) != 0,
        ..VvcBufferingPeriod::default()
    };
    // §D.3.2: at least one of the two HRD flags must be set.
    if !bp.bp_nal_hrd_params_present_flag && !bp.bp_vcl_hrd_params_present_flag {
        return Err(BitstreamError::invalid(
            "buffering_period: bp_nal/vcl_hrd_params_present_flag both 0 (§D.3.2)",
        ));
    }
    if bp.bp_du_hrd_params_present_flag {
        bp.bp_du_cpb_removal_delay_increment_length_minus1 = r.u(5) as u8;
        bp.bp_dpb_output_delay_du_length_minus1 = r.u(5) as u8;
        bp.bp_du_cpb_params_in_pic_timing_sei_flag = r.u(1) != 0;
        bp.bp_du_dpb_params_in_pic_timing_sei_flag = r.u(1) != 0;
    }
    bp.bp_concatenation_flag = r.u(1) != 0;
    bp.bp_additional_concatenation_info_present_flag = r.u(1) != 0;
    let initial_len = bp.bp_cpb_initial_removal_delay_length_minus1 as u32 + 1;
    let removal_len = bp.bp_cpb_removal_delay_length_minus1 as u32 + 1;
    if bp.bp_additional_concatenation_info_present_flag {
        bp.bp_max_initial_removal_delay_for_concatenation = r.u(initial_len);
    }
    bp.bp_cpb_removal_delay_delta_minus1 = r.u(removal_len);
    bp.bp_max_sublayers_minus1 = r.u(3) as u8;
    if bp.bp_max_sublayers_minus1 > 0 {
        bp.bp_cpb_removal_delay_deltas_present_flag = r.u(1) != 0;
    }
    if bp.bp_cpb_removal_delay_deltas_present_flag {
        let num_minus1 = r.ue()?;
        // §D.3.2: 0..=15 — bounds the loop.
        if num_minus1 > 15 {
            return Err(BitstreamError::invalid(format!(
                "bp_num_cpb_removal_delay_deltas_minus1={num_minus1} (must be 0..=15, §D.3.2)"
            )));
        }
        for _ in 0..=num_minus1 {
            bp.bp_cpb_removal_delay_delta_vals.push(r.u(removal_len));
        }
    }
    bp.bp_cpb_cnt_minus1 = r.ue()?;
    // §D.3.2: 0..=31 — bounds the schedule loops.
    if bp.bp_cpb_cnt_minus1 > 31 {
        return Err(BitstreamError::invalid(format!(
            "bp_cpb_cnt_minus1={} (must be 0..=31, §D.3.2)",
            bp.bp_cpb_cnt_minus1
        )));
    }
    if bp.bp_max_sublayers_minus1 > 0 {
        bp.bp_sublayer_initial_cpb_removal_delay_present_flag = r.u(1) != 0;
    }
    for i in bp.first_coded_sublayer()..=bp.bp_max_sublayers_minus1 as usize {
        for (present, slot) in [
            (bp.bp_nal_hrd_params_present_flag, &mut bp.nal_initial_cpb),
            (bp.bp_vcl_hrd_params_present_flag, &mut bp.vcl_initial_cpb),
        ] {
            if !present {
                continue;
            }
            for _ in 0..=bp.bp_cpb_cnt_minus1 {
                let mut e = VvcInitialCpbDelays {
                    removal_delay: r.u(initial_len),
                    removal_offset: r.u(initial_len),
                    alt: None,
                };
                if bp.bp_du_hrd_params_present_flag {
                    e.alt = Some((r.u(initial_len), r.u(initial_len)));
                }
                slot[i].push(e);
            }
        }
    }
    if bp.bp_max_sublayers_minus1 > 0 {
        bp.bp_sublayer_dpb_output_offsets_present_flag = r.u(1) != 0;
    }
    if bp.bp_sublayer_dpb_output_offsets_present_flag {
        for _ in 0..bp.bp_max_sublayers_minus1 {
            bp.bp_dpb_output_tid_offsets.push(r.ue()?);
        }
    }
    bp.bp_alt_cpb_params_present_flag = r.u(1) != 0;
    if bp.bp_alt_cpb_params_present_flag {
        bp.bp_use_alt_cpb_params_flag = r.u(1) != 0;
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "buffering_period payload too short",
        ));
    }
    read_payload_alignment(&mut r)?;
    Ok(bp)
}

/// Encode a `buffering_period()` into a framed [`SeiMessage`] — the
/// byte-exact inverse of [`decode_buffering_period`].
pub fn encode_buffering_period(bp: &VvcBufferingPeriod) -> Result<SeiMessage, BitstreamError> {
    if !bp.bp_nal_hrd_params_present_flag && !bp.bp_vcl_hrd_params_present_flag {
        return Err(BitstreamError::invalid(
            "buffering_period: bp_nal/vcl_hrd_params_present_flag both 0 (§D.3.2)",
        ));
    }
    if bp.bp_cpb_cnt_minus1 > 31 {
        return Err(BitstreamError::invalid(
            "bp_cpb_cnt_minus1 must be 0..=31 (§D.3.2)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_bit(u32::from(bp.bp_nal_hrd_params_present_flag));
    w.write_bit(u32::from(bp.bp_vcl_hrd_params_present_flag));
    w.write_bits(bp.bp_cpb_initial_removal_delay_length_minus1 as u32, 5);
    w.write_bits(bp.bp_cpb_removal_delay_length_minus1 as u32, 5);
    w.write_bits(bp.bp_dpb_output_delay_length_minus1 as u32, 5);
    w.write_bit(u32::from(bp.bp_du_hrd_params_present_flag));
    if bp.bp_du_hrd_params_present_flag {
        w.write_bits(bp.bp_du_cpb_removal_delay_increment_length_minus1 as u32, 5);
        w.write_bits(bp.bp_dpb_output_delay_du_length_minus1 as u32, 5);
        w.write_bit(u32::from(bp.bp_du_cpb_params_in_pic_timing_sei_flag));
        w.write_bit(u32::from(bp.bp_du_dpb_params_in_pic_timing_sei_flag));
    }
    w.write_bit(u32::from(bp.bp_concatenation_flag));
    w.write_bit(u32::from(bp.bp_additional_concatenation_info_present_flag));
    let initial_len = bp.bp_cpb_initial_removal_delay_length_minus1 as u32 + 1;
    let removal_len = bp.bp_cpb_removal_delay_length_minus1 as u32 + 1;
    let fits = |v: u32, bits: u32| u64::from(v) >> bits == 0;
    if bp.bp_additional_concatenation_info_present_flag {
        if !fits(
            bp.bp_max_initial_removal_delay_for_concatenation,
            initial_len,
        ) {
            return Err(BitstreamError::invalid(
                "bp_max_initial_removal_delay_for_concatenation does not fit its length field",
            ));
        }
        w.write_bits(
            bp.bp_max_initial_removal_delay_for_concatenation,
            initial_len,
        );
    }
    if !fits(bp.bp_cpb_removal_delay_delta_minus1, removal_len) {
        return Err(BitstreamError::invalid(
            "bp_cpb_removal_delay_delta_minus1 does not fit its length field",
        ));
    }
    w.write_bits(bp.bp_cpb_removal_delay_delta_minus1, removal_len);
    if bp.bp_max_sublayers_minus1 > 7 {
        return Err(BitstreamError::invalid(
            "bp_max_sublayers_minus1 does not fit u(3)",
        ));
    }
    w.write_bits(bp.bp_max_sublayers_minus1 as u32, 3);
    if bp.bp_max_sublayers_minus1 > 0 {
        w.write_bit(u32::from(bp.bp_cpb_removal_delay_deltas_present_flag));
    } else if bp.bp_cpb_removal_delay_deltas_present_flag {
        return Err(BitstreamError::invalid(
            "bp_cpb_removal_delay_deltas_present_flag is inferred 0 for a single sublayer",
        ));
    }
    if bp.bp_cpb_removal_delay_deltas_present_flag {
        if bp.bp_cpb_removal_delay_delta_vals.is_empty()
            || bp.bp_cpb_removal_delay_delta_vals.len() > 16
        {
            return Err(BitstreamError::invalid(
                "bp_cpb_removal_delay_delta_vals must have 1..=16 entries (§D.3.2)",
            ));
        }
        w.write_ue(bp.bp_cpb_removal_delay_delta_vals.len() as u32 - 1)?;
        for &v in &bp.bp_cpb_removal_delay_delta_vals {
            if !fits(v, removal_len) {
                return Err(BitstreamError::invalid(
                    "bp_cpb_removal_delay_delta_val does not fit its length field",
                ));
            }
            w.write_bits(v, removal_len);
        }
    } else if !bp.bp_cpb_removal_delay_delta_vals.is_empty() {
        return Err(BitstreamError::invalid(
            "bp_cpb_removal_delay_delta_vals without the deltas-present flag",
        ));
    }
    w.write_ue(bp.bp_cpb_cnt_minus1)?;
    if bp.bp_max_sublayers_minus1 > 0 {
        w.write_bit(u32::from(
            bp.bp_sublayer_initial_cpb_removal_delay_present_flag,
        ));
    } else if bp.bp_sublayer_initial_cpb_removal_delay_present_flag {
        return Err(BitstreamError::invalid(
            "bp_sublayer_initial_cpb_removal_delay_present_flag is inferred 0 for a \
             single sublayer",
        ));
    }
    let coded = bp.first_coded_sublayer()..=bp.bp_max_sublayers_minus1 as usize;
    for (name, present, table) in [
        (
            "NAL",
            bp.bp_nal_hrd_params_present_flag,
            &bp.nal_initial_cpb,
        ),
        (
            "VCL",
            bp.bp_vcl_hrd_params_present_flag,
            &bp.vcl_initial_cpb,
        ),
    ] {
        for (i, entries) in table.iter().enumerate() {
            let expected = if present && coded.contains(&i) {
                bp.bp_cpb_cnt_minus1 as usize + 1
            } else {
                0
            };
            if entries.len() != expected {
                return Err(BitstreamError::invalid(format!(
                    "buffering_period {name} initial-CPB sublayer {i}: {} entries, \
                     expected {expected}",
                    entries.len()
                )));
            }
        }
    }
    for i in coded.clone() {
        for (present, table) in [
            (bp.bp_nal_hrd_params_present_flag, &bp.nal_initial_cpb),
            (bp.bp_vcl_hrd_params_present_flag, &bp.vcl_initial_cpb),
        ] {
            if !present {
                continue;
            }
            for e in &table[i] {
                if !fits(e.removal_delay, initial_len) || !fits(e.removal_offset, initial_len) {
                    return Err(BitstreamError::invalid(
                        "initial CPB removal delay/offset does not fit its length field",
                    ));
                }
                w.write_bits(e.removal_delay, initial_len);
                w.write_bits(e.removal_offset, initial_len);
                match (bp.bp_du_hrd_params_present_flag, e.alt) {
                    (true, Some((d, o))) => {
                        if !fits(d, initial_len) || !fits(o, initial_len) {
                            return Err(BitstreamError::invalid(
                                "alt initial CPB removal delay/offset does not fit its \
                                 length field",
                            ));
                        }
                        w.write_bits(d, initial_len);
                        w.write_bits(o, initial_len);
                    }
                    (false, None) => {}
                    _ => {
                        return Err(BitstreamError::invalid(
                            "alt initial CPB entries must be present iff \
                             bp_du_hrd_params_present_flag (§D.3.1)",
                        ));
                    }
                }
            }
        }
    }
    if bp.bp_max_sublayers_minus1 > 0 {
        w.write_bit(u32::from(bp.bp_sublayer_dpb_output_offsets_present_flag));
    } else if bp.bp_sublayer_dpb_output_offsets_present_flag {
        return Err(BitstreamError::invalid(
            "bp_sublayer_dpb_output_offsets_present_flag is inferred 0 for a single sublayer",
        ));
    }
    let expected_offsets = if bp.bp_sublayer_dpb_output_offsets_present_flag {
        bp.bp_max_sublayers_minus1 as usize
    } else {
        0
    };
    if bp.bp_dpb_output_tid_offsets.len() != expected_offsets {
        return Err(BitstreamError::invalid(
            "bp_dpb_output_tid_offsets length does not match the offsets-present flag",
        ));
    }
    for &v in &bp.bp_dpb_output_tid_offsets {
        w.write_ue(v)?;
    }
    w.write_bit(u32::from(bp.bp_alt_cpb_params_present_flag));
    if bp.bp_alt_cpb_params_present_flag {
        w.write_bit(u32::from(bp.bp_use_alt_cpb_params_flag));
    } else if bp.bp_use_alt_cpb_params_flag {
        return Err(BitstreamError::invalid(
            "bp_use_alt_cpb_params_flag without bp_alt_cpb_params_present_flag",
        ));
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_BUFFERING_PERIOD,
        payload: finish_payload(w),
    })
}

// ─────────────────────────── Picture timing (§D.4) ──────────────────────────

/// Per-sublayer alternative-CPB timing block (§D.4.1 inner loops).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcPtAltCpb {
    /// `(alt_initial_removal_delay_delta[j],
    /// alt_initial_removal_offset_delta[j])`, `bp_cpb_cnt_minus1 + 1`
    /// entries, each `u(bp_cpb_initial_removal_delay_length_minus1 +
    /// 1)`.
    pub initial_deltas: Vec<(u32, u32)>,
    /// `u(bp_cpb_removal_delay_length_minus1 + 1)`.
    pub cpb_delay_offset: u32,
    /// `u(bp_dpb_output_delay_length_minus1 + 1)`.
    pub dpb_delay_offset: u32,
}

/// Decoding-unit block of `pic_timing()` — coded iff
/// `bp_du_hrd_params_present_flag &&
/// bp_du_cpb_params_in_pic_timing_sei_flag`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcPtDuInfo {
    /// Coded iff `pt_num_decoding_units_minus1 > 0`; inferred 0.
    pub pt_du_common_cpb_removal_delay_flag: bool,
    /// `pt_du_common_cpb_removal_delay_increment_minus1[i]` — coded
    /// for sublayers with delays present when the common flag is set.
    pub common_increment_minus1: [u32; 8],
    /// `pt_num_nalus_in_du_minus1[i]` — one per decoding unit.
    pub num_nalus_in_du_minus1: Vec<u32>,
    /// `pt_du_cpb_removal_delay_increment_minus1[i][j]` — one row per
    /// decoding unit `i < pt_num_decoding_units_minus1` when the
    /// common flag is off; indexed by absolute sublayer `j`.
    pub du_increment_minus1: Vec<[u32; 8]>,
}

/// `pic_timing()` (§D.4.1). Sublayer-indexed arrays are absolute
/// (`TemporalId ..= bp_max_sublayers_minus1` hold coded/inferred
/// values; other entries stay at their defaults).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcPicTiming {
    /// `pt_cpb_removal_delay_minus1[i]`,
    /// `u(bp_cpb_removal_delay_length_minus1 + 1)`. Entry
    /// `[bp_max_sublayers_minus1]` is always coded (first syntax
    /// element).
    pub pt_cpb_removal_delay_minus1: [u32; 8],
    /// `[bp_max_sublayers_minus1]` is inferred 1 (§D.4.2).
    pub pt_sublayer_delays_present_flag: [bool; 8],
    pub pt_cpb_removal_delay_delta_enabled_flag: [bool; 8],
    /// `u(Ceil(Log2(bp_num_cpb_removal_delay_deltas_minus1 + 1)))`;
    /// inferred 0 when that width is zero.
    pub pt_cpb_removal_delay_delta_idx: [u32; 8],
    /// `u(bp_dpb_output_delay_length_minus1 + 1)`.
    pub pt_dpb_output_delay: u32,
    /// Coded iff `bp_alt_cpb_params_present_flag`.
    pub pt_cpb_alt_timing_info_present_flag: bool,
    /// Per-sublayer alternative timing for the NAL HRD — `Some` for
    /// the §D.3.1-coded sublayer range when alt timing is on and the
    /// BP signals the NAL HRD.
    pub nal_alt: [Option<VvcPtAltCpb>; 8],
    pub vcl_alt: [Option<VvcPtAltCpb>; 8],
    /// `u(bp_dpb_output_delay_du_length_minus1 + 1)` — coded iff
    /// `bp_du_hrd_params_present_flag &&
    /// bp_du_dpb_params_in_pic_timing_sei_flag`.
    pub pt_dpb_output_du_delay: u32,
    /// `Some` iff `bp_du_hrd_params_present_flag &&
    /// bp_du_cpb_params_in_pic_timing_sei_flag`.
    pub du: Option<VvcPtDuInfo>,
    /// Coded iff `bp_additional_concatenation_info_present_flag`.
    pub pt_delay_for_concatenation_ensured_flag: bool,
    pub pt_display_elemental_periods_minus1: u8,
}

/// Width of `pt_cpb_removal_delay_delta_idx` (§D.4.2).
fn delta_idx_bits(bp: &VvcBufferingPeriod) -> u32 {
    let n = bp.bp_cpb_removal_delay_delta_vals.len() as u32;
    if n <= 1 {
        0
    } else {
        32 - (n - 1).leading_zeros()
    }
}

/// Decode a `pic_timing()` payload (§D.4.1) against its applicable
/// buffering period and the SEI NAL's `TemporalId`.
pub fn decode_pic_timing(
    msg: &SeiMessage,
    bp: &VvcBufferingPeriod,
    temporal_id: u8,
) -> Result<VvcPicTiming, BitstreamError> {
    if msg.payload_type != SEI_TYPE_PIC_TIMING {
        return Err(BitstreamError::invalid(format!(
            "expected pic_timing payloadType 1, got {}",
            msg.payload_type
        )));
    }
    let max = bp.bp_max_sublayers_minus1 as usize;
    if temporal_id as usize > max {
        return Err(BitstreamError::invalid(
            "pic_timing TemporalId exceeds bp_max_sublayers_minus1",
        ));
    }
    let removal_len = bp.bp_cpb_removal_delay_length_minus1 as u32 + 1;
    let initial_len = bp.bp_cpb_initial_removal_delay_length_minus1 as u32 + 1;
    let output_len = bp.bp_dpb_output_delay_length_minus1 as u32 + 1;
    let mut r = BitReader::new(&msg.payload);
    let mut pt = VvcPicTiming::default();
    pt.pt_cpb_removal_delay_minus1[max] = r.u(removal_len);
    pt.pt_sublayer_delays_present_flag[max] = true; // inferred (§D.4.2)
    for i in temporal_id as usize..max {
        pt.pt_sublayer_delays_present_flag[i] = r.u(1) != 0;
        if pt.pt_sublayer_delays_present_flag[i] {
            if bp.bp_cpb_removal_delay_deltas_present_flag {
                pt.pt_cpb_removal_delay_delta_enabled_flag[i] = r.u(1) != 0;
            }
            if pt.pt_cpb_removal_delay_delta_enabled_flag[i] {
                let bits = delta_idx_bits(bp);
                if bits > 0 {
                    let idx = r.u(bits);
                    if idx as usize >= bp.bp_cpb_removal_delay_delta_vals.len() {
                        return Err(BitstreamError::invalid(
                            "pt_cpb_removal_delay_delta_idx out of the BP delta list (§D.4.2)",
                        ));
                    }
                    pt.pt_cpb_removal_delay_delta_idx[i] = idx;
                }
            } else {
                pt.pt_cpb_removal_delay_minus1[i] = r.u(removal_len);
            }
        }
    }
    pt.pt_dpb_output_delay = r.u(output_len);
    if bp.bp_alt_cpb_params_present_flag {
        pt.pt_cpb_alt_timing_info_present_flag = r.u(1) != 0;
        if pt.pt_cpb_alt_timing_info_present_flag {
            for (present, table) in [
                (bp.bp_nal_hrd_params_present_flag, &mut pt.nal_alt),
                (bp.bp_vcl_hrd_params_present_flag, &mut pt.vcl_alt),
            ] {
                if !present {
                    continue;
                }
                for slot in table
                    .iter_mut()
                    .take(max + 1)
                    .skip(bp.first_coded_sublayer())
                {
                    let mut alt = VvcPtAltCpb::default();
                    for _ in 0..=bp.bp_cpb_cnt_minus1 {
                        alt.initial_deltas
                            .push((r.u(initial_len), r.u(initial_len)));
                    }
                    alt.cpb_delay_offset = r.u(removal_len);
                    alt.dpb_delay_offset = r.u(output_len);
                    *slot = Some(alt);
                }
            }
        }
    }
    if bp.bp_du_hrd_params_present_flag && bp.bp_du_dpb_params_in_pic_timing_sei_flag {
        pt.pt_dpb_output_du_delay = r.u(bp.bp_dpb_output_delay_du_length_minus1 as u32 + 1);
    }
    if bp.bp_du_hrd_params_present_flag && bp.bp_du_cpb_params_in_pic_timing_sei_flag {
        let du_len = bp.bp_du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
        let mut du = VvcPtDuInfo::default();
        let num_du_minus1 = r.ue()?;
        // Hostile-input bound: each DU costs at least one bit.
        if num_du_minus1 as u64 > r.bits_remaining() as u64 {
            return Err(BitstreamError::unexpected_end(
                "pt_num_decoding_units_minus1 exceeds remaining payload",
            ));
        }
        if num_du_minus1 > 0 {
            du.pt_du_common_cpb_removal_delay_flag = r.u(1) != 0;
            if du.pt_du_common_cpb_removal_delay_flag {
                for i in temporal_id as usize..=max {
                    if pt.pt_sublayer_delays_present_flag[i] {
                        du.common_increment_minus1[i] = r.u(du_len);
                    }
                }
            }
            for i in 0..=num_du_minus1 {
                du.num_nalus_in_du_minus1.push(r.ue()?);
                if !du.pt_du_common_cpb_removal_delay_flag && i < num_du_minus1 {
                    let mut row = [0u32; 8];
                    for (j, v) in row
                        .iter_mut()
                        .enumerate()
                        .take(max + 1)
                        .skip(temporal_id as usize)
                    {
                        if pt.pt_sublayer_delays_present_flag[j] {
                            *v = r.u(du_len);
                        }
                    }
                    du.du_increment_minus1.push(row);
                }
            }
        } else {
            du.num_nalus_in_du_minus1.push(r.ue()?);
        }
        pt.du = Some(du);
    }
    if bp.bp_additional_concatenation_info_present_flag {
        pt.pt_delay_for_concatenation_ensured_flag = r.u(1) != 0;
    }
    pt.pt_display_elemental_periods_minus1 = r.u(8) as u8;
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "pic_timing payload too short",
        ));
    }
    read_payload_alignment(&mut r)?;
    Ok(pt)
}

/// Encode a `pic_timing()` into a framed [`SeiMessage`] — the
/// byte-exact inverse of [`decode_pic_timing`] under the same
/// buffering-period + `TemporalId` context.
pub fn encode_pic_timing(
    pt: &VvcPicTiming,
    bp: &VvcBufferingPeriod,
    temporal_id: u8,
) -> Result<SeiMessage, BitstreamError> {
    let max = bp.bp_max_sublayers_minus1 as usize;
    if temporal_id as usize > max {
        return Err(BitstreamError::invalid(
            "pic_timing TemporalId exceeds bp_max_sublayers_minus1",
        ));
    }
    if !pt.pt_sublayer_delays_present_flag[max] {
        return Err(BitstreamError::invalid(
            "pt_sublayer_delays_present_flag[bp_max_sublayers_minus1] is inferred 1 (§D.4.2)",
        ));
    }
    let removal_len = bp.bp_cpb_removal_delay_length_minus1 as u32 + 1;
    let initial_len = bp.bp_cpb_initial_removal_delay_length_minus1 as u32 + 1;
    let output_len = bp.bp_dpb_output_delay_length_minus1 as u32 + 1;
    let fits = |v: u32, bits: u32| u64::from(v) >> bits == 0;
    let mut w = BitWriter::new();
    if !fits(pt.pt_cpb_removal_delay_minus1[max], removal_len) {
        return Err(BitstreamError::invalid(
            "pt_cpb_removal_delay_minus1 does not fit its length field",
        ));
    }
    w.write_bits(pt.pt_cpb_removal_delay_minus1[max], removal_len);
    for i in temporal_id as usize..max {
        w.write_bit(u32::from(pt.pt_sublayer_delays_present_flag[i]));
        if pt.pt_sublayer_delays_present_flag[i] {
            if bp.bp_cpb_removal_delay_deltas_present_flag {
                w.write_bit(u32::from(pt.pt_cpb_removal_delay_delta_enabled_flag[i]));
            } else if pt.pt_cpb_removal_delay_delta_enabled_flag[i] {
                return Err(BitstreamError::invalid(
                    "pt_cpb_removal_delay_delta_enabled_flag requires BP removal-delay \
                     deltas (§D.4.1)",
                ));
            }
            if pt.pt_cpb_removal_delay_delta_enabled_flag[i] {
                let bits = delta_idx_bits(bp);
                if pt.pt_cpb_removal_delay_delta_idx[i] as usize
                    >= bp.bp_cpb_removal_delay_delta_vals.len().max(1)
                {
                    return Err(BitstreamError::invalid(
                        "pt_cpb_removal_delay_delta_idx out of the BP delta list (§D.4.2)",
                    ));
                }
                if bits > 0 {
                    w.write_bits(pt.pt_cpb_removal_delay_delta_idx[i], bits);
                }
            } else {
                if !fits(pt.pt_cpb_removal_delay_minus1[i], removal_len) {
                    return Err(BitstreamError::invalid(
                        "pt_cpb_removal_delay_minus1 does not fit its length field",
                    ));
                }
                w.write_bits(pt.pt_cpb_removal_delay_minus1[i], removal_len);
            }
        }
    }
    if !fits(pt.pt_dpb_output_delay, output_len) {
        return Err(BitstreamError::invalid(
            "pt_dpb_output_delay does not fit its length field",
        ));
    }
    w.write_bits(pt.pt_dpb_output_delay, output_len);
    if bp.bp_alt_cpb_params_present_flag {
        w.write_bit(u32::from(pt.pt_cpb_alt_timing_info_present_flag));
    } else if pt.pt_cpb_alt_timing_info_present_flag {
        return Err(BitstreamError::invalid(
            "pt_cpb_alt_timing_info_present_flag requires bp_alt_cpb_params_present_flag",
        ));
    }
    if pt.pt_cpb_alt_timing_info_present_flag {
        for (name, present, table) in [
            ("NAL", bp.bp_nal_hrd_params_present_flag, &pt.nal_alt),
            ("VCL", bp.bp_vcl_hrd_params_present_flag, &pt.vcl_alt),
        ] {
            for (i, slot) in table.iter().enumerate() {
                let expect = present && (bp.first_coded_sublayer()..=max).contains(&i);
                match (expect, slot) {
                    (true, Some(alt)) => {
                        if alt.initial_deltas.len() != bp.bp_cpb_cnt_minus1 as usize + 1 {
                            return Err(BitstreamError::invalid(format!(
                                "pic_timing {name} alt sublayer {i}: initial-delta entries \
                                 must be bp_cpb_cnt_minus1 + 1"
                            )));
                        }
                        for &(d, o) in &alt.initial_deltas {
                            if !fits(d, initial_len) || !fits(o, initial_len) {
                                return Err(BitstreamError::invalid(
                                    "pt alt initial delta does not fit its length field",
                                ));
                            }
                            w.write_bits(d, initial_len);
                            w.write_bits(o, initial_len);
                        }
                        if !fits(alt.cpb_delay_offset, removal_len)
                            || !fits(alt.dpb_delay_offset, output_len)
                        {
                            return Err(BitstreamError::invalid(
                                "pt alt delay offset does not fit its length field",
                            ));
                        }
                        w.write_bits(alt.cpb_delay_offset, removal_len);
                        w.write_bits(alt.dpb_delay_offset, output_len);
                    }
                    (false, None) => {}
                    _ => {
                        return Err(BitstreamError::invalid(format!(
                            "pic_timing {name} alt sublayer {i}: presence does not match \
                             the BP context"
                        )));
                    }
                }
            }
        }
    } else if pt.nal_alt.iter().any(Option::is_some) || pt.vcl_alt.iter().any(Option::is_some) {
        return Err(BitstreamError::invalid(
            "pic_timing alt-timing blocks without pt_cpb_alt_timing_info_present_flag",
        ));
    }
    if bp.bp_du_hrd_params_present_flag && bp.bp_du_dpb_params_in_pic_timing_sei_flag {
        let du_out_len = bp.bp_dpb_output_delay_du_length_minus1 as u32 + 1;
        if !fits(pt.pt_dpb_output_du_delay, du_out_len) {
            return Err(BitstreamError::invalid(
                "pt_dpb_output_du_delay does not fit its length field",
            ));
        }
        w.write_bits(pt.pt_dpb_output_du_delay, du_out_len);
    }
    let du_expected =
        bp.bp_du_hrd_params_present_flag && bp.bp_du_cpb_params_in_pic_timing_sei_flag;
    match (du_expected, &pt.du) {
        (true, Some(du)) => {
            let du_len = bp.bp_du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
            if du.num_nalus_in_du_minus1.is_empty() {
                return Err(BitstreamError::invalid(
                    "pic_timing DU block needs at least one decoding unit",
                ));
            }
            let num_du_minus1 = du.num_nalus_in_du_minus1.len() as u32 - 1;
            w.write_ue(num_du_minus1)?;
            if num_du_minus1 > 0 {
                w.write_bit(u32::from(du.pt_du_common_cpb_removal_delay_flag));
                if du.pt_du_common_cpb_removal_delay_flag {
                    for i in temporal_id as usize..=max {
                        if pt.pt_sublayer_delays_present_flag[i] {
                            if !fits(du.common_increment_minus1[i], du_len) {
                                return Err(BitstreamError::invalid(
                                    "pt_du_common_cpb_removal_delay_increment_minus1 does \
                                     not fit its length field",
                                ));
                            }
                            w.write_bits(du.common_increment_minus1[i], du_len);
                        }
                    }
                }
                let expected_rows = if du.pt_du_common_cpb_removal_delay_flag {
                    0
                } else {
                    num_du_minus1 as usize
                };
                if du.du_increment_minus1.len() != expected_rows {
                    return Err(BitstreamError::invalid(
                        "pic_timing per-DU increment rows must cover every DU but the last \
                         (when the common flag is off)",
                    ));
                }
                for (i, &nalus) in du.num_nalus_in_du_minus1.iter().enumerate() {
                    w.write_ue(nalus)?;
                    if !du.pt_du_common_cpb_removal_delay_flag && i < num_du_minus1 as usize {
                        let row = &du.du_increment_minus1[i];
                        for (j, &v) in row
                            .iter()
                            .enumerate()
                            .take(max + 1)
                            .skip(temporal_id as usize)
                        {
                            if pt.pt_sublayer_delays_present_flag[j] {
                                if !fits(v, du_len) {
                                    return Err(BitstreamError::invalid(
                                        "pt_du_cpb_removal_delay_increment_minus1 does not \
                                         fit its length field",
                                    ));
                                }
                                w.write_bits(v, du_len);
                            }
                        }
                    }
                }
            } else {
                w.write_ue(du.num_nalus_in_du_minus1[0])?;
            }
        }
        (false, None) => {}
        _ => {
            return Err(BitstreamError::invalid(
                "pic_timing DU block presence must match the BP DU-in-PT flags",
            ));
        }
    }
    if bp.bp_additional_concatenation_info_present_flag {
        w.write_bit(u32::from(pt.pt_delay_for_concatenation_ensured_flag));
    } else if pt.pt_delay_for_concatenation_ensured_flag {
        return Err(BitstreamError::invalid(
            "pt_delay_for_concatenation_ensured_flag requires the BP \
             additional-concatenation flag",
        ));
    }
    w.write_bits(pt.pt_display_elemental_periods_minus1 as u32, 8);
    Ok(SeiMessage {
        payload_type: SEI_TYPE_PIC_TIMING,
        payload: finish_payload(w),
    })
}

// ─────────────────────────── Decoding unit info (§D.5) ──────────────────────

/// `decoding_unit_info()` (§D.5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcDecodingUnitInfo {
    pub dui_decoding_unit_idx: u32,
    /// `[bp_max_sublayers_minus1]` is inferred 1 when the BP has
    /// `bp_du_cpb_params_in_pic_timing_sei_flag == 0` (§D.5.2).
    pub dui_sublayer_delays_present_flag: [bool; 8],
    /// `u(bp_du_cpb_removal_delay_increment_length_minus1 + 1)`.
    pub dui_du_cpb_removal_delay_increment: [u32; 8],
    pub dui_dpb_output_du_delay_present_flag: bool,
    /// `u(bp_dpb_output_delay_du_length_minus1 + 1)`.
    pub dui_dpb_output_du_delay: u32,
}

/// Decode a `decoding_unit_info()` payload (§D.5.1) against its
/// applicable buffering period and the SEI NAL's `TemporalId`.
pub fn decode_decoding_unit_info(
    msg: &SeiMessage,
    bp: &VvcBufferingPeriod,
    temporal_id: u8,
) -> Result<VvcDecodingUnitInfo, BitstreamError> {
    if msg.payload_type != SEI_TYPE_DECODING_UNIT_INFO {
        return Err(BitstreamError::invalid(format!(
            "expected decoding_unit_info payloadType 130, got {}",
            msg.payload_type
        )));
    }
    let max = bp.bp_max_sublayers_minus1 as usize;
    if temporal_id as usize > max {
        return Err(BitstreamError::invalid(
            "decoding_unit_info TemporalId exceeds bp_max_sublayers_minus1",
        ));
    }
    let du_len = bp.bp_du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
    let mut r = BitReader::new(&msg.payload);
    let mut dui = VvcDecodingUnitInfo {
        dui_decoding_unit_idx: r.ue()?,
        ..VvcDecodingUnitInfo::default()
    };
    if !bp.bp_du_cpb_params_in_pic_timing_sei_flag {
        for i in temporal_id as usize..=max {
            if i < max {
                dui.dui_sublayer_delays_present_flag[i] = r.u(1) != 0;
            } else {
                dui.dui_sublayer_delays_present_flag[i] = true; // inferred (§D.5.2)
            }
            if dui.dui_sublayer_delays_present_flag[i] {
                dui.dui_du_cpb_removal_delay_increment[i] = r.u(du_len);
            }
        }
    }
    if !bp.bp_du_dpb_params_in_pic_timing_sei_flag {
        dui.dui_dpb_output_du_delay_present_flag = r.u(1) != 0;
    }
    if dui.dui_dpb_output_du_delay_present_flag {
        dui.dui_dpb_output_du_delay = r.u(bp.bp_dpb_output_delay_du_length_minus1 as u32 + 1);
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "decoding_unit_info payload too short",
        ));
    }
    read_payload_alignment(&mut r)?;
    Ok(dui)
}

/// Encode a `decoding_unit_info()` into a framed [`SeiMessage`] — the
/// byte-exact inverse of [`decode_decoding_unit_info`] under the same
/// context.
pub fn encode_decoding_unit_info(
    dui: &VvcDecodingUnitInfo,
    bp: &VvcBufferingPeriod,
    temporal_id: u8,
) -> Result<SeiMessage, BitstreamError> {
    let max = bp.bp_max_sublayers_minus1 as usize;
    if temporal_id as usize > max {
        return Err(BitstreamError::invalid(
            "decoding_unit_info TemporalId exceeds bp_max_sublayers_minus1",
        ));
    }
    let du_len = bp.bp_du_cpb_removal_delay_increment_length_minus1 as u32 + 1;
    let fits = |v: u32, bits: u32| u64::from(v) >> bits == 0;
    let mut w = BitWriter::new();
    w.write_ue(dui.dui_decoding_unit_idx)?;
    if !bp.bp_du_cpb_params_in_pic_timing_sei_flag {
        if !dui.dui_sublayer_delays_present_flag[max] {
            return Err(BitstreamError::invalid(
                "dui_sublayer_delays_present_flag[bp_max_sublayers_minus1] is inferred 1 \
                 (§D.5.2)",
            ));
        }
        for i in temporal_id as usize..=max {
            if i < max {
                w.write_bit(u32::from(dui.dui_sublayer_delays_present_flag[i]));
            }
            if dui.dui_sublayer_delays_present_flag[i] {
                if !fits(dui.dui_du_cpb_removal_delay_increment[i], du_len) {
                    return Err(BitstreamError::invalid(
                        "dui_du_cpb_removal_delay_increment does not fit its length field",
                    ));
                }
                w.write_bits(dui.dui_du_cpb_removal_delay_increment[i], du_len);
            }
        }
    }
    if !bp.bp_du_dpb_params_in_pic_timing_sei_flag {
        w.write_bit(u32::from(dui.dui_dpb_output_du_delay_present_flag));
    } else if dui.dui_dpb_output_du_delay_present_flag {
        return Err(BitstreamError::invalid(
            "dui_dpb_output_du_delay_present_flag is inferred 0 when the BP carries DU \
             DPB params in pic timing (§D.5.1)",
        ));
    }
    if dui.dui_dpb_output_du_delay_present_flag {
        let out_len = bp.bp_dpb_output_delay_du_length_minus1 as u32 + 1;
        if !fits(dui.dui_dpb_output_du_delay, out_len) {
            return Err(BitstreamError::invalid(
                "dui_dpb_output_du_delay does not fit its length field",
            ));
        }
        w.write_bits(dui.dui_dpb_output_du_delay, out_len);
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_DECODING_UNIT_INFO,
        payload: finish_payload(w),
    })
}

// ─────────────────────────── Scalable nesting (§D.6) ────────────────────────

/// `scalable_nesting()` (§D.6.1). Nested SEI messages are surfaced as
/// raw [`SeiMessage`]s (decode them with the same typed decoders).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcScalableNesting {
    pub sn_ols_flag: bool,
    pub sn_subpic_flag: bool,
    /// `sn_ols_idx_delta_minus1[i]` — coded iff `sn_ols_flag`.
    pub sn_ols_idx_delta_minus1: Vec<u32>,
    /// Coded iff `!sn_ols_flag`.
    pub sn_all_layers_flag: bool,
    /// `sn_layer_id[1..=sn_num_layers_minus1]` — coded iff
    /// `!sn_ols_flag && !sn_all_layers_flag` (`sn_layer_id[0]` is the
    /// current layer and never coded).
    pub sn_layer_ids: Vec<u8>,
    /// Coded iff `sn_subpic_flag`.
    pub sn_subpic_id_len_minus1: u32,
    pub sn_subpic_ids: Vec<u32>,
    pub messages: Vec<SeiMessage>,
}

/// Decode a `scalable_nesting()` payload (§D.6.1).
pub fn decode_scalable_nesting(msg: &SeiMessage) -> Result<VvcScalableNesting, BitstreamError> {
    if msg.payload_type != SEI_TYPE_SCALABLE_NESTING {
        return Err(BitstreamError::invalid(format!(
            "expected scalable_nesting payloadType 133, got {}",
            msg.payload_type
        )));
    }
    let mut r = BitReader::new(&msg.payload);
    let mut sn = VvcScalableNesting {
        sn_ols_flag: r.u(1) != 0,
        sn_subpic_flag: r.u(1) != 0,
        ..VvcScalableNesting::default()
    };
    if sn.sn_ols_flag {
        let num_olss_minus1 = r.ue()?;
        // Hostile-input bound: each entry costs at least one bit.
        if num_olss_minus1 as u64 >= r.bits_remaining() as u64 {
            return Err(BitstreamError::unexpected_end(
                "sn_num_olss_minus1 exceeds remaining payload",
            ));
        }
        for _ in 0..=num_olss_minus1 {
            sn.sn_ols_idx_delta_minus1.push(r.ue()?);
        }
    } else {
        sn.sn_all_layers_flag = r.u(1) != 0;
        if !sn.sn_all_layers_flag {
            let num_layers_minus1 = r.ue()?;
            // nuh_layer_id is u(6) so at most 64 layers exist.
            if num_layers_minus1 > 63 {
                return Err(BitstreamError::invalid(format!(
                    "sn_num_layers_minus1={num_layers_minus1} exceeds the 64-layer \
                     nuh_layer_id space"
                )));
            }
            for _ in 1..=num_layers_minus1 {
                sn.sn_layer_ids.push(r.u(6) as u8);
            }
        }
    }
    if sn.sn_subpic_flag {
        let num_subpics_minus1 = r.ue()?;
        sn.sn_subpic_id_len_minus1 = r.ue()?;
        // §D.6.2: sn_subpic_id_len_minus1 is 0..=15.
        if sn.sn_subpic_id_len_minus1 > 15 {
            return Err(BitstreamError::invalid(format!(
                "sn_subpic_id_len_minus1={} (must be 0..=15, §D.6.2)",
                sn.sn_subpic_id_len_minus1
            )));
        }
        let id_bits = sn.sn_subpic_id_len_minus1 + 1;
        if (num_subpics_minus1 as u64 + 1) * id_bits as u64 > r.bits_remaining() as u64 {
            return Err(BitstreamError::unexpected_end(
                "sn_num_subpics_minus1 exceeds remaining payload",
            ));
        }
        for _ in 0..=num_subpics_minus1 {
            sn.sn_subpic_ids.push(r.u(id_bits));
        }
    }
    let num_seis_minus1 = r.ue()?;
    // §D.6.2: 0..=63.
    if num_seis_minus1 > 63 {
        return Err(BitstreamError::invalid(format!(
            "sn_num_seis_minus1={num_seis_minus1} (must be 0..=63, §D.6.2)"
        )));
    }
    while !r.byte_aligned() {
        if r.read_bit() != 0 {
            return Err(BitstreamError::invalid(
                "scalable_nesting sn_zero_bit was 1 (§D.6.1)",
            ));
        }
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "scalable_nesting payload too short",
        ));
    }
    let mut i = r.bit_pos() / 8;
    for _ in 0..=num_seis_minus1 {
        sn.messages
            .push(parse_one_sei_message(&msg.payload, &mut i)?);
    }
    if i != msg.payload.len() {
        return Err(BitstreamError::invalid(
            "scalable_nesting: trailing bytes after the nested SEI messages",
        ));
    }
    Ok(sn)
}

/// Encode a `scalable_nesting()` into a framed [`SeiMessage`] — the
/// byte-exact inverse of [`decode_scalable_nesting`].
pub fn encode_scalable_nesting(sn: &VvcScalableNesting) -> Result<SeiMessage, BitstreamError> {
    if sn.messages.is_empty() || sn.messages.len() > 64 {
        return Err(BitstreamError::invalid(
            "scalable_nesting must nest 1..=64 SEI messages (§D.6.2)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_bit(u32::from(sn.sn_ols_flag));
    w.write_bit(u32::from(sn.sn_subpic_flag));
    if sn.sn_ols_flag {
        if sn.sn_ols_idx_delta_minus1.is_empty() {
            return Err(BitstreamError::invalid(
                "scalable_nesting OLS mode needs at least one OLS index",
            ));
        }
        if sn.sn_all_layers_flag || !sn.sn_layer_ids.is_empty() {
            return Err(BitstreamError::invalid(
                "scalable_nesting layer-mode fields are not coded in OLS mode",
            ));
        }
        w.write_ue(sn.sn_ols_idx_delta_minus1.len() as u32 - 1)?;
        for &v in &sn.sn_ols_idx_delta_minus1 {
            w.write_ue(v)?;
        }
    } else {
        if !sn.sn_ols_idx_delta_minus1.is_empty() {
            return Err(BitstreamError::invalid(
                "scalable_nesting OLS indices are not coded in layer mode",
            ));
        }
        w.write_bit(u32::from(sn.sn_all_layers_flag));
        if !sn.sn_all_layers_flag {
            if sn.sn_layer_ids.len() > 63 {
                return Err(BitstreamError::invalid(
                    "scalable_nesting layer list exceeds the 64-layer nuh_layer_id space",
                ));
            }
            w.write_ue(sn.sn_layer_ids.len() as u32)?;
            for &id in &sn.sn_layer_ids {
                if id > 63 {
                    return Err(BitstreamError::invalid("sn_layer_id does not fit u(6)"));
                }
                w.write_bits(id as u32, 6);
            }
        } else if !sn.sn_layer_ids.is_empty() {
            return Err(BitstreamError::invalid(
                "scalable_nesting layer ids are not coded when sn_all_layers_flag is set",
            ));
        }
    }
    if sn.sn_subpic_flag {
        if sn.sn_subpic_ids.is_empty() {
            return Err(BitstreamError::invalid(
                "scalable_nesting subpic mode needs at least one subpicture id",
            ));
        }
        if sn.sn_subpic_id_len_minus1 > 15 {
            return Err(BitstreamError::invalid(
                "sn_subpic_id_len_minus1 must be 0..=15 (§D.6.2)",
            ));
        }
        w.write_ue(sn.sn_subpic_ids.len() as u32 - 1)?;
        w.write_ue(sn.sn_subpic_id_len_minus1)?;
        let id_bits = sn.sn_subpic_id_len_minus1 + 1;
        for &id in &sn.sn_subpic_ids {
            if u64::from(id) >> id_bits != 0 {
                return Err(BitstreamError::invalid(
                    "sn_subpic_id does not fit its declared length",
                ));
            }
            w.write_bits(id, id_bits);
        }
    } else if !sn.sn_subpic_ids.is_empty() || sn.sn_subpic_id_len_minus1 != 0 {
        return Err(BitstreamError::invalid(
            "scalable_nesting subpicture fields are not coded without sn_subpic_flag",
        ));
    }
    w.write_ue(sn.messages.len() as u32 - 1)?;
    w.align_to_byte(); // sn_zero_bit padding
    let mut payload = w.finish();
    for m in &sn.messages {
        write_sei_message(&mut payload, m);
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_SCALABLE_NESTING,
        payload,
    })
}

// ─────────────────────────── Subpicture level info (§D.7) ───────────────────

/// `subpic_level_info()` (§D.7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcSubpicLevelInfo {
    pub sli_cbr_constraint_flag: bool,
    pub sli_explicit_fraction_present_flag: bool,
    /// Coded iff the explicit-fraction flag is set.
    pub sli_num_subpics_minus1: u32,
    pub sli_max_sublayers_minus1: u8,
    pub sli_sublayer_info_present_flag: bool,
    /// `[k][i]` → `(sli_non_subpic_layers_fraction, sli_ref_level_idc,
    /// per-subpic sli_ref_level_fraction_minus1)`. One row per coded
    /// sublayer `k` (all of `0..=sli_max_sublayers_minus1` when the
    /// sublayer-info flag is set, else just the highest), each with
    /// `sli_num_ref_levels_minus1 + 1` entries.
    pub sublayers: Vec<Vec<VvcSliRefLevel>>,
}

/// One reference level entry of `subpic_level_info()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcSliRefLevel {
    pub non_subpic_layers_fraction: u8,
    pub ref_level_idc: u8,
    /// `sli_num_subpics_minus1 + 1` entries iff the explicit-fraction
    /// flag is set.
    pub ref_level_fraction_minus1: Vec<u8>,
}

/// Decode a `subpic_level_info()` payload (§D.7.1).
pub fn decode_subpic_level_info(msg: &SeiMessage) -> Result<VvcSubpicLevelInfo, BitstreamError> {
    if msg.payload_type != SEI_TYPE_SUBPIC_LEVEL_INFO {
        return Err(BitstreamError::invalid(format!(
            "expected subpic_level_info payloadType 203, got {}",
            msg.payload_type
        )));
    }
    let mut r = BitReader::new(&msg.payload);
    let num_ref_levels_minus1 = r.u(3);
    let mut sli = VvcSubpicLevelInfo {
        sli_cbr_constraint_flag: r.u(1) != 0,
        sli_explicit_fraction_present_flag: r.u(1) != 0,
        ..VvcSubpicLevelInfo::default()
    };
    if sli.sli_explicit_fraction_present_flag {
        sli.sli_num_subpics_minus1 = r.ue()?;
        // Hostile-input bound: each fraction costs 8 bits per entry.
        if sli.sli_num_subpics_minus1 as u64 * 8 > r.bits_remaining() as u64 {
            return Err(BitstreamError::unexpected_end(
                "sli_num_subpics_minus1 exceeds remaining payload",
            ));
        }
    }
    sli.sli_max_sublayers_minus1 = r.u(3) as u8;
    sli.sli_sublayer_info_present_flag = r.u(1) != 0;
    while !r.byte_aligned() {
        if r.read_bit() != 0 {
            return Err(BitstreamError::invalid(
                "subpic_level_info sli_alignment_zero_bit was 1 (§D.7.1)",
            ));
        }
    }
    let start = if sli.sli_sublayer_info_present_flag {
        0
    } else {
        sli.sli_max_sublayers_minus1 as usize
    };
    for _k in start..=sli.sli_max_sublayers_minus1 as usize {
        let mut row = Vec::new();
        for _i in 0..=num_ref_levels_minus1 {
            let mut e = VvcSliRefLevel {
                non_subpic_layers_fraction: r.u(8) as u8,
                ref_level_idc: r.u(8) as u8,
                ..VvcSliRefLevel::default()
            };
            if sli.sli_explicit_fraction_present_flag {
                for _j in 0..=sli.sli_num_subpics_minus1 {
                    e.ref_level_fraction_minus1.push(r.u(8) as u8);
                }
            }
            row.push(e);
        }
        sli.sublayers.push(row);
    }
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end(
            "subpic_level_info payload too short",
        ));
    }
    read_payload_alignment(&mut r)?;
    Ok(sli)
}

/// Encode a `subpic_level_info()` into a framed [`SeiMessage`] — the
/// byte-exact inverse of [`decode_subpic_level_info`].
pub fn encode_subpic_level_info(sli: &VvcSubpicLevelInfo) -> Result<SeiMessage, BitstreamError> {
    let coded_sublayers = if sli.sli_sublayer_info_present_flag {
        sli.sli_max_sublayers_minus1 as usize + 1
    } else {
        1
    };
    if sli.sublayers.len() != coded_sublayers {
        return Err(BitstreamError::invalid(
            "subpic_level_info sublayer rows must match the sublayer-info flag",
        ));
    }
    let num_ref_levels = sli.sublayers[0].len();
    if num_ref_levels == 0 || num_ref_levels > 8 {
        return Err(BitstreamError::invalid(
            "sli_num_ref_levels_minus1 must fit u(3) with at least one level",
        ));
    }
    if sli.sli_max_sublayers_minus1 > 7 {
        return Err(BitstreamError::invalid(
            "sli_max_sublayers_minus1 does not fit u(3)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_bits(num_ref_levels as u32 - 1, 3);
    w.write_bit(u32::from(sli.sli_cbr_constraint_flag));
    w.write_bit(u32::from(sli.sli_explicit_fraction_present_flag));
    if sli.sli_explicit_fraction_present_flag {
        w.write_ue(sli.sli_num_subpics_minus1)?;
    } else if sli.sli_num_subpics_minus1 != 0 {
        return Err(BitstreamError::invalid(
            "sli_num_subpics_minus1 is only coded with explicit fractions",
        ));
    }
    w.write_bits(sli.sli_max_sublayers_minus1 as u32, 3);
    w.write_bit(u32::from(sli.sli_sublayer_info_present_flag));
    w.align_to_byte(); // sli_alignment_zero_bit
    for row in &sli.sublayers {
        if row.len() != num_ref_levels {
            return Err(BitstreamError::invalid(
                "subpic_level_info rows must all have the same reference-level count",
            ));
        }
        for e in row {
            w.write_bits(e.non_subpic_layers_fraction as u32, 8);
            w.write_bits(e.ref_level_idc as u32, 8);
            let expected = if sli.sli_explicit_fraction_present_flag {
                sli.sli_num_subpics_minus1 as usize + 1
            } else {
                0
            };
            if e.ref_level_fraction_minus1.len() != expected {
                return Err(BitstreamError::invalid(
                    "sli_ref_level_fraction_minus1 entries must match \
                     sli_num_subpics_minus1 + 1",
                ));
            }
            for &f in &e.ref_level_fraction_minus1 {
                w.write_bits(f as u32, 8);
            }
        }
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_SUBPIC_LEVEL_INFO,
        payload: finish_payload(w),
    })
}

// ─────────────────────────── SEI manifest / prefix (§D.8/§D.9) ──────────────

/// `sei_manifest()` (§D.8.1): `(payloadType, description)` pairs.
/// Description values per §D.8.2: 0 unknown, 1 necessary,
/// 2 unnecessary, 3 undetermined (4..=255 reserved).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcSeiManifest {
    pub entries: Vec<(u16, u8)>,
}

/// Decode a `sei_manifest()` payload (§D.8.1).
pub fn decode_sei_manifest(msg: &SeiMessage) -> Result<VvcSeiManifest, BitstreamError> {
    if msg.payload_type != SEI_TYPE_SEI_MANIFEST {
        return Err(BitstreamError::invalid(format!(
            "expected sei_manifest payloadType 200, got {}",
            msg.payload_type
        )));
    }
    let mut r = BitReader::new(&msg.payload);
    let num = r.u(16);
    if num as u64 * 24 > r.bits_remaining() as u64 {
        return Err(BitstreamError::unexpected_end(
            "manifest_num_sei_msg_types exceeds remaining payload",
        ));
    }
    let mut m = VvcSeiManifest::default();
    for _ in 0..num {
        m.entries.push((r.u(16) as u16, r.u(8) as u8));
    }
    read_payload_alignment(&mut r)?;
    Ok(m)
}

/// Encode a `sei_manifest()` — byte-exact inverse of
/// [`decode_sei_manifest`].
pub fn encode_sei_manifest(m: &VvcSeiManifest) -> Result<SeiMessage, BitstreamError> {
    if m.entries.len() > u16::MAX as usize {
        return Err(BitstreamError::invalid(
            "sei_manifest entry count does not fit u(16)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_bits(m.entries.len() as u32, 16);
    for &(t, d) in &m.entries {
        w.write_bits(t as u32, 16);
        w.write_bits(d as u32, 8);
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_SEI_MANIFEST,
        payload: finish_payload(w),
    })
}

/// `sei_prefix_indication()` (§D.9.1): bit-string prefixes of an SEI
/// payload of type `prefix_sei_payload_type`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VvcSeiPrefixIndication {
    pub prefix_sei_payload_type: u16,
    /// Each indication is a bit string; stored as the bit values in
    /// coded order (1..=65536 bits each per the u(16) length field).
    pub indications: Vec<Vec<bool>>,
}

/// Decode a `sei_prefix_indication()` payload (§D.9.1).
pub fn decode_sei_prefix_indication(
    msg: &SeiMessage,
) -> Result<VvcSeiPrefixIndication, BitstreamError> {
    if msg.payload_type != SEI_TYPE_SEI_PREFIX_INDICATION {
        return Err(BitstreamError::invalid(format!(
            "expected sei_prefix_indication payloadType 201, got {}",
            msg.payload_type
        )));
    }
    let mut r = BitReader::new(&msg.payload);
    let mut out = VvcSeiPrefixIndication {
        prefix_sei_payload_type: r.u(16) as u16,
        ..VvcSeiPrefixIndication::default()
    };
    let num_minus1 = r.u(8);
    for _ in 0..=num_minus1 {
        let num_bits_minus1 = r.u(16);
        if num_bits_minus1 as u64 + 1 > r.bits_remaining() as u64 {
            return Err(BitstreamError::unexpected_end(
                "num_bits_in_prefix_indication_minus1 exceeds remaining payload",
            ));
        }
        let mut bits = Vec::with_capacity(num_bits_minus1 as usize + 1);
        for _ in 0..=num_bits_minus1 {
            bits.push(r.u(1) != 0);
        }
        while !r.byte_aligned() {
            if r.read_bit() != 1 {
                return Err(BitstreamError::invalid(
                    "sei_prefix_indication byte_alignment_bit_equal_to_one was 0 (§D.9.1)",
                ));
            }
        }
        out.indications.push(bits);
    }
    read_payload_alignment(&mut r)?;
    Ok(out)
}

/// Encode a `sei_prefix_indication()` — byte-exact inverse of
/// [`decode_sei_prefix_indication`].
pub fn encode_sei_prefix_indication(
    p: &VvcSeiPrefixIndication,
) -> Result<SeiMessage, BitstreamError> {
    if p.indications.is_empty() || p.indications.len() > 256 {
        return Err(BitstreamError::invalid(
            "sei_prefix_indication needs 1..=256 indications (u(8) count)",
        ));
    }
    let mut w = BitWriter::new();
    w.write_bits(p.prefix_sei_payload_type as u32, 16);
    w.write_bits(p.indications.len() as u32 - 1, 8);
    for bits in &p.indications {
        if bits.is_empty() || bits.len() > 1 << 16 {
            return Err(BitstreamError::invalid(
                "each SEI prefix indication needs 1..=65536 bits (u(16) length)",
            ));
        }
        w.write_bits(bits.len() as u32 - 1, 16);
        for &b in bits {
            w.write_bit(u32::from(b));
        }
        while !w.byte_aligned() {
            w.write_bit(1); // byte_alignment_bit_equal_to_one
        }
    }
    Ok(SeiMessage {
        payload_type: SEI_TYPE_SEI_PREFIX_INDICATION,
        payload: finish_payload(w),
    })
}

// ─────────────────────────── Typed dispatch ─────────────────────────────────

/// A decoded H.266 SEI payload (context-free families only — decode
/// `pic_timing` / `decoding_unit_info` with their buffering-period
/// context via [`decode_pic_timing`] / [`decode_decoding_unit_info`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VvcSei {
    BufferingPeriod(Box<VvcBufferingPeriod>),
    ScalableNesting(VvcScalableNesting),
    SubpicLevelInfo(VvcSubpicLevelInfo),
    SeiManifest(VvcSeiManifest),
    SeiPrefixIndication(VvcSeiPrefixIndication),
    /// §D.10 — the payload is intentionally empty; presence is the
    /// signal.
    ConstrainedRaslEncoding,
    /// Everything else (including the H.274-specified families and
    /// the context-dependent PT/DUI) surfaced raw — §D.2.2 requires
    /// decoders to skip unrecognised SEI payloads.
    Unknown {
        payload_type: u32,
        payload: Vec<u8>,
    },
}

/// Decode one raw [`SeiMessage`] into a typed [`VvcSei`].
pub fn decode_sei_message(msg: &SeiMessage) -> Result<VvcSei, BitstreamError> {
    match msg.payload_type {
        SEI_TYPE_BUFFERING_PERIOD => Ok(VvcSei::BufferingPeriod(Box::new(
            decode_buffering_period(msg)?,
        ))),
        SEI_TYPE_SCALABLE_NESTING => Ok(VvcSei::ScalableNesting(decode_scalable_nesting(msg)?)),
        SEI_TYPE_SUBPIC_LEVEL_INFO => Ok(VvcSei::SubpicLevelInfo(decode_subpic_level_info(msg)?)),
        SEI_TYPE_SEI_MANIFEST => Ok(VvcSei::SeiManifest(decode_sei_manifest(msg)?)),
        SEI_TYPE_SEI_PREFIX_INDICATION => Ok(VvcSei::SeiPrefixIndication(
            decode_sei_prefix_indication(msg)?,
        )),
        SEI_TYPE_CONSTRAINED_RASL_ENCODING => {
            // §D.10.1: the syntax structure is empty.
            if !msg.payload.is_empty() {
                return Err(BitstreamError::invalid(
                    "constrained_rasl_encoding_indication carries no syntax (§D.10.1)",
                ));
            }
            Ok(VvcSei::ConstrainedRaslEncoding)
        }
        other => Ok(VvcSei::Unknown {
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
    fn framing_roundtrips_and_rejects_truncation() {
        let msg = SeiMessage {
            payload_type: 300,
            payload: (0..700).map(|i| (i % 249 + 1) as u8).collect(),
        };
        let rbsp = write_sei_rbsp(std::slice::from_ref(&msg)).unwrap();
        assert_eq!(parse_sei_rbsp(&rbsp).unwrap(), vec![msg]);

        assert!(matches!(
            parse_sei_rbsp(&[0x06, 0x0A, 0xAA]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
        assert!(matches!(
            parse_sei_rbsp(&[]).unwrap_err(),
            BitstreamError::UnexpectedEnd(_)
        ));
    }

    #[test]
    fn sei_nal_accepts_prefix_and_suffix_types() {
        let body = write_sei_rbsp(&[SeiMessage {
            payload_type: 4,
            payload: vec![0xB5, 0x00, 0x31],
        }])
        .unwrap();
        for t in [NAL_TYPE_PREFIX_SEI, NAL_TYPE_SUFFIX_SEI] {
            let mut nal = vec![0x00, (t << 3) | 0x01];
            nal.extend_from_slice(&crate::nal::rbsp_to_ebsp(&body));
            let msgs = parse_sei_nal(&nal).unwrap_or_else(|e| panic!("type {t}: {e}"));
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].payload_type, 4);
        }
        let nal = [0x00u8, (super::super::NAL_TYPE_SPS << 3) | 0x01, 0x80];
        assert!(matches!(
            parse_sei_nal(&nal).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    /// A representative two-sublayer BP with NAL HRD, DU HRD and alt
    /// CPB params — reused as PT/DUI context.
    fn sample_bp() -> VvcBufferingPeriod {
        let mut bp = VvcBufferingPeriod {
            bp_nal_hrd_params_present_flag: true,
            bp_cpb_initial_removal_delay_length_minus1: 15,
            bp_cpb_removal_delay_length_minus1: 9,
            bp_dpb_output_delay_length_minus1: 7,
            bp_du_hrd_params_present_flag: true,
            bp_du_cpb_removal_delay_increment_length_minus1: 5,
            bp_dpb_output_delay_du_length_minus1: 6,
            bp_du_cpb_params_in_pic_timing_sei_flag: true,
            bp_du_dpb_params_in_pic_timing_sei_flag: false,
            bp_concatenation_flag: false,
            bp_additional_concatenation_info_present_flag: true,
            bp_max_initial_removal_delay_for_concatenation: 0x1234,
            bp_cpb_removal_delay_delta_minus1: 3,
            bp_max_sublayers_minus1: 1,
            bp_cpb_removal_delay_deltas_present_flag: true,
            bp_cpb_removal_delay_delta_vals: vec![7, 12, 100],
            bp_cpb_cnt_minus1: 1,
            bp_sublayer_initial_cpb_removal_delay_present_flag: true,
            bp_sublayer_dpb_output_offsets_present_flag: true,
            bp_dpb_output_tid_offsets: vec![2],
            bp_alt_cpb_params_present_flag: true,
            bp_use_alt_cpb_params_flag: false,
            ..VvcBufferingPeriod::default()
        };
        for i in 0..=1usize {
            for j in 0..=1u32 {
                bp.nal_initial_cpb[i].push(VvcInitialCpbDelays {
                    removal_delay: 9000 + j,
                    removal_offset: 100 + i as u32,
                    alt: Some((50, 60)),
                });
            }
        }
        bp
    }

    #[test]
    fn buffering_period_encode_decode_roundtrips() {
        let bp = sample_bp();
        let msg = encode_buffering_period(&bp).expect("BP encodes");
        assert_eq!(msg.payload_type, SEI_TYPE_BUFFERING_PERIOD);
        let back = decode_buffering_period(&msg).expect("BP decodes");
        assert_eq!(back, bp);
        // And the re-encode is byte-identical.
        assert_eq!(encode_buffering_period(&back).unwrap().payload, msg.payload);
    }

    #[test]
    fn buffering_period_rejects_both_hrd_flags_zero_and_bad_counts() {
        let mut bp = sample_bp();
        bp.bp_nal_hrd_params_present_flag = false;
        assert!(matches!(
            encode_buffering_period(&bp).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));

        let mut w = BitWriter::new();
        w.write_bit(0); // nal
        w.write_bit(0); // vcl — both zero is non-conforming
        w.write_bits(0, 15);
        let msg = SeiMessage {
            payload_type: 0,
            payload: finish_payload(w),
        };
        assert!(matches!(
            decode_buffering_period(&msg).unwrap_err(),
            BitstreamError::InvalidData(_)
        ));
    }

    #[test]
    fn pic_timing_roundtrips_with_du_and_alt_timing() {
        let bp = sample_bp();
        let tid = 0u8;
        let mut pt = VvcPicTiming {
            pt_dpb_output_delay: 44,
            pt_cpb_alt_timing_info_present_flag: true,
            pt_display_elemental_periods_minus1: 1,
            pt_delay_for_concatenation_ensured_flag: true,
            ..VvcPicTiming::default()
        };
        pt.pt_cpb_removal_delay_minus1[1] = 900;
        pt.pt_sublayer_delays_present_flag[1] = true;
        pt.pt_sublayer_delays_present_flag[0] = true;
        pt.pt_cpb_removal_delay_delta_enabled_flag[0] = true;
        pt.pt_cpb_removal_delay_delta_idx[0] = 2;
        for i in 0..=1usize {
            pt.nal_alt[i] = Some(VvcPtAltCpb {
                initial_deltas: vec![(1, 2), (3, 4)],
                cpb_delay_offset: 5,
                dpb_delay_offset: 6,
            });
        }
        // DU block: 3 DUs, per-DU increments (common flag off).
        pt.du = Some(VvcPtDuInfo {
            pt_du_common_cpb_removal_delay_flag: false,
            num_nalus_in_du_minus1: vec![4, 5, 6],
            du_increment_minus1: vec![
                {
                    let mut r = [0u32; 8];
                    r[0] = 7;
                    r[1] = 8;
                    r
                },
                {
                    let mut r = [0u32; 8];
                    r[0] = 9;
                    r[1] = 10;
                    r
                },
            ],
            ..VvcPtDuInfo::default()
        });
        let msg = encode_pic_timing(&pt, &bp, tid).expect("PT encodes");
        let back = decode_pic_timing(&msg, &bp, tid).expect("PT decodes");
        assert_eq!(back, pt);
        assert_eq!(
            encode_pic_timing(&back, &bp, tid).unwrap().payload,
            msg.payload
        );
    }

    #[test]
    fn decoding_unit_info_roundtrips_and_infers_top_sublayer() {
        let mut bp = sample_bp();
        bp.bp_du_cpb_params_in_pic_timing_sei_flag = false;
        let mut dui = VvcDecodingUnitInfo {
            dui_decoding_unit_idx: 3,
            dui_dpb_output_du_delay_present_flag: true,
            dui_dpb_output_du_delay: 42,
            ..VvcDecodingUnitInfo::default()
        };
        dui.dui_sublayer_delays_present_flag[0] = true;
        dui.dui_sublayer_delays_present_flag[1] = true; // top: inferred, must be set
        dui.dui_du_cpb_removal_delay_increment[0] = 11;
        dui.dui_du_cpb_removal_delay_increment[1] = 13;
        let msg = encode_decoding_unit_info(&dui, &bp, 0).expect("DUI encodes");
        let back = decode_decoding_unit_info(&msg, &bp, 0).expect("DUI decodes");
        assert_eq!(back, dui);
    }

    #[test]
    fn scalable_nesting_roundtrips_with_nested_messages() {
        let sn = VvcScalableNesting {
            sn_ols_flag: true,
            sn_subpic_flag: true,
            sn_ols_idx_delta_minus1: vec![0, 1],
            sn_subpic_id_len_minus1: 7,
            sn_subpic_ids: vec![3, 200],
            messages: vec![
                SeiMessage {
                    payload_type: 4,
                    payload: vec![0xB5, 0x00, 0x31, 0xAA],
                },
                SeiMessage {
                    payload_type: 132,
                    payload: vec![1, 2, 3],
                },
            ],
            ..VvcScalableNesting::default()
        };
        let msg = encode_scalable_nesting(&sn).expect("nesting encodes");
        let back = decode_scalable_nesting(&msg).expect("nesting decodes");
        assert_eq!(back, sn);
        // Layer-mode variant.
        let sn2 = VvcScalableNesting {
            sn_ols_flag: false,
            sn_all_layers_flag: false,
            sn_layer_ids: vec![1, 5],
            messages: vec![SeiMessage {
                payload_type: 207,
                payload: vec![],
            }],
            ..VvcScalableNesting::default()
        };
        let msg2 = encode_scalable_nesting(&sn2).expect("layer-mode nesting encodes");
        assert_eq!(decode_scalable_nesting(&msg2).unwrap(), sn2);
    }

    #[test]
    fn subpic_level_info_roundtrips() {
        let sli = VvcSubpicLevelInfo {
            sli_cbr_constraint_flag: true,
            sli_explicit_fraction_present_flag: true,
            sli_num_subpics_minus1: 1,
            sli_max_sublayers_minus1: 1,
            sli_sublayer_info_present_flag: true,
            sublayers: vec![
                vec![VvcSliRefLevel {
                    non_subpic_layers_fraction: 10,
                    ref_level_idc: 51,
                    ref_level_fraction_minus1: vec![100, 200],
                }],
                vec![VvcSliRefLevel {
                    non_subpic_layers_fraction: 20,
                    ref_level_idc: 83,
                    ref_level_fraction_minus1: vec![50, 60],
                }],
            ],
        };
        let msg = encode_subpic_level_info(&sli).expect("SLI encodes");
        assert_eq!(decode_subpic_level_info(&msg).unwrap(), sli);
    }

    #[test]
    fn manifest_and_prefix_indication_roundtrip_via_dispatch() {
        let m = VvcSeiManifest {
            entries: vec![(0, 1), (137, 2), (203, 3)],
        };
        let msg = encode_sei_manifest(&m).unwrap();
        let VvcSei::SeiManifest(back) = decode_sei_message(&msg).unwrap() else {
            panic!("expected manifest");
        };
        assert_eq!(back, m);

        let p = VvcSeiPrefixIndication {
            prefix_sei_payload_type: 137,
            indications: vec![vec![true, false, true], vec![false; 16]],
        };
        let msg = encode_sei_prefix_indication(&p).unwrap();
        let VvcSei::SeiPrefixIndication(back) = decode_sei_message(&msg).unwrap() else {
            panic!("expected prefix indication");
        };
        assert_eq!(back, p);

        // CREI: empty payload decodes; non-empty is rejected.
        let crei = SeiMessage {
            payload_type: SEI_TYPE_CONSTRAINED_RASL_ENCODING,
            payload: vec![],
        };
        assert_eq!(
            decode_sei_message(&crei).unwrap(),
            VvcSei::ConstrainedRaslEncoding
        );
        let bad = SeiMessage {
            payload_type: SEI_TYPE_CONSTRAINED_RASL_ENCODING,
            payload: vec![0],
        };
        assert!(decode_sei_message(&bad).is_err());

        // H.274-delegated types surface raw.
        let raw = SeiMessage {
            payload_type: 19,
            payload: vec![1, 2],
        };
        let VvcSei::Unknown { payload_type, .. } = decode_sei_message(&raw).unwrap() else {
            panic!("expected Unknown");
        };
        assert_eq!(payload_type, 19);
    }
}
