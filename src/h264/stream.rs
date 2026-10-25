//! H.264 stream front end: parameter-set bookkeeping, full slice
//! headers for every NAL unit, and detection of the first slice of each
//! primary coded picture (§7.4.1.2.4).
//!
//! [`H264Parser::process_nal`] takes one NAL unit (header byte first,
//! emulation prevention bytes in place, as [`nal_units`] or a
//! length-prefixed sample yields it) and returns what it was. Slices
//! come back with their complete [`SliceHeader`], whether they start a
//! new picture, and where their `slice_data()` begins inside the NAL
//! unit — everything a hardware decode bridge needs before it builds
//! its parameter buffers.

use super::slice::{SliceHeader, parse_slice_header, peek_slice_pps_id};
use super::{
    H264Pps, H264Sps, NAL_TYPE_AUD, NAL_TYPE_IDR, NAL_TYPE_PPS, NAL_TYPE_SPS, ebsp_to_rbsp,
    nal_header, parse_pps, parse_pps_with_sps, parse_sps,
};
use crate::BitstreamError;
use crate::bit_reader::BitReader;

/// NAL unit types 10 / 11: end of sequence / end of stream.
pub const NAL_TYPE_END_OF_SEQUENCE: u8 = 10;
pub const NAL_TYPE_END_OF_STREAM: u8 = 11;

/// Every NAL unit of an Annex B byte stream (start codes removed,
/// `trailing_zero_8bits` trimmed, emulation prevention bytes kept).
pub fn nal_units(stream: &[u8]) -> Vec<&[u8]> {
    super::split_annex_b(stream)
        .into_iter()
        .map(|n| {
            let end = n.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
            &n[..end]
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// A coded slice as [`H264Parser`] parsed it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct H264Slice {
    pub header: SliceHeader,
    /// `seq_parameter_set_id` of the active SPS.
    pub sps_id: u8,
    /// First slice of a new primary coded picture (§7.4.1.2.4). Always
    /// false for redundant slices.
    pub first_of_picture: bool,
    /// `redundant_pic_cnt == 0`.
    pub primary: bool,
    /// Bit offset of `slice_data()` inside the NAL unit (header byte and
    /// emulation prevention bytes counted).
    pub slice_data_bit_offset: usize,
}

/// What one NAL unit was.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum H264Event {
    /// A sequence parameter set, now stored under its id.
    Sps(u8),
    /// A picture parameter set, now stored under its id.
    Pps(u8),
    /// A coded slice of an IDR or non-IDR picture.
    Slice(Box<H264Slice>),
    /// A NAL unit that starts a new access unit when it precedes the
    /// first VCL unit (AUD, SEI, SPS/PPS, types 14..=18, §7.4.1.2.3) and
    /// carries nothing this parser decodes, by `nal_unit_type`.
    AccessUnitStart(u8),
    /// End of sequence (the next picture is an IDR picture).
    EndOfSequence,
    /// End of stream.
    EndOfStream,
    /// Any other NAL unit (data partitions, filler, extensions …), by
    /// `nal_unit_type`.
    Other(u8),
}

/// Parameter sets plus the previous primary slice for picture-boundary
/// detection.
#[derive(Debug, Clone)]
pub struct H264Parser {
    sps: Vec<Option<H264Sps>>,
    pps: Vec<Option<H264Pps>>,
    prev: Option<SliceHeader>,
    /// An access unit delimiter or end of sequence / stream arrived
    /// since the previous slice.
    boundary: bool,
}

impl Default for H264Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl H264Parser {
    pub fn new() -> Self {
        H264Parser {
            sps: vec![None; 32],
            pps: vec![None; 256],
            prev: None,
            boundary: true,
        }
    }

    /// The stored SPS with `seq_parameter_set_id == id`.
    pub fn sps(&self, id: u8) -> Option<&H264Sps> {
        self.sps.get(usize::from(id)).and_then(Option::as_ref)
    }

    /// The stored PPS with `pic_parameter_set_id == id`.
    pub fn pps(&self, id: u8) -> Option<&H264Pps> {
        self.pps.get(usize::from(id)).and_then(Option::as_ref)
    }

    /// The SPS / PPS pair a slice was parsed against.
    pub fn active(&self, slice: &H264Slice) -> Option<(&H264Sps, &H264Pps)> {
        Some((
            self.sps(slice.sps_id)?,
            self.pps(slice.header.pic_parameter_set_id)?,
        ))
    }

    /// Store an SPS from out-of-band configuration (e.g. `avcC`).
    pub fn insert_sps(&mut self, sps: H264Sps) {
        let id = usize::from(sps.seq_parameter_set_id);
        if id < 32 {
            self.sps[id] = Some(sps);
        }
    }

    /// Store a PPS from out-of-band configuration.
    pub fn insert_pps(&mut self, pps: H264Pps) {
        let id = usize::from(pps.pic_parameter_set_id);
        self.pps[id] = Some(pps);
    }

    /// Process one NAL unit (header byte first, emulation prevention in
    /// place).
    pub fn process_nal(&mut self, nal: &[u8]) -> Result<H264Event, BitstreamError> {
        let first = *nal
            .first()
            .ok_or_else(|| BitstreamError::unexpected_end("empty NAL unit"))?;
        let (forbidden, nal_ref_idc, nal_unit_type) = nal_header(first);
        if forbidden != 0 {
            return Err(BitstreamError::invalid("forbidden_zero_bit set"));
        }
        match nal_unit_type {
            1 | NAL_TYPE_IDR => self.slice(nal, nal_ref_idc, nal_unit_type),
            NAL_TYPE_SPS => {
                let sps = parse_sps(&ebsp_to_rbsp(&nal[1..]))?;
                let id = sps.seq_parameter_set_id;
                if id > 31 {
                    return Err(BitstreamError::invalid("seq_parameter_set_id > 31"));
                }
                self.sps[usize::from(id)] = Some(sps);
                Ok(H264Event::Sps(id))
            }
            NAL_TYPE_PPS => {
                let rbsp = ebsp_to_rbsp(&nal[1..]);
                let mut r = BitReader::new(&rbsp);
                let pps_id = r.ue()?;
                let sps_id = r.ue()?;
                if pps_id > 255 || sps_id > 31 {
                    return Err(BitstreamError::invalid("PPS ids out of range"));
                }
                let pps = match self.sps(sps_id as u8) {
                    Some(sps) => parse_pps_with_sps(&rbsp, sps)?,
                    None => parse_pps(&rbsp)?,
                };
                self.pps[pps_id as usize] = Some(pps);
                Ok(H264Event::Pps(pps_id as u8))
            }
            NAL_TYPE_END_OF_SEQUENCE => {
                self.boundary = true;
                Ok(H264Event::EndOfSequence)
            }
            NAL_TYPE_END_OF_STREAM => {
                self.boundary = true;
                Ok(H264Event::EndOfStream)
            }
            NAL_TYPE_AUD => {
                // An access unit delimiter always starts an access unit.
                self.boundary = true;
                Ok(H264Event::AccessUnitStart(nal_unit_type))
            }
            6 | 13..=18 => Ok(H264Event::AccessUnitStart(nal_unit_type)),
            t => Ok(H264Event::Other(t)),
        }
    }

    fn slice(
        &mut self,
        nal: &[u8],
        nal_ref_idc: u8,
        nal_unit_type: u8,
    ) -> Result<H264Event, BitstreamError> {
        let rbsp = ebsp_to_rbsp(&nal[1..]);
        let pps_id = peek_slice_pps_id(&rbsp)?;
        let pps = self.pps(pps_id).ok_or_else(|| {
            BitstreamError::invalid(format!("slice refers to missing PPS {pps_id}"))
        })?;
        let sps_id = pps.seq_parameter_set_id;
        let sps = self.sps(sps_id).ok_or_else(|| {
            BitstreamError::invalid(format!("PPS {pps_id} refers to missing SPS {sps_id}"))
        })?;
        let header = parse_slice_header(&rbsp, nal_unit_type, nal_ref_idc, sps, pps)?;
        let primary = header.redundant_pic_cnt == 0;
        let first_of_picture = primary
            && match (&self.prev, self.boundary) {
                (None, _) | (_, true) => true,
                (Some(prev), false) => differs(prev, &header, sps),
            };
        if primary {
            self.boundary = false;
            self.prev = Some(header.clone());
        }
        let slice_data_bit_offset = header.slice_data_bit_offset_in_nal(nal);
        Ok(H264Event::Slice(Box::new(H264Slice {
            header,
            sps_id,
            first_of_picture,
            primary,
            slice_data_bit_offset,
        })))
    }
}

/// §7.4.1.2.4: does slice `h` belong to a different primary coded
/// picture than the previous primary slice `prev`?
pub fn differs(prev: &SliceHeader, h: &SliceHeader, sps: &H264Sps) -> bool {
    prev.frame_num != h.frame_num
        || prev.pic_parameter_set_id != h.pic_parameter_set_id
        || prev.field_pic_flag != h.field_pic_flag
        || (prev.field_pic_flag
            && h.field_pic_flag
            && prev.bottom_field_flag != h.bottom_field_flag)
        || ((prev.nal_ref_idc == 0) != (h.nal_ref_idc == 0))
        || (sps.pic_order_cnt_type == 0
            && (prev.pic_order_cnt_lsb != h.pic_order_cnt_lsb
                || prev.delta_pic_order_cnt_bottom != h.delta_pic_order_cnt_bottom))
        || (sps.pic_order_cnt_type == 1 && prev.delta_pic_order_cnt != h.delta_pic_order_cnt)
        || (prev.is_idr() != h.is_idr())
        || (prev.is_idr() && h.is_idr() && prev.idr_pic_id != h.idr_pic_id)
}
