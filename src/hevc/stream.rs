//! HEVC stream front end: VPS / SPS / PPS tables, complete slice
//! segment headers for every coded slice NAL unit, and picture
//! boundaries (`first_slice_segment_in_pic_flag`, §7.4.2.4.4).
//!
//! [`HevcParser::process_nal`] takes one NAL unit (2-byte header first,
//! emulation prevention bytes in place). Dependent slice segments are
//! completed from the preceding independent segment of the picture.

use super::slice::{SliceSegmentHeader, parse_slice_segment_header, peek_slice_pps_id};
use super::{
    HevcPps, HevcSps, HevcVps, NAL_TYPE_AUD, NAL_TYPE_PPS, NAL_TYPE_SPS, NAL_TYPE_VPS, nal_header,
    parse_pps_nal, parse_sps_nal, parse_vps_nal,
};
use crate::BitstreamError;

/// End of sequence / end of bitstream NAL unit types.
pub const NAL_TYPE_EOS: u8 = 36;
pub const NAL_TYPE_EOB: u8 = 37;

/// Every NAL unit of an Annex B byte stream (start codes removed,
/// trailing zero bytes trimmed, emulation prevention bytes kept).
pub fn nal_units(stream: &[u8]) -> Vec<&[u8]> {
    super::split_annex_b(stream)
        .into_iter()
        .map(|n| {
            let end = n.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
            &n[..end]
        })
        .filter(|n| n.len() >= 2)
        .collect()
}

/// A coded slice segment as [`HevcParser`] parsed it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcSlice {
    pub header: SliceSegmentHeader,
    /// `sps_seq_parameter_set_id` of the active SPS.
    pub sps_id: u8,
    /// First slice segment of a picture.
    pub first_of_picture: bool,
}

/// What one NAL unit was.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HevcEvent {
    Vps(u8),
    Sps(u8),
    Pps(u8),
    Slice(Box<HevcSlice>),
    /// End of sequence: the next picture is an IRAP with NoRaslOutputFlag.
    EndOfSequence,
    EndOfBitstream,
    /// AUD and prefix SEI / reserved prefix units that start an access
    /// unit before its first VCL unit, by `nal_unit_type`.
    AccessUnitStart(u8),
    /// Anything else (suffix SEI, filler, reserved VCL types, layers
    /// above 0 …), by `nal_unit_type`.
    Other(u8),
}

/// Parameter-set tables plus the slice context for dependent segments.
#[derive(Debug, Clone)]
pub struct HevcParser {
    vps: Vec<Option<HevcVps>>,
    sps: Vec<Option<HevcSps>>,
    pps: Vec<Option<HevcPps>>,
    last_independent: Option<SliceSegmentHeader>,
}

impl Default for HevcParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HevcParser {
    pub fn new() -> Self {
        HevcParser {
            vps: vec![None; 16],
            sps: vec![None; 16],
            pps: vec![None; 64],
            last_independent: None,
        }
    }

    pub fn vps(&self, id: u8) -> Option<&HevcVps> {
        self.vps.get(usize::from(id)).and_then(Option::as_ref)
    }

    pub fn sps(&self, id: u8) -> Option<&HevcSps> {
        self.sps.get(usize::from(id)).and_then(Option::as_ref)
    }

    pub fn pps(&self, id: u8) -> Option<&HevcPps> {
        self.pps.get(usize::from(id)).and_then(Option::as_ref)
    }

    /// The SPS / PPS pair a slice was parsed against.
    pub fn active(&self, slice: &HevcSlice) -> Option<(&HevcSps, &HevcPps)> {
        Some((
            self.sps(slice.sps_id)?,
            self.pps(slice.header.slice_pic_parameter_set_id)?,
        ))
    }

    /// Store an SPS from out-of-band configuration (e.g. `hvcC`).
    pub fn insert_sps(&mut self, sps: HevcSps) {
        let id = usize::from(sps.sps_seq_parameter_set_id);
        if id < 16 {
            self.sps[id] = Some(sps);
        }
    }

    /// Store a PPS from out-of-band configuration.
    pub fn insert_pps(&mut self, pps: HevcPps) {
        let id = usize::from(pps.pps_pic_parameter_set_id);
        if id < 64 {
            self.pps[id] = Some(pps);
        }
    }

    /// Process one NAL unit.
    pub fn process_nal(&mut self, nal: &[u8]) -> Result<HevcEvent, BitstreamError> {
        if nal.len() < 2 {
            return Err(BitstreamError::unexpected_end(
                "NAL unit shorter than its header",
            ));
        }
        let (forbidden, t, layer, tid_plus1) = nal_header(nal[0], nal[1]);
        if forbidden != 0 || tid_plus1 == 0 {
            return Err(BitstreamError::invalid("HEVC NAL unit header"));
        }
        if layer != 0 {
            return Ok(HevcEvent::Other(t));
        }
        match t {
            0..=9 | 16..=21 => self.slice(nal),
            NAL_TYPE_VPS => {
                let vps = parse_vps_nal(nal)?;
                let id = vps.vps_video_parameter_set_id;
                if id > 15 {
                    return Err(BitstreamError::invalid("vps_video_parameter_set_id > 15"));
                }
                self.vps[usize::from(id)] = Some(vps);
                Ok(HevcEvent::Vps(id))
            }
            NAL_TYPE_SPS => {
                let sps = parse_sps_nal(nal)?;
                let id = sps.sps_seq_parameter_set_id;
                if id > 15 {
                    return Err(BitstreamError::invalid("sps_seq_parameter_set_id > 15"));
                }
                self.sps[usize::from(id)] = Some(sps);
                Ok(HevcEvent::Sps(id))
            }
            NAL_TYPE_PPS => {
                let pps = parse_pps_nal(nal)?;
                let id = pps.pps_pic_parameter_set_id;
                if id > 63 {
                    return Err(BitstreamError::invalid("pps_pic_parameter_set_id > 63"));
                }
                self.pps[usize::from(id)] = Some(pps);
                Ok(HevcEvent::Pps(id))
            }
            NAL_TYPE_EOS => {
                self.last_independent = None;
                Ok(HevcEvent::EndOfSequence)
            }
            NAL_TYPE_EOB => Ok(HevcEvent::EndOfBitstream),
            NAL_TYPE_AUD | 39 | 41..=44 | 48..=55 => Ok(HevcEvent::AccessUnitStart(t)),
            _ => Ok(HevcEvent::Other(t)),
        }
    }

    fn slice(&mut self, nal: &[u8]) -> Result<HevcEvent, BitstreamError> {
        let pps_id = peek_slice_pps_id(nal)?;
        let pps = self.pps(pps_id).ok_or_else(|| {
            BitstreamError::invalid(format!("slice refers to missing PPS {pps_id}"))
        })?;
        let sps_id = pps.pps_seq_parameter_set_id;
        let sps = self.sps(sps_id).ok_or_else(|| {
            BitstreamError::invalid(format!("PPS {pps_id} refers to missing SPS {sps_id}"))
        })?;
        let first = nal.get(2).is_some_and(|b| b & 0x80 != 0);
        let prev = if first {
            None
        } else {
            self.last_independent.as_ref()
        };
        let header = parse_slice_segment_header(nal, sps, pps, prev)?;
        if !header.dependent_slice_segment_flag {
            self.last_independent = Some(header.clone());
        }
        Ok(HevcEvent::Slice(Box::new(HevcSlice {
            first_of_picture: header.first_slice_segment_in_pic_flag,
            header,
            sps_id,
        })))
    }
}
