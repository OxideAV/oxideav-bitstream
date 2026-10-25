//! HEVC reference picture state: `NoRaslOutputFlag` (§8.1.3), picture
//! order count (§8.3.1), the reference picture set with DPB marking
//! (§8.3.2) and reference picture list construction (§8.3.4), for the
//! base layer of single-layer, non-SCC streams.
//!
//! [`HevcDpb::begin_picture`] takes a picture's first (independent)
//! slice segment header, derives its POC, applies the RPS to the DPB
//! and returns the five RPS lists as picture keys. A RASL picture whose
//! IRAP has `NoRaslOutputFlag` is reported as skipped (§8.1.3: it is
//! neither decoded nor output). [`HevcDpb::ref_pic_lists`] builds
//! RefPicList0 / RefPicList1 for each P / B slice and
//! [`HevcDpb::finish_picture`] marks the decoded picture as a
//! short-term reference (§8.1.3 step 4). Keys name pictures; a bridge
//! maps them to surfaces and releases those [`HevcDpb::finish_picture`]
//! / [`HevcDpb::begin_picture`] report unused.
//!
//! The decoding process for generating unavailable reference pictures
//! (§8.3.3) is not performed: entries for missing pictures are `None`
//! ("no reference picture"), which only occurs for broken streams or
//! for the RASL pictures the module already tells the caller to skip.

use super::HevcSps;
use super::slice::{HevcSliceType, SliceSegmentHeader};
use crate::BitstreamError;

/// Marking of a picture in the DPB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HevcMarking {
    #[default]
    Unused,
    ShortTerm,
    LongTerm,
}

/// A decoded picture held for reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcRefPicture {
    pub key: u32,
    /// `PicOrderCntVal`.
    pub poc: i32,
    pub marking: HevcMarking,
    pub temporal_id: u8,
}

/// One reference picture list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcListEntry {
    pub key: u32,
    pub poc: i32,
    /// The entry comes from RefPicSetLtCurr (a long-term reference).
    pub long_term: bool,
}

/// The five RPS lists of the current picture (§8.3.2), as picture keys;
/// `None` is "no reference picture".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HevcRps {
    pub st_curr_before: Vec<Option<u32>>,
    pub st_curr_after: Vec<Option<u32>>,
    pub st_foll: Vec<Option<u32>>,
    pub lt_curr: Vec<Option<u32>>,
    pub lt_foll: Vec<Option<u32>>,
}

impl HevcRps {
    /// The picture is used by the current picture (StCurrBefore /
    /// StCurrAfter / LtCurr).
    pub fn is_curr(&self, key: u32) -> bool {
        self.st_curr_before
            .iter()
            .chain(&self.st_curr_after)
            .chain(&self.lt_curr)
            .any(|&k| k == Some(key))
    }
}

/// The picture being decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcCurrentPicture {
    pub key: u32,
    /// `PicOrderCntVal`.
    pub poc: i32,
    /// `PicOrderCntMsb`.
    pub poc_msb: i32,
    pub irap: bool,
    pub idr: bool,
    /// `NoRaslOutputFlag` (IRAP pictures; false otherwise).
    pub no_rasl_output_flag: bool,
    /// A RASL picture associated with an IRAP with `NoRaslOutputFlag`:
    /// do not decode or output it (and do not call
    /// [`HevcDpb::finish_picture`] — the next `begin_picture` drops it).
    pub skip: bool,
    /// `PicOutputFlag` (§8.1.3).
    pub pic_output_flag: bool,
    pub rps: HevcRps,
    /// Keys of DPB pictures the RPS marked unused (they are gone).
    pub released: Vec<u32>,
}

/// What [`HevcDpb::finish_picture`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcFinishedPicture {
    pub key: u32,
    pub poc: i32,
    /// The picture is held as a short-term reference (false when the
    /// DPB holds a single picture, `sps_max_dec_pic_buffering_minus1 == 0`).
    pub stored: bool,
    /// Pictures dropped to keep a hostile stream's DPB bounded (empty
    /// for conforming streams).
    pub released: Vec<u32>,
}

/// RefPicList0 / RefPicList1 of a slice; `None` entries are "no
/// reference picture".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HevcRefPicLists {
    pub list0: Vec<Option<HevcListEntry>>,
    pub list1: Vec<Option<HevcListEntry>>,
}

#[derive(Debug, Clone)]
struct Pending {
    current: HevcCurrentPicture,
    temporal_id: u8,
    referenceable: bool,
}

/// Reference picture state of one HEVC base layer. See the module docs.
#[derive(Debug, Clone, Default)]
pub struct HevcDpb {
    pics: Vec<HevcRefPicture>,
    prev_tid0_poc_lsb: u32,
    prev_tid0_poc_msb: i32,
    /// The next picture is the first of the bitstream or follows an end
    /// of sequence.
    after_eos: bool,
    started: bool,
    /// NoRaslOutputFlag of the last IRAP picture.
    irap_no_rasl_output: bool,
    next_key: u32,
    pending: Option<Pending>,
}

/// RASL nal_unit_types (§7.4.2.2 Table 7-1).
fn is_rasl(t: u8) -> bool {
    matches!(t, 8 | 9)
}

fn is_radl(t: u8) -> bool {
    matches!(t, 6 | 7)
}

/// Sub-layer non-reference picture (even types up to RSV_VCL_N14).
fn is_slnr(t: u8) -> bool {
    t <= 14 && t.is_multiple_of(2)
}

fn is_bla(t: u8) -> bool {
    (16..=18).contains(&t)
}

impl HevcDpb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every picture (seek); the next picture starts a sequence.
    pub fn clear(&mut self) {
        let next = self.next_key;
        *self = HevcDpb {
            next_key: next,
            ..HevcDpb::default()
        };
    }

    /// An end of sequence NAL unit: the next IRAP has `NoRaslOutputFlag`.
    pub fn end_of_sequence(&mut self) {
        self.after_eos = true;
    }

    /// The pictures held for reference, in decoding order —
    /// `ReferenceFrames[]` of a picture-parameter buffer.
    pub fn references(&self) -> impl Iterator<Item = &HevcRefPicture> {
        self.pics
            .iter()
            .filter(|p| p.marking != HevcMarking::Unused)
    }

    /// The picture named `key`, if it is still held.
    pub fn picture(&self, key: u32) -> Option<&HevcRefPicture> {
        self.pics.iter().find(|p| p.key == key)
    }

    /// The picture in progress.
    pub fn current(&self) -> Option<&HevcCurrentPicture> {
        self.pending.as_ref().map(|p| &p.current)
    }

    /// Start the picture whose first slice segment header is `h`
    /// (independent, `first_slice_segment_in_pic_flag == 1`).
    pub fn begin_picture(
        &mut self,
        sps: &HevcSps,
        h: &SliceSegmentHeader,
    ) -> Result<HevcCurrentPicture, BitstreamError> {
        if h.dependent_slice_segment_flag {
            return Err(BitstreamError::invalid(
                "a picture cannot start with a dependent slice segment",
            ));
        }
        if h.nuh_layer_id != 0 {
            return Err(BitstreamError::unsupported(
                "HEVC layers above the base layer",
            ));
        }
        // A skipped (or abandoned) picture in progress is dropped.
        self.pending = None;
        let t = h.nal_unit_type;
        let irap = h.is_irap();
        let no_rasl_output = irap && (h.is_idr() || is_bla(t) || !self.started || self.after_eos);
        if irap {
            self.irap_no_rasl_output = no_rasl_output;
        }
        self.started = true;
        self.after_eos = false;
        let skip = is_rasl(t) && self.irap_no_rasl_output;

        // §8.3.1
        let max_lsb = 1i64 << (u32::from(sps.log2_max_pic_order_cnt_lsb_minus4) + 4);
        let lsb = i64::from(h.slice_pic_order_cnt_lsb);
        let msb: i64 = if irap && no_rasl_output {
            0
        } else {
            let prev_lsb = i64::from(self.prev_tid0_poc_lsb);
            let prev_msb = i64::from(self.prev_tid0_poc_msb);
            if lsb < prev_lsb && prev_lsb - lsb >= max_lsb / 2 {
                prev_msb + max_lsb
            } else if lsb > prev_lsb && lsb - prev_lsb > max_lsb / 2 {
                prev_msb - max_lsb
            } else {
                prev_msb
            }
        };
        let poc = i32::try_from(msb + lsb)
            .map_err(|_| BitstreamError::invalid("PicOrderCntVal overflows 32 bits"))?;
        let msb = msb as i32;
        if skip {
            return Ok(HevcCurrentPicture {
                key: u32::MAX,
                poc,
                poc_msb: msb,
                irap,
                idr: false,
                no_rasl_output_flag: false,
                skip: true,
                pic_output_flag: false,
                rps: HevcRps::default(),
                released: Vec::new(),
            });
        }
        if h.temporal_id == 0 && !is_rasl(t) && !is_radl(t) && !is_slnr(t) {
            self.prev_tid0_poc_lsb = h.slice_pic_order_cnt_lsb;
            self.prev_tid0_poc_msb = msb;
        }

        // §8.3.2
        if irap && no_rasl_output {
            for p in &mut self.pics {
                p.marking = HevcMarking::Unused;
            }
        }
        let mut rps = HevcRps::default();
        if !h.is_idr() {
            let st = &h.short_term_rps;
            let mut poc_st_before = Vec::new();
            let mut poc_st_after = Vec::new();
            let mut poc_st_foll = Vec::new();
            for (d, &used) in st.delta_poc_s0.iter().zip(&st.used_by_curr_pic_s0) {
                let v = i64::from(poc) + i64::from(*d);
                if used {
                    poc_st_before.push(v);
                } else {
                    poc_st_foll.push(v);
                }
            }
            for (d, &used) in st.delta_poc_s1.iter().zip(&st.used_by_curr_pic_s1) {
                let v = i64::from(poc) + i64::from(*d);
                if used {
                    poc_st_after.push(v);
                } else {
                    poc_st_foll.push(v);
                }
            }
            let mut lt_curr = Vec::new();
            let mut lt_foll = Vec::new();
            for lt in &h.long_term_refs {
                let mut v = i64::from(lt.poc_lsb_lt);
                if lt.delta_poc_msb_present_flag {
                    v += i64::from(poc)
                        - i64::from(lt.delta_poc_msb_cycle_lt_acc) * max_lsb
                        - (i64::from(poc) & (max_lsb - 1));
                }
                let e = (v, lt.delta_poc_msb_present_flag);
                if lt.used_by_curr_pic_lt {
                    lt_curr.push(e);
                } else {
                    lt_foll.push(e);
                }
            }
            let find_lt = |pics: &[HevcRefPicture], (v, msb_present): (i64, bool)| {
                pics.iter()
                    .find(|p| {
                        p.marking != HevcMarking::Unused
                            && if msb_present {
                                i64::from(p.poc) == v
                            } else {
                                i64::from(p.poc) & (max_lsb - 1) == v
                            }
                    })
                    .map(|p| p.key)
            };
            rps.lt_curr = lt_curr.iter().map(|&e| find_lt(&self.pics, e)).collect();
            rps.lt_foll = lt_foll.iter().map(|&e| find_lt(&self.pics, e)).collect();
            for key in rps.lt_curr.iter().chain(&rps.lt_foll).flatten() {
                if let Some(p) = self.pics.iter_mut().find(|p| p.key == *key) {
                    p.marking = HevcMarking::LongTerm;
                }
            }
            let find_st = |pics: &[HevcRefPicture], v: i64| {
                pics.iter()
                    .find(|p| p.marking == HevcMarking::ShortTerm && i64::from(p.poc) == v)
                    .map(|p| p.key)
            };
            rps.st_curr_before = poc_st_before
                .iter()
                .map(|&v| find_st(&self.pics, v))
                .collect();
            rps.st_curr_after = poc_st_after
                .iter()
                .map(|&v| find_st(&self.pics, v))
                .collect();
            rps.st_foll = poc_st_foll
                .iter()
                .map(|&v| find_st(&self.pics, v))
                .collect();
        }
        let in_rps: Vec<u32> = rps
            .st_curr_before
            .iter()
            .chain(&rps.st_curr_after)
            .chain(&rps.st_foll)
            .chain(&rps.lt_curr)
            .chain(&rps.lt_foll)
            .flatten()
            .copied()
            .collect();
        for p in &mut self.pics {
            if !in_rps.contains(&p.key) {
                p.marking = HevcMarking::Unused;
            }
        }
        let mut released = Vec::new();
        self.pics.retain(|p| {
            let keep = p.marking != HevcMarking::Unused;
            if !keep {
                released.push(p.key);
            }
            keep
        });

        let key = self.next_key;
        self.next_key = self.next_key.wrapping_add(1);
        let current = HevcCurrentPicture {
            key,
            poc,
            poc_msb: msb,
            irap,
            idr: h.is_idr(),
            no_rasl_output_flag: no_rasl_output,
            skip: false,
            pic_output_flag: h.pic_output_flag,
            rps,
            released,
        };
        // §C.5.2.2: a one-picture DPB is emptied before the next picture.
        let referenceable = sps.sps_max_dec_pic_buffering_minus1 > 0;
        self.pending = Some(Pending {
            current: current.clone(),
            temporal_id: h.temporal_id,
            referenceable,
        });
        Ok(current)
    }

    /// RefPicList0 / RefPicList1 of slice `h` of the current picture
    /// (§8.3.4). Dependent slice segments use their independent
    /// segment's lists.
    pub fn ref_pic_lists(&self, h: &SliceSegmentHeader) -> Result<HevcRefPicLists, BitstreamError> {
        let p = self
            .pending
            .as_ref()
            .ok_or_else(|| BitstreamError::invalid("no picture in progress"))?;
        if !h.slice_type.is_inter() {
            return Ok(HevcRefPicLists::default());
        }
        let rps = &p.current.rps;
        let entry = |k: Option<u32>, long: bool| {
            k.and_then(|k| self.picture(k)).map(|pic| HevcListEntry {
                key: pic.key,
                poc: pic.poc,
                long_term: long,
            })
        };
        let total = rps.st_curr_before.len() + rps.st_curr_after.len() + rps.lt_curr.len();
        if total == 0 {
            return Err(BitstreamError::invalid(
                "P / B slice with NumPicTotalCurr equal to 0",
            ));
        }
        let build =
            |first: &[Option<u32>], second: &[Option<u32>], active: usize, entries: &[u32]| {
                let n = active.max(total);
                let mut temp: Vec<Option<HevcListEntry>> = Vec::with_capacity(n);
                while temp.len() < n {
                    for &k in first {
                        if temp.len() < n {
                            temp.push(entry(k, false));
                        }
                    }
                    for &k in second {
                        if temp.len() < n {
                            temp.push(entry(k, false));
                        }
                    }
                    for &k in &rps.lt_curr {
                        if temp.len() < n {
                            temp.push(entry(k, true));
                        }
                    }
                }
                (0..active)
                    .map(|i| {
                        let idx = entries.get(i).map_or(i, |&e| e as usize);
                        temp.get(idx).copied().flatten()
                    })
                    .collect::<Vec<_>>()
            };
        let m = &h.ref_pic_lists_modification;
        let e0: &[u32] = if m.ref_pic_list_modification_flag_l0 {
            &m.list_entry_l0
        } else {
            &[]
        };
        let mut out = HevcRefPicLists {
            list0: build(
                &rps.st_curr_before,
                &rps.st_curr_after,
                h.num_ref_idx_l0_active_minus1 as usize + 1,
                e0,
            ),
            list1: Vec::new(),
        };
        if h.slice_type == HevcSliceType::B {
            let e1: &[u32] = if m.ref_pic_list_modification_flag_l1 {
                &m.list_entry_l1
            } else {
                &[]
            };
            out.list1 = build(
                &rps.st_curr_after,
                &rps.st_curr_before,
                h.num_ref_idx_l1_active_minus1 as usize + 1,
                e1,
            );
        }
        Ok(out)
    }

    /// Finish the current picture: it is marked as a short-term
    /// reference (§8.1.3 step 4).
    pub fn finish_picture(&mut self) -> Result<HevcFinishedPicture, BitstreamError> {
        let p = self
            .pending
            .take()
            .ok_or_else(|| BitstreamError::invalid("no picture in progress"))?;
        // Bound the DPB against hostile RPS signalling: Table A.8's
        // largest DPB is 16 pictures.
        let mut released = Vec::new();
        while self.pics.len() >= 16 {
            released.push(self.pics.remove(0).key);
        }
        if p.referenceable {
            self.pics.push(HevcRefPicture {
                key: p.current.key,
                poc: p.current.poc,
                marking: HevcMarking::ShortTerm,
                temporal_id: p.temporal_id,
            });
        }
        Ok(HevcFinishedPicture {
            key: p.current.key,
            poc: p.current.poc,
            stored: p.referenceable,
            released,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hevc::HevcShortTermRps;
    use crate::hevc::slice::{LongTermRef, RefPicListsModification};

    fn sps() -> HevcSps {
        HevcSps {
            log2_max_pic_order_cnt_lsb_minus4: 0,
            sps_max_dec_pic_buffering_minus1: 4,
            ..HevcSps::default()
        }
    }

    fn pic(t: u8, lsb: u32, ty: HevcSliceType, s0: &[i32], s1: &[i32]) -> SliceSegmentHeader {
        SliceSegmentHeader {
            nal_unit_type: t,
            first_slice_segment_in_pic_flag: true,
            slice_type: ty,
            slice_pic_order_cnt_lsb: lsb,
            pic_output_flag: true,
            short_term_rps: HevcShortTermRps {
                delta_poc_s0: s0.to_vec(),
                used_by_curr_pic_s0: vec![true; s0.len()],
                delta_poc_s1: s1.to_vec(),
                used_by_curr_pic_s1: vec![true; s1.len()],
                ..HevcShortTermRps::default()
            },
            num_ref_idx_l0_active_minus1: 1,
            num_ref_idx_l1_active_minus1: 1,
            ..SliceSegmentHeader::default()
        }
    }

    fn pocs(l: &[Option<HevcListEntry>]) -> Vec<(i32, bool)> {
        l.iter()
            .map(|e| (e.unwrap().poc, e.unwrap().long_term))
            .collect()
    }

    #[test]
    fn rps_marking_and_list_construction() {
        let sps = sps();
        let mut d = HevcDpb::new();
        d.begin_picture(&sps, &pic(19, 0, HevcSliceType::I, &[], &[]))
            .unwrap();
        d.finish_picture().unwrap();
        d.begin_picture(&sps, &pic(1, 8, HevcSliceType::P, &[-8], &[]))
            .unwrap();
        d.finish_picture().unwrap();
        // B at POC 4 between 0 and 8.
        let h = pic(1, 4, HevcSliceType::B, &[-4], &[4]);
        let cur = d.begin_picture(&sps, &h).unwrap();
        assert_eq!(cur.poc, 4);
        let l = d.ref_pic_lists(&h).unwrap();
        assert_eq!(pocs(&l.list0), [(0, false), (8, false)]);
        assert_eq!(pocs(&l.list1), [(8, false), (0, false)]);
        // More active entries than NumPicTotalCurr cycle the temp list.
        let mut h3 = h.clone();
        h3.num_ref_idx_l0_active_minus1 = 2;
        assert_eq!(
            pocs(&d.ref_pic_lists(&h3).unwrap().list0),
            [(0, false), (8, false), (0, false)]
        );
        // list_entry_l0 picks from RefPicListTemp0.
        h3.ref_pic_lists_modification = RefPicListsModification {
            ref_pic_list_modification_flag_l0: true,
            list_entry_l0: vec![1, 1, 0],
            ..RefPicListsModification::default()
        };
        assert_eq!(
            pocs(&d.ref_pic_lists(&h3).unwrap().list0),
            [(8, false), (8, false), (0, false)]
        );
        d.finish_picture().unwrap();

        // POC 12 keeps POC 8 short-term and POC 0 as long-term (lsb
        // match, MSB absent); POC 4 leaves the RPS.
        let mut h = pic(1, 12, HevcSliceType::P, &[-4], &[]);
        h.long_term_refs = vec![LongTermRef {
            poc_lsb_lt: 0,
            used_by_curr_pic_lt: true,
            ..LongTermRef::default()
        }];
        let cur = d.begin_picture(&sps, &h).unwrap();
        assert_eq!(cur.poc, 12);
        assert_eq!(cur.released.len(), 1, "POC 4 is no longer referenced");
        assert_eq!(d.references().count(), 2);
        let lt = d.references().find(|p| p.poc == 0).unwrap();
        assert_eq!(lt.marking, HevcMarking::LongTerm);
        let l = d.ref_pic_lists(&h).unwrap();
        assert_eq!(pocs(&l.list0), [(8, false), (0, true)]);
    }

    #[test]
    fn cra_after_eos_skips_its_rasl_pictures() {
        let sps = sps();
        let mut d = HevcDpb::new();
        d.end_of_sequence();
        let cra = d
            .begin_picture(&sps, &pic(21, 8, HevcSliceType::I, &[], &[]))
            .unwrap();
        assert!(cra.no_rasl_output_flag);
        assert_eq!(
            cra.poc, 8,
            "PicOrderCntMsb is 0 at an IRAP with NoRaslOutputFlag"
        );
        d.finish_picture().unwrap();
        let rasl = d
            .begin_picture(&sps, &pic(9, 6, HevcSliceType::B, &[-2], &[2]))
            .unwrap();
        assert!(rasl.skip);
        let radl = d
            .begin_picture(&sps, &pic(7, 7, HevcSliceType::P, &[], &[1]))
            .unwrap();
        assert!(!radl.skip);
        assert_eq!(radl.rps.st_curr_after, [Some(cra.key)]);
    }
}
