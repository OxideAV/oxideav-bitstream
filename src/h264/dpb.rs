//! H.264 reference picture management: picture numbers (§8.2.4.1),
//! reference list initialisation for P / SP / B slices in frames and
//! fields (§8.2.4.2) and their modification (§8.2.4.3), decoded
//! reference picture marking — IDR, sliding window and
//! `memory_management_control_operation` 1..=6 (§8.2.5) — and the
//! decoding process for gaps in `frame_num` (§8.2.5.2), driven together
//! with the picture order count (§8.2.1).
//!
//! The model is the frame store: every [`FrameStore`] holds one frame,
//! one complementary field pair or one non-paired field, each field
//! carrying its own marking. A store is named by a `key` this module
//! hands out; a hardware bridge maps keys to surfaces (both fields of a
//! pair share the store, hence the surface).
//!
//! One coded picture is handled as:
//!
//! 1. [`Dpb::begin_picture`] with the picture's first slice header —
//!    gaps in `frame_num`, field pairing, picture order count;
//! 2. [`Dpb::ref_pic_lists`] for each P / SP / B slice;
//! 3. [`Dpb::finish_picture`] once all slices are decoded — marking, the
//!    picture joins the DPB, stores no longer used for reference leave.

use super::H264Sps;
use super::poc::{PictureStructure, Poc, PocState};
use super::slice::{MmcoOp, RefPicListModificationOp, SliceHeader, SliceType};
use crate::BitstreamError;

/// Marking of one field (§8.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Marking {
    #[default]
    Unused,
    ShortTerm,
    LongTerm,
}

/// Field parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Parity {
    Top,
    Bottom,
}

impl Parity {
    fn index(self) -> usize {
        match self {
            Parity::Top => 0,
            Parity::Bottom => 1,
        }
    }

    fn other(self) -> Parity {
        match self {
            Parity::Top => Parity::Bottom,
            Parity::Bottom => Parity::Top,
        }
    }

    fn of(structure: PictureStructure) -> Option<Parity> {
        match structure {
            PictureStructure::Frame => None,
            PictureStructure::TopField => Some(Parity::Top),
            PictureStructure::BottomField => Some(Parity::Bottom),
        }
    }
}

/// One field of a frame store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FieldState {
    /// The field has been decoded (or inferred, for a "non-existing" frame).
    pub decoded: bool,
    pub marking: Marking,
    /// `TopFieldOrderCnt` / `BottomFieldOrderCnt`.
    pub poc: i32,
    /// `LongTermFrameIdx` while `marking == LongTerm`.
    pub long_term_frame_idx: u32,
}

impl FieldState {
    fn is_ref(&self) -> bool {
        self.decoded && self.marking != Marking::Unused
    }

    fn is(&self, m: Marking) -> bool {
        self.decoded && self.marking == m
    }
}

/// A decoded frame, complementary field pair or non-paired field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameStore {
    /// Handle given out by [`Dpb::begin_picture`].
    pub key: u32,
    /// `FrameNum` (0 after `memory_management_control_operation` 5).
    pub frame_num: u32,
    /// `[top, bottom]`.
    pub fields: [FieldState; 2],
    /// Decoded as a coded frame (both fields at once).
    pub coded_frame: bool,
    /// A "non-existing" frame inferred for a gap in `frame_num` (§8.2.5.2).
    pub non_existing: bool,
}

impl FrameStore {
    pub fn top(&self) -> &FieldState {
        &self.fields[0]
    }

    pub fn bottom(&self) -> &FieldState {
        &self.fields[1]
    }

    pub fn field(&self, p: Parity) -> &FieldState {
        &self.fields[p.index()]
    }

    /// At least one field is used for reference.
    pub fn is_reference(&self) -> bool {
        self.fields.iter().any(FieldState::is_ref)
    }

    fn any(&self, m: Marking) -> bool {
        self.fields.iter().any(|f| f.is(m))
    }

    fn both(&self, m: Marking) -> bool {
        self.fields.iter().all(|f| f.is(m))
    }

    /// Both fields are short-term (a short-term frame or complementary
    /// reference field pair).
    pub fn is_short_term_frame(&self) -> bool {
        self.both(Marking::ShortTerm)
    }

    /// Both fields are long-term.
    pub fn is_long_term_frame(&self) -> bool {
        self.both(Marking::LongTerm)
    }

    /// At least one field is long-term.
    pub fn has_long_term(&self) -> bool {
        self.any(Marking::LongTerm)
    }

    /// `LongTermFrameIdx` of the long-term field(s), when any.
    pub fn long_term_frame_idx(&self) -> Option<u32> {
        self.fields
            .iter()
            .find(|f| f.is(Marking::LongTerm))
            .map(|f| f.long_term_frame_idx)
    }

    /// `PicOrderCnt()` of the store (eq. 8-1): the minimum over its
    /// decoded fields.
    pub fn pic_order_cnt(&self) -> i32 {
        match (self.fields[0].decoded, self.fields[1].decoded) {
            (true, true) => self.fields[0].poc.min(self.fields[1].poc),
            (true, false) => self.fields[0].poc,
            (false, true) => self.fields[1].poc,
            (false, false) => 0,
        }
    }

    /// `FrameNumWrap` (eq. 8-27) relative to the current `frame_num`.
    pub fn frame_num_wrap(&self, current_frame_num: u32, max_frame_num: u32) -> i64 {
        if self.frame_num > current_frame_num {
            i64::from(self.frame_num) - i64::from(max_frame_num)
        } else {
            i64::from(self.frame_num)
        }
    }
}

/// One reference picture list entry: a frame (or complementary pair)
/// when `parity` is `None`, one field otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefPicture {
    pub key: u32,
    pub parity: Option<Parity>,
}

/// RefPicList0 / RefPicList1 of a slice; `None` entries are "no
/// reference picture". Each list has `num_ref_idx_lX_active_minus1 + 1`
/// entries (list 1 is empty outside B slices, both are empty for I / SI).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct RefPicLists {
    pub list0: Vec<Option<RefPicture>>,
    pub list1: Vec<Option<RefPicture>>,
}

/// The picture being decoded, as [`Dpb::begin_picture`] set it up.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CurrentPicture {
    /// Store key. The second field of a complementary field pair reuses
    /// its first field's key.
    pub key: u32,
    pub structure: PictureStructure,
    /// Counts derived by §8.2.1 (before any MMCO 5 adjustment, which is
    /// what the picture's own decoding uses).
    pub poc: Poc,
    pub frame_num: u32,
    pub idr: bool,
    /// `nal_ref_idc != 0`.
    pub reference: bool,
    /// Second field (in decoding order) of a complementary field pair.
    pub second_field: bool,
    /// Keys of the "non-existing" frames §8.2.5.2 inserted ahead of this
    /// picture (they hold no samples; a bridge may give them a dummy
    /// surface or none).
    pub non_existing: Vec<u32>,
    /// Key of the previous picture when it was a non-reference first
    /// field that this picture does not pair with: nothing holds it any
    /// more.
    pub abandoned_first_field: Option<u32>,
}

/// What [`Dpb::finish_picture`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FinishedPicture {
    pub key: u32,
    /// The picture is now held for reference.
    pub stored: bool,
    /// The picture carried `memory_management_control_operation` 5.
    pub mmco5: bool,
    /// `PicOrderCnt( CurrPic )` after the MMCO 5 adjustment (equal to
    /// the derived count otherwise): the value output ordering uses.
    pub pic_order_cnt: i32,
    /// The counts the picture keeps in the DPB.
    pub poc: Poc,
    /// The picture is a first field whose second field may follow into
    /// the same store (keep its surface even when it is not a reference).
    pub awaiting_second_field: bool,
    /// Stores that left the DPB (no field used for reference any more),
    /// non-existing frames included.
    pub released: Vec<u32>,
}

#[derive(Debug, Clone)]
struct InProgress {
    current: CurrentPicture,
    header: SliceHeader,
    max_frame_num: u32,
}

#[derive(Debug, Clone, Copy)]
struct LastField {
    key: u32,
    parity: Parity,
    frame_num: u32,
    reference: bool,
    idr: bool,
}

/// `Max( max_num_ref_frames, 1 )`, bounded by the largest DPB of
/// Table A-1 (16 frames).
fn ref_cap(sps: &H264Sps) -> usize {
    sps.max_num_ref_frames.clamp(1, 16) as usize
}

/// Reference picture state of one H.264 stream. See the module docs.
#[derive(Debug, Clone, Default)]
pub struct Dpb {
    stores: Vec<FrameStore>,
    /// `MaxLongTermFrameIdx`; `None` is "no long-term frame indices".
    max_long_term_frame_idx: Option<u32>,
    poc: PocState,
    prev_ref_frame_num: u32,
    next_key: u32,
    pending: Option<InProgress>,
    last_field: Option<LastField>,
    /// Keys released by gap filling before the current picture.
    released_early: Vec<u32>,
}

impl Dpb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every picture (stream restart / seek). Keys keep counting.
    pub fn clear(&mut self) {
        let next = self.next_key;
        *self = Dpb {
            next_key: next,
            ..Dpb::default()
        };
    }

    /// The frame stores holding at least one reference field, in
    /// insertion order — `ReferenceFrames[]` of a picture-parameter
    /// buffer.
    pub fn references(&self) -> impl Iterator<Item = &FrameStore> {
        self.stores.iter().filter(|s| s.is_reference())
    }

    /// The store named `key`, if it is still in the DPB.
    pub fn store(&self, key: u32) -> Option<&FrameStore> {
        self.stores.iter().find(|s| s.key == key)
    }

    /// `MaxLongTermFrameIdx` (`None`: no long-term frame indices).
    pub fn max_long_term_frame_idx(&self) -> Option<u32> {
        self.max_long_term_frame_idx
    }

    /// The picture order count state.
    pub fn poc_state(&self) -> &PocState {
        &self.poc
    }

    /// The picture in progress.
    pub fn current(&self) -> Option<&CurrentPicture> {
        self.pending.as_ref().map(|p| &p.current)
    }

    fn new_key(&mut self) -> u32 {
        let k = self.next_key;
        self.next_key = self.next_key.wrapping_add(1);
        k
    }

    /// Start the picture whose first slice header (primary coded
    /// picture, `redundant_pic_cnt == 0`) is `h`.
    ///
    /// A `frame_num` gap is filled with "non-existing" frames when the
    /// SPS allows gaps and is an error otherwise (an unintentional loss,
    /// §8.2.5.2 NOTE 2).
    pub fn begin_picture(
        &mut self,
        sps: &H264Sps,
        h: &SliceHeader,
    ) -> Result<CurrentPicture, BitstreamError> {
        if self.pending.is_some() {
            return Err(BitstreamError::invalid(
                "begin_picture while a picture is in progress",
            ));
        }
        let idr = h.is_idr();
        let reference = h.nal_ref_idc != 0;
        let structure = PictureStructure::of(h);
        let max_frame_num = sps.max_frame_num();

        // Field pairing (§3.36 / §3.37): the previous picture was a first
        // field of opposite parity with the same frame_num.
        let pair = match (self.last_field, Parity::of(structure)) {
            (Some(first), Some(parity))
                if parity == first.parity.other() && h.frame_num == first.frame_num =>
            {
                let ref_pair = first.reference && reference && !idr && !h.has_mmco5();
                let non_ref_pair = !first.reference && !reference;
                // A first IDR field pairs only with a reference field.
                (ref_pair || (non_ref_pair && !first.idr)).then_some(first)
            }
            _ => None,
        };
        let abandoned_first_field = match (self.last_field, pair) {
            (Some(first), None) if !first.reference => Some(first.key),
            _ => None,
        };
        self.last_field = None;

        // §8.2.5.2 gaps in frame_num.
        let mut non_existing = Vec::new();
        if idr {
            self.prev_ref_frame_num = 0;
        } else if pair.is_none()
            && h.frame_num != self.prev_ref_frame_num
            && h.frame_num != (self.prev_ref_frame_num + 1) % max_frame_num
        {
            if !sps.gaps_in_frame_num_value_allowed_flag {
                return Err(BitstreamError::invalid(format!(
                    "frame_num {} after {} without gaps_in_frame_num_value_allowed_flag",
                    h.frame_num, self.prev_ref_frame_num
                )));
            }
            let mut unused = (self.prev_ref_frame_num + 1) % max_frame_num;
            let gap = (h.frame_num + max_frame_num - unused) % max_frame_num;
            let cap = ref_cap(sps) as u32;
            if gap > cap {
                // Only the last `cap` non-existing frames can survive the
                // sliding window, and inserting them flushes every older
                // short-term reference: skip straight to them (the POC
                // state still steps through every skipped frame_num).
                for st in &mut self.stores {
                    for f in &mut st.fields {
                        if f.marking == Marking::ShortTerm {
                            f.marking = Marking::Unused;
                        }
                    }
                }
                for _ in 0..gap - cap {
                    self.poc.skip_non_existing(sps, unused);
                    unused = (unused + 1) % max_frame_num;
                }
            }
            while unused != h.frame_num {
                self.sliding_window(sps, unused, max_frame_num, None);
                let poc = self.poc.derive_non_existing(sps, unused)?;
                self.poc.finish_non_existing(unused, &poc);
                let key = self.new_key();
                let field = FieldState {
                    decoded: true,
                    marking: Marking::ShortTerm,
                    poc: 0,
                    long_term_frame_idx: 0,
                };
                self.stores.push(FrameStore {
                    key,
                    frame_num: unused,
                    fields: [
                        FieldState {
                            poc: poc.top_field_order_cnt,
                            ..field
                        },
                        FieldState {
                            poc: poc.bottom_field_order_cnt,
                            ..field
                        },
                    ],
                    coded_frame: true,
                    non_existing: true,
                });
                non_existing.push(key);
                self.prev_ref_frame_num = unused;
                unused = (unused + 1) % max_frame_num;
            }
            let released = self.evict_unused();
            self.released_early.extend(released);
        }

        let poc = self.poc.derive(sps, h)?;
        let key = match pair {
            Some(first) => first.key,
            None => self.new_key(),
        };
        let current = CurrentPicture {
            key,
            structure,
            poc,
            frame_num: h.frame_num,
            idr,
            reference,
            second_field: pair.is_some(),
            non_existing,
            abandoned_first_field,
        };
        self.pending = Some(InProgress {
            current: current.clone(),
            header: h.clone(),
            max_frame_num,
        });
        Ok(current)
    }

    // ───────────────────────── §8.2.4.1 picture numbers ─────────────────

    /// PicNum of field `p` of `s` seen from a current field of parity
    /// `cur` (eq. 8-30 / 8-31), or of frame `s` (eq. 8-28).
    fn pic_num(s: &FrameStore, p: Option<Parity>, cur: Option<Parity>, fnum: u32, max: u32) -> i64 {
        let wrap = s.frame_num_wrap(fnum, max);
        match (p, cur) {
            (Some(p), Some(c)) if p == c => 2 * wrap + 1,
            (Some(_), Some(_)) => 2 * wrap,
            _ => wrap,
        }
    }

    /// LongTermPicNum (eq. 8-29 / 8-32 / 8-33).
    fn long_term_pic_num(s: &FrameStore, p: Option<Parity>, cur: Option<Parity>) -> i64 {
        match p {
            Some(p) => {
                let idx = i64::from(s.field(p).long_term_frame_idx);
                if Some(p) == cur { 2 * idx + 1 } else { 2 * idx }
            }
            None => i64::from(s.long_term_frame_idx().unwrap_or(0)),
        }
    }

    /// Is the entry a short-term reference picture (frame: both fields)?
    fn entry_is(s: &FrameStore, p: Option<Parity>, m: Marking) -> bool {
        match p {
            Some(p) => s.field(p).is(m),
            None => s.both(m),
        }
    }

    // ───────────────────────── §8.2.4.2 initialisation ──────────────────

    /// §8.2.4.2.5: alternate parities over an ordered list of stores.
    fn interleave(&self, frames: &[u32], cur: Parity, class: Marking) -> Vec<RefPicture> {
        let has = |key: u32, p: Parity| self.store(key).is_some_and(|s| s.field(p).is(class));
        let mut out = Vec::new();
        let mut next = [0usize, 0usize];
        let mut want = cur;
        loop {
            let find = |from: usize, p: Parity| (from..frames.len()).find(|&i| has(frames[i], p));
            let w = want.index();
            match find(next[w], want) {
                Some(i) => {
                    out.push(RefPicture {
                        key: frames[i],
                        parity: Some(want),
                    });
                    next[w] = i + 1;
                    let o = want.other();
                    if find(next[o.index()], o).is_some() {
                        want = o;
                    }
                }
                None => {
                    let o = want.other();
                    if find(next[o.index()], o).is_some() {
                        want = o;
                    } else {
                        break;
                    }
                }
            }
        }
        out
    }

    fn init_lists(
        &self,
        sps: &H264Sps,
        h: &SliceHeader,
        cur: &CurrentPicture,
        max_frame_num: u32,
    ) -> (Vec<RefPicture>, Vec<RefPicture>) {
        let fnum = cur.frame_num;
        let parity = Parity::of(cur.structure);
        let refs: Vec<&FrameStore> = self.stores.iter().filter(|s| s.is_reference()).collect();
        // POC type 0 "non-existing" frames are not in B lists.
        let b_usable = |s: &&FrameStore| !(s.non_existing && sps.pic_order_cnt_type == 0);
        match (h.slice_type, parity) {
            (SliceType::B, None) => {
                let cur_poc = cur.poc.pic_order_cnt;
                let mut st: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.is_short_term_frame())
                    .filter(b_usable)
                    .collect();
                st.sort_by_key(|s| s.pic_order_cnt());
                let before: Vec<&FrameStore> = st
                    .iter()
                    .copied()
                    .filter(|s| s.pic_order_cnt() < cur_poc)
                    .collect();
                let after: Vec<&FrameStore> = st
                    .iter()
                    .copied()
                    .filter(|s| s.pic_order_cnt() > cur_poc)
                    .collect();
                let equal: Vec<&FrameStore> = st
                    .iter()
                    .copied()
                    .filter(|s| s.pic_order_cnt() == cur_poc)
                    .collect();
                let mut lt: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.is_long_term_frame())
                    .collect();
                lt.sort_by_key(|s| s.long_term_frame_idx());
                let frame = |s: &&FrameStore| RefPicture {
                    key: s.key,
                    parity: None,
                };
                // L0: POC < cur descending, then the rest ascending.
                let mut l0: Vec<RefPicture> = before.iter().rev().map(frame).collect();
                l0.extend(equal.iter().map(frame));
                l0.extend(after.iter().map(frame));
                l0.extend(lt.iter().map(frame));
                // L1: POC > cur ascending, then the rest descending.
                let mut l1: Vec<RefPicture> = after.iter().map(frame).collect();
                l1.extend(equal.iter().rev().map(frame));
                l1.extend(before.iter().rev().map(frame));
                l1.extend(lt.iter().map(frame));
                if l1.len() > 1 && l1 == l0 {
                    l1.swap(0, 1);
                }
                (l0, l1)
            }
            (SliceType::B, Some(p)) => {
                let cur_poc = cur.poc.pic_order_cnt;
                let mut st: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.any(Marking::ShortTerm))
                    .filter(b_usable)
                    .collect();
                st.sort_by_key(|s| s.pic_order_cnt());
                let le: Vec<u32> = st
                    .iter()
                    .filter(|s| s.pic_order_cnt() <= cur_poc)
                    .map(|s| s.key)
                    .collect();
                let gt: Vec<u32> = st
                    .iter()
                    .filter(|s| s.pic_order_cnt() > cur_poc)
                    .map(|s| s.key)
                    .collect();
                let mut f0: Vec<u32> = le.iter().rev().copied().collect();
                f0.extend(gt.iter().copied());
                let mut f1: Vec<u32> = gt.clone();
                f1.extend(le.iter().rev().copied());
                let lt = self.long_term_frames_by_idx(&refs);
                let mut l0 = self.interleave(&f0, p, Marking::ShortTerm);
                l0.extend(self.interleave(&lt, p, Marking::LongTerm));
                let mut l1 = self.interleave(&f1, p, Marking::ShortTerm);
                l1.extend(self.interleave(&lt, p, Marking::LongTerm));
                if l1.len() > 1 && l1 == l0 {
                    l1.swap(0, 1);
                }
                (l0, l1)
            }
            (_, None) => {
                let mut st: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.is_short_term_frame())
                    .collect();
                st.sort_by_key(|s| std::cmp::Reverse(s.frame_num_wrap(fnum, max_frame_num)));
                let mut lt: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.is_long_term_frame())
                    .collect();
                lt.sort_by_key(|s| s.long_term_frame_idx());
                let l0 = st
                    .iter()
                    .chain(lt.iter())
                    .map(|s| RefPicture {
                        key: s.key,
                        parity: None,
                    })
                    .collect();
                (l0, Vec::new())
            }
            (_, Some(p)) => {
                let mut st: Vec<&FrameStore> = refs
                    .iter()
                    .copied()
                    .filter(|s| s.any(Marking::ShortTerm))
                    .collect();
                st.sort_by_key(|s| std::cmp::Reverse(s.frame_num_wrap(fnum, max_frame_num)));
                let f0: Vec<u32> = st.iter().map(|s| s.key).collect();
                let lt = self.long_term_frames_by_idx(&refs);
                let mut l0 = self.interleave(&f0, p, Marking::ShortTerm);
                l0.extend(self.interleave(&lt, p, Marking::LongTerm));
                (l0, Vec::new())
            }
        }
    }

    fn long_term_frames_by_idx(&self, refs: &[&FrameStore]) -> Vec<u32> {
        let mut lt: Vec<&FrameStore> = refs.iter().copied().filter(|s| s.has_long_term()).collect();
        lt.sort_by_key(|s| s.long_term_frame_idx());
        lt.iter().map(|s| s.key).collect()
    }

    /// The initial lists (§8.2.4.2) of a slice of the current picture,
    /// before modification and before truncation to the active sizes.
    pub fn initial_ref_pic_lists(
        &self,
        sps: &H264Sps,
        h: &SliceHeader,
    ) -> Result<(Vec<RefPicture>, Vec<RefPicture>), BitstreamError> {
        let p = self
            .pending
            .as_ref()
            .ok_or_else(|| BitstreamError::invalid("no picture in progress"))?;
        if !h.slice_type.has_list0() {
            return Ok((Vec::new(), Vec::new()));
        }
        Ok(self.init_lists(sps, h, &p.current, p.max_frame_num))
    }

    /// RefPicList0 / RefPicList1 of slice `h` of the current picture:
    /// initialisation (§8.2.4.2), truncation / padding to the active
    /// sizes, then the slice's modification commands (§8.2.4.3).
    pub fn ref_pic_lists(
        &self,
        sps: &H264Sps,
        h: &SliceHeader,
    ) -> Result<RefPicLists, BitstreamError> {
        let p = self
            .pending
            .as_ref()
            .ok_or_else(|| BitstreamError::invalid("no picture in progress"))?;
        if !h.slice_type.has_list0() {
            return Ok(RefPicLists::default());
        }
        let (l0, l1) = self.init_lists(sps, h, &p.current, p.max_frame_num);
        let mut out = RefPicLists {
            list0: self.modify(
                l0,
                &h.ref_pic_list_modification.modifications_l0,
                h.num_ref_idx_l0_active_minus1,
                &p.current,
                p.max_frame_num,
            ),
            list1: Vec::new(),
        };
        if h.slice_type.has_list1() {
            out.list1 = self.modify(
                l1,
                &h.ref_pic_list_modification.modifications_l1,
                h.num_ref_idx_l1_active_minus1,
                &p.current,
                p.max_frame_num,
            );
        }
        Ok(out)
    }

    // ───────────────────────── §8.2.4.3 modification ────────────────────

    fn modify(
        &self,
        init: Vec<RefPicture>,
        ops: &[RefPicListModificationOp],
        active_minus1: u32,
        cur: &CurrentPicture,
        max_frame_num: u32,
    ) -> Vec<Option<RefPicture>> {
        let n = active_minus1 as usize + 1;
        // §8.2.4.2: truncate / pad, then one spare slot for the shifts.
        let mut list: Vec<Option<RefPicture>> = init.into_iter().map(Some).take(n).collect();
        list.resize(n + 1, None);
        let parity = Parity::of(cur.structure);
        let field = parity.is_some();
        let curr_pic_num = if field {
            2 * i64::from(cur.frame_num) + 1
        } else {
            i64::from(cur.frame_num)
        };
        let max_pic_num = if field {
            2 * i64::from(max_frame_num)
        } else {
            i64::from(max_frame_num)
        };
        let fnum = cur.frame_num;
        let candidates: &[Option<Parity>] = if field {
            &[Some(Parity::Top), Some(Parity::Bottom)]
        } else {
            &[None]
        };
        // The number an entry is matched on: PicNum for short-term
        // commands, LongTermPicNum for long-term ones.
        let number = |s: &FrameStore, c: Option<Parity>, class: Marking| -> Option<i64> {
            if !Self::entry_is(s, c, class) {
                return None;
            }
            Some(match class {
                Marking::LongTerm => Self::long_term_pic_num(s, c, parity),
                _ => Self::pic_num(s, c, parity, fnum, max_frame_num),
            })
        };
        let mut pred = curr_pic_num;
        let mut idx = 0usize;
        for op in ops {
            if idx >= n {
                break;
            }
            let (class, want) = match *op {
                RefPicListModificationOp::SubtractPicNum(d)
                | RefPicListModificationOp::AddPicNum(d) => {
                    let d = i64::from(d) + 1;
                    // eq. 8-34 / 8-35
                    let no_wrap = if matches!(op, RefPicListModificationOp::SubtractPicNum(_)) {
                        if pred - d < 0 {
                            pred - d + max_pic_num
                        } else {
                            pred - d
                        }
                    } else if pred + d >= max_pic_num {
                        pred + d - max_pic_num
                    } else {
                        pred + d
                    };
                    pred = no_wrap;
                    // eq. 8-36
                    let pic_num = if no_wrap > curr_pic_num {
                        no_wrap - max_pic_num
                    } else {
                        no_wrap
                    };
                    (Marking::ShortTerm, pic_num)
                }
                RefPicListModificationOp::LongTermPicNum(num) => {
                    (Marking::LongTerm, i64::from(num))
                }
            };
            let target = self.stores.iter().find_map(|s| {
                candidates
                    .iter()
                    .find(|&&c| number(s, c, class) == Some(want))
                    .map(|&c| RefPicture {
                        key: s.key,
                        parity: c,
                    })
            });
            // PicNumF / LongTermPicNumF( e ) != the inserted number.
            let keep = |e: &Option<RefPicture>| -> bool {
                match e.and_then(|e| self.store(e.key).map(|s| (s, e.parity))) {
                    Some((s, c)) => number(s, c, class) != Some(want),
                    None => true,
                }
            };
            // eq. 8-37 / 8-38
            for c in (idx + 1..=n).rev() {
                list[c] = list[c - 1];
            }
            list[idx] = target;
            idx += 1;
            let mut nidx = idx;
            for c in idx..=n {
                if keep(&list[c]) {
                    list[nidx] = list[c];
                    nidx += 1;
                }
            }
        }
        list.truncate(n);
        list
    }

    // ───────────────────────── §8.2.5 marking ───────────────────────────

    /// §8.2.5.3 sliding window, for a picture of `frame_num` (the current
    /// picture, or a non-existing frame). `second_field_of` is the store
    /// key when the current picture is the second field of a reference
    /// pair.
    fn sliding_window(
        &mut self,
        sps: &H264Sps,
        frame_num: u32,
        max_frame_num: u32,
        second_field_of: Option<u32>,
    ) {
        if let Some(key) = second_field_of
            && self.store(key).is_some_and(|s| s.any(Marking::ShortTerm))
        {
            return;
        }
        let cap = ref_cap(sps);
        loop {
            let num_short = self
                .stores
                .iter()
                .filter(|s| s.any(Marking::ShortTerm))
                .count();
            let num_long = self
                .stores
                .iter()
                .filter(|s| s.any(Marking::LongTerm))
                .count();
            if num_short + num_long < cap || num_short == 0 {
                break;
            }
            let victim = self
                .stores
                .iter_mut()
                .filter(|s| s.any(Marking::ShortTerm))
                .min_by_key(|s| s.frame_num_wrap(frame_num, max_frame_num));
            if let Some(s) = victim {
                for f in &mut s.fields {
                    if f.marking == Marking::ShortTerm {
                        f.marking = Marking::Unused;
                    }
                }
            }
        }
    }

    /// Safety net for non-conforming streams: §8.2.5.1 requires at most
    /// `Max( max_num_ref_frames, 1 )` reference frames after marking.
    /// Drop the oldest short-term, then the highest-index long-term
    /// stores until that holds, so hostile marking cannot grow the DPB.
    fn enforce_capacity(&mut self, sps: &H264Sps, fnum: u32, max_frame_num: u32) {
        let cap = ref_cap(sps);
        while self.stores.iter().filter(|s| s.is_reference()).count() > cap {
            let victim = self
                .stores
                .iter()
                .enumerate()
                .filter(|(_, s)| s.is_reference() && !s.has_long_term())
                .min_by_key(|(_, s)| s.frame_num_wrap(fnum, max_frame_num))
                .or_else(|| {
                    self.stores
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| s.is_reference())
                        .max_by_key(|(_, s)| s.long_term_frame_idx())
                })
                .map(|(i, _)| i);
            match victim {
                Some(i) => self.unmark(i, None),
                None => break,
            }
        }
    }

    /// Unmark the holder(s) of `LongTermFrameIdx == idx` (§8.2.5.4.3 /
    /// §8.2.5.4.6), sparing a field of the store `spare`.
    fn evict_long_term_idx(&mut self, idx: u32, spare: Option<u32>) {
        for s in &mut self.stores {
            if Some(s.key) == spare {
                continue;
            }
            let holds: Vec<usize> = (0..2)
                .filter(|&i| {
                    s.fields[i].is(Marking::LongTerm) && s.fields[i].long_term_frame_idx == idx
                })
                .collect();
            if holds.is_empty() {
                continue;
            }
            if s.both(Marking::LongTerm) {
                // A long-term frame or pair: both fields go.
                for f in &mut s.fields {
                    f.marking = Marking::Unused;
                }
            } else {
                for i in holds {
                    s.fields[i].marking = Marking::Unused;
                }
            }
        }
    }

    fn apply_mmco(
        &mut self,
        ops: &[MmcoOp],
        cur: &CurrentPicture,
        max_frame_num: u32,
        current_long: &mut Option<u32>,
    ) -> bool {
        let parity = Parity::of(cur.structure);
        let field = parity.is_some();
        let curr_pic_num = if field {
            2 * i64::from(cur.frame_num) + 1
        } else {
            i64::from(cur.frame_num)
        };
        let fnum = cur.frame_num;
        let mut mmco5 = false;
        for op in ops {
            match *op {
                MmcoOp::MarkShortTermUnused {
                    difference_of_pic_nums_minus1: d,
                } => {
                    let x = curr_pic_num - (i64::from(d) + 1);
                    if let Some((i, c)) = self.find(
                        |s, c| {
                            Self::entry_is(s, c, Marking::ShortTerm)
                                && Self::pic_num(s, c, parity, fnum, max_frame_num) == x
                        },
                        field,
                    ) {
                        self.unmark(i, c);
                    }
                }
                MmcoOp::MarkLongTermUnused {
                    long_term_pic_num: n,
                } => {
                    let n = i64::from(n);
                    if let Some((i, c)) = self.find(
                        |s, c| {
                            Self::entry_is(s, c, Marking::LongTerm)
                                && Self::long_term_pic_num(s, c, parity) == n
                        },
                        field,
                    ) {
                        self.unmark(i, c);
                    }
                }
                MmcoOp::AssignLongTerm {
                    difference_of_pic_nums_minus1: d,
                    long_term_frame_idx: idx,
                } => {
                    let x = curr_pic_num - (i64::from(d) + 1);
                    let target = self.find(
                        |s, c| {
                            Self::entry_is(s, c, Marking::ShortTerm)
                                && Self::pic_num(s, c, parity, fnum, max_frame_num) == x
                        },
                        field,
                    );
                    let spare = target.map(|(i, _)| self.stores[i].key);
                    self.evict_long_term_idx(idx, if field { spare } else { None });
                    // The eviction never touches the target (it is short-term).
                    if let Some((i, c)) = target {
                        let s = &mut self.stores[i];
                        let fields: Vec<usize> = match c {
                            Some(p) => vec![p.index()],
                            None => vec![0, 1],
                        };
                        for k in fields {
                            s.fields[k].marking = Marking::LongTerm;
                            s.fields[k].long_term_frame_idx = idx;
                        }
                    }
                }
                MmcoOp::SetMaxLongTermFrameIdx {
                    max_long_term_frame_idx_plus1: m,
                } => {
                    for s in &mut self.stores {
                        for f in &mut s.fields {
                            if f.marking == Marking::LongTerm
                                && (m == 0 || f.long_term_frame_idx > m - 1)
                            {
                                f.marking = Marking::Unused;
                            }
                        }
                    }
                    self.max_long_term_frame_idx = m.checked_sub(1);
                }
                MmcoOp::MarkAllUnused => {
                    for s in &mut self.stores {
                        for f in &mut s.fields {
                            f.marking = Marking::Unused;
                        }
                    }
                    self.max_long_term_frame_idx = None;
                    mmco5 = true;
                }
                MmcoOp::AssignCurrentLongTerm {
                    long_term_frame_idx: idx,
                } => {
                    let spare = (cur.second_field && field).then_some(cur.key);
                    self.evict_long_term_idx(idx, spare);
                    *current_long = Some(idx);
                }
            }
        }
        mmco5
    }

    /// Find a reference entry: a field (`field` = true) or a frame.
    fn find(
        &self,
        want: impl Fn(&FrameStore, Option<Parity>) -> bool,
        field: bool,
    ) -> Option<(usize, Option<Parity>)> {
        for (i, s) in self.stores.iter().enumerate() {
            if field {
                for p in [Parity::Top, Parity::Bottom] {
                    if want(s, Some(p)) {
                        return Some((i, Some(p)));
                    }
                }
            } else if want(s, None) {
                return Some((i, None));
            }
        }
        None
    }

    fn unmark(&mut self, i: usize, c: Option<Parity>) {
        let s = &mut self.stores[i];
        match c {
            Some(p) => s.fields[p.index()].marking = Marking::Unused,
            None => {
                for f in &mut s.fields {
                    f.marking = Marking::Unused;
                }
            }
        }
    }

    fn evict_unused(&mut self) -> Vec<u32> {
        let mut released = Vec::new();
        self.stores.retain(|s| {
            let keep = s.is_reference();
            if !keep {
                released.push(s.key);
            }
            keep
        });
        released
    }

    /// Finish the current picture: decoded reference picture marking
    /// (§8.2.5.1) for a reference picture, then the DPB update.
    pub fn finish_picture(&mut self, sps: &H264Sps) -> Result<FinishedPicture, BitstreamError> {
        let InProgress {
            current: cur,
            header: h,
            max_frame_num,
        } = self
            .pending
            .take()
            .ok_or_else(|| BitstreamError::invalid("no picture in progress"))?;
        let parity = Parity::of(cur.structure);
        let mut mmco5 = false;
        let mut current_long: Option<u32> = None;
        if cur.reference {
            let marking = h.dec_ref_pic_marking.clone().unwrap_or_default();
            if cur.idr {
                for s in &mut self.stores {
                    for f in &mut s.fields {
                        f.marking = Marking::Unused;
                    }
                }
                if marking.long_term_reference_flag {
                    current_long = Some(0);
                    self.max_long_term_frame_idx = Some(0);
                } else {
                    self.max_long_term_frame_idx = None;
                }
            } else if marking.adaptive_ref_pic_marking_mode_flag {
                mmco5 = self.apply_mmco(&marking.mmco, &cur, max_frame_num, &mut current_long);
            } else {
                let second = cur.second_field.then_some(cur.key);
                self.sliding_window(sps, cur.frame_num, max_frame_num, second);
            }
        }
        let poc = if mmco5 {
            cur.poc.after_mmco5(cur.structure)
        } else {
            cur.poc
        };
        self.poc.finish(sps, &h, &cur.poc, mmco5);
        if cur.reference {
            self.prev_ref_frame_num = if mmco5 { 0 } else { cur.frame_num };
        }

        // The picture's own fields.
        let field_state = FieldState {
            decoded: true,
            marking: match (cur.reference, current_long) {
                (false, _) => Marking::Unused,
                (true, Some(_)) => Marking::LongTerm,
                (true, None) => Marking::ShortTerm,
            },
            poc: 0,
            long_term_frame_idx: current_long.unwrap_or(0),
        };
        let mut fields = [FieldState::default(); 2];
        match parity {
            None => {
                fields[0] = FieldState {
                    poc: poc.top_field_order_cnt,
                    ..field_state
                };
                fields[1] = FieldState {
                    poc: poc.bottom_field_order_cnt,
                    ..field_state
                };
            }
            Some(Parity::Top) => {
                fields[0] = FieldState {
                    poc: poc.top_field_order_cnt,
                    ..field_state
                };
            }
            Some(Parity::Bottom) => {
                fields[1] = FieldState {
                    poc: poc.bottom_field_order_cnt,
                    ..field_state
                };
            }
        }
        let frame_num = if mmco5 { 0 } else { cur.frame_num };
        if cur.reference {
            match self.stores.iter_mut().find(|s| s.key == cur.key) {
                Some(s) if cur.second_field => {
                    let p = parity.expect("second field is a field");
                    s.fields[p.index()] = fields[p.index()];
                    // §8.2.5.4.6: the pair becomes long-term when both are.
                    if let Some(idx) = current_long
                        && s.fields[p.other().index()].is(Marking::LongTerm)
                    {
                        s.fields[p.other().index()].long_term_frame_idx = idx;
                    }
                }
                _ => self.stores.push(FrameStore {
                    key: cur.key,
                    frame_num,
                    fields,
                    coded_frame: parity.is_none(),
                    non_existing: false,
                }),
            }
        }
        let awaiting_second_field = parity.is_some() && !cur.second_field;
        if let (true, Some(p)) = (awaiting_second_field, parity) {
            self.last_field = Some(LastField {
                key: cur.key,
                parity: p,
                frame_num: cur.frame_num,
                reference: cur.reference,
                idr: cur.idr,
            });
        }
        self.enforce_capacity(sps, cur.frame_num, max_frame_num);
        let mut released = std::mem::take(&mut self.released_early);
        released.extend(self.evict_unused());
        let stored = self.store(cur.key).is_some();
        Ok(FinishedPicture {
            key: cur.key,
            stored,
            mmco5,
            pic_order_cnt: poc.pic_order_cnt,
            poc,
            awaiting_second_field,
            released,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h264::slice::{DecRefPicMarking, RefPicListModification};

    fn sps(log2_max_frame_num_minus4: u8, max_num_ref_frames: u32) -> H264Sps {
        H264Sps {
            log2_max_frame_num_minus4,
            log2_max_pic_order_cnt_lsb_minus4: 4,
            max_num_ref_frames,
            frame_mbs_only_flag: false,
            pic_width_in_mbs_minus1: 3,
            pic_height_in_map_units_minus1: 1,
            chroma_format_idc: 1,
            ..H264Sps::default()
        }
    }

    fn frame(key: u32, frame_num: u32, poc: i32, m: Marking, lt_idx: u32) -> FrameStore {
        let f = FieldState {
            decoded: true,
            marking: m,
            poc,
            long_term_frame_idx: lt_idx,
        };
        FrameStore {
            key,
            frame_num,
            fields: [f, FieldState { poc: poc + 1, ..f }],
            coded_frame: true,
            non_existing: false,
        }
    }

    fn header(slice_type: SliceType, frame_num: u32, poc_lsb: u32, nal_ref_idc: u8) -> SliceHeader {
        SliceHeader {
            nal_unit_type: 1,
            nal_ref_idc,
            slice_type,
            slice_type_raw: u32::from(slice_type.code()),
            frame_num,
            pic_order_cnt_lsb: poc_lsb,
            num_ref_idx_l0_active_minus1: 3,
            num_ref_idx_l1_active_minus1: 3,
            dec_ref_pic_marking: (nal_ref_idc != 0).then(DecRefPicMarking::default),
            ..SliceHeader::default()
        }
    }

    fn keys(l: &[Option<RefPicture>]) -> Vec<Option<u32>> {
        l.iter().map(|e| e.map(|e| e.key)).collect()
    }

    fn with_current(dpb: &mut Dpb, sps: &H264Sps, h: &SliceHeader) {
        dpb.pending = Some(InProgress {
            current: CurrentPicture {
                key: 99,
                structure: PictureStructure::of(h),
                poc: dpb.poc.derive(sps, h).unwrap(),
                frame_num: h.frame_num,
                idr: false,
                reference: h.nal_ref_idc != 0,
                second_field: false,
                non_existing: Vec::new(),
                abandoned_first_field: None,
            },
            header: h.clone(),
            max_frame_num: sps.max_frame_num(),
        });
    }

    #[test]
    fn p_frame_list_matches_the_8_2_4_2_1_example() {
        // PicNum 300, 302, 303 short-term; LongTermPicNum 0 and 3.
        let sps = sps(6, 8);
        let mut dpb = Dpb::new();
        dpb.stores = vec![
            frame(1, 300, 0, Marking::ShortTerm, 0),
            frame(2, 303, 0, Marking::ShortTerm, 0),
            frame(3, 10, 0, Marking::LongTerm, 3),
            frame(4, 302, 0, Marking::ShortTerm, 0),
            frame(5, 20, 0, Marking::LongTerm, 0),
        ];
        let mut h = header(SliceType::P, 304, 0, 1);
        h.num_ref_idx_l0_active_minus1 = 4;
        with_current(&mut dpb, &sps, &h);
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        assert_eq!(
            keys(&l.list0),
            [Some(2), Some(4), Some(1), Some(5), Some(3)]
        );
        assert!(l.list1.is_empty());
    }

    #[test]
    fn b_frame_lists_order_by_poc_and_swap_when_equal() {
        let sps = sps(4, 8);
        let mut dpb = Dpb::new();
        dpb.stores = vec![
            frame(1, 1, 10, Marking::ShortTerm, 0),
            frame(2, 2, 40, Marking::ShortTerm, 0),
            frame(3, 3, 20, Marking::ShortTerm, 0),
            frame(4, 4, 50, Marking::ShortTerm, 0),
            frame(5, 0, 0, Marking::LongTerm, 1),
        ];
        // Current POC 30 (frame: min(top, bottom) of lsb 30).
        let mut h = header(SliceType::B, 5, 30, 0);
        h.num_ref_idx_l0_active_minus1 = 4;
        h.num_ref_idx_l1_active_minus1 = 4;
        with_current(&mut dpb, &sps, &h);
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        assert_eq!(
            keys(&l.list0),
            [Some(3), Some(1), Some(2), Some(4), Some(5)]
        );
        assert_eq!(
            keys(&l.list1),
            [Some(2), Some(4), Some(3), Some(1), Some(5)]
        );

        // Only future references: L1 == L0 → first two entries swap.
        dpb.stores.retain(|s| s.key == 2 || s.key == 4);
        h.num_ref_idx_l0_active_minus1 = 1;
        h.num_ref_idx_l1_active_minus1 = 1;
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        assert_eq!(keys(&l.list0), [Some(2), Some(4)]);
        assert_eq!(keys(&l.list1), [Some(4), Some(2)]);
    }

    #[test]
    fn field_lists_alternate_parity_from_the_current_one() {
        let sps = sps(4, 8);
        let mut dpb = Dpb::new();
        let mut half = frame(2, 1, 4, Marking::ShortTerm, 0);
        half.fields[1].marking = Marking::Unused;
        dpb.stores = vec![half, frame(1, 2, 8, Marking::ShortTerm, 0)];
        let mut h = header(SliceType::P, 3, 12, 1);
        h.field_pic_flag = true;
        h.bottom_field_flag = true;
        h.num_ref_idx_l0_active_minus1 = 2;
        with_current(&mut dpb, &sps, &h);
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        let got: Vec<(u32, Parity)> = l
            .list0
            .iter()
            .map(|e| (e.unwrap().key, e.unwrap().parity.unwrap()))
            .collect();
        // FrameNumWrap order: fn 2 then fn 1. Bottom first; fn 1 has no
        // short-term bottom field, so its top field comes last.
        assert_eq!(
            got,
            [(1, Parity::Bottom), (1, Parity::Top), (2, Parity::Top)]
        );
    }

    #[test]
    fn short_term_modification_moves_a_picture_to_the_front() {
        let sps = sps(4, 8);
        let mut dpb = Dpb::new();
        dpb.stores = (0..4)
            .map(|n| frame(n + 1, n, 2 * n as i32, Marking::ShortTerm, 0))
            .collect();
        let mut h = header(SliceType::P, 4, 8, 1);
        // picNumPred 4 − (2 + 1) = 1 → frame_num 1 (key 2) at index 0.
        h.ref_pic_list_modification = RefPicListModification {
            ref_pic_list_modification_flag_l0: true,
            modifications_l0: vec![RefPicListModificationOp::SubtractPicNum(2)],
            ..RefPicListModification::default()
        };
        with_current(&mut dpb, &sps, &h);
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        assert_eq!(keys(&l.list0), [Some(2), Some(4), Some(3), Some(1)]);
        // A short list is padded with "no reference picture".
        h.num_ref_idx_l0_active_minus1 = 5;
        let l = dpb.ref_pic_lists(&sps, &h).unwrap();
        assert_eq!(l.list0.len(), 6);
        assert_eq!(l.list0[4], None);
    }

    /// Drive whole pictures through begin / finish.
    fn decode(dpb: &mut Dpb, sps: &H264Sps, h: &SliceHeader) -> FinishedPicture {
        dpb.begin_picture(sps, h).unwrap();
        dpb.finish_picture(sps).unwrap()
    }

    fn state(dpb: &Dpb) -> (Vec<u32>, Vec<(u32, u32)>) {
        let st = dpb
            .references()
            .filter(|s| s.any(Marking::ShortTerm))
            .map(|s| s.frame_num)
            .collect();
        let lt = dpb
            .references()
            .filter_map(|s| s.long_term_frame_idx().map(|i| (i, s.frame_num)))
            .collect();
        (st, lt)
    }

    #[test]
    fn sliding_window_and_mmco_long_term_lifecycle() {
        let sps = sps(4, 2);
        let mut dpb = Dpb::new();
        let mut idr = header(SliceType::I, 0, 0, 3);
        idr.nal_unit_type = 5;
        decode(&mut dpb, &sps, &idr);
        decode(&mut dpb, &sps, &header(SliceType::P, 1, 2, 2));
        assert_eq!(state(&dpb), (vec![0, 1], vec![]));
        // Sliding window (max_num_ref_frames 2) drops frame_num 0.
        let f = decode(&mut dpb, &sps, &header(SliceType::P, 2, 4, 2));
        assert_eq!(state(&dpb), (vec![1, 2], vec![]));
        assert_eq!(f.released.len(), 1);
        // MMCO 3: picNumX = 3 − 1 = 2 becomes long-term index 0;
        // MMCO 1 drops picNumX 3 − 2 = 1.
        let mut h = header(SliceType::P, 3, 6, 2);
        h.dec_ref_pic_marking = Some(DecRefPicMarking {
            adaptive_ref_pic_marking_mode_flag: true,
            mmco: vec![
                MmcoOp::SetMaxLongTermFrameIdx {
                    max_long_term_frame_idx_plus1: 1,
                },
                MmcoOp::AssignLongTerm {
                    difference_of_pic_nums_minus1: 0,
                    long_term_frame_idx: 0,
                },
                MmcoOp::MarkShortTermUnused {
                    difference_of_pic_nums_minus1: 1,
                },
            ],
            ..DecRefPicMarking::default()
        });
        decode(&mut dpb, &sps, &h);
        assert_eq!(state(&dpb), (vec![3], vec![(0, 2)]));
        assert_eq!(dpb.max_long_term_frame_idx(), Some(0));
        // A P frame now lists short-term before long-term.
        let p = header(SliceType::P, 4, 8, 0);
        dpb.begin_picture(&sps, &p).unwrap();
        let mut q = p.clone();
        q.num_ref_idx_l0_active_minus1 = 1;
        let l = dpb.ref_pic_lists(&sps, &q).unwrap();
        let fns: Vec<u32> = l
            .list0
            .iter()
            .map(|e| dpb.store(e.unwrap().key).unwrap().frame_num)
            .collect();
        assert_eq!(fns, [3, 2]);
        dpb.finish_picture(&sps).unwrap();
        // MMCO 6 makes the current picture long-term, replacing index 0;
        // MMCO 5 then resets everything.
        let mut h = header(SliceType::P, 4, 10, 2);
        h.dec_ref_pic_marking = Some(DecRefPicMarking {
            adaptive_ref_pic_marking_mode_flag: true,
            mmco: vec![MmcoOp::AssignCurrentLongTerm {
                long_term_frame_idx: 0,
            }],
            ..DecRefPicMarking::default()
        });
        decode(&mut dpb, &sps, &h);
        assert_eq!(state(&dpb), (vec![3], vec![(0, 4)]));
        let mut h = header(SliceType::P, 5, 12, 2);
        h.dec_ref_pic_marking = Some(DecRefPicMarking {
            adaptive_ref_pic_marking_mode_flag: true,
            mmco: vec![MmcoOp::MarkAllUnused],
            ..DecRefPicMarking::default()
        });
        let f = decode(&mut dpb, &sps, &h);
        assert!(f.mmco5);
        assert_eq!(f.pic_order_cnt, 0, "MMCO 5 rebases the count");
        assert_eq!(state(&dpb), (vec![0], vec![]), "frame_num inferred 0");
        // The next picture continues after the inferred frame_num 0.
        decode(&mut dpb, &sps, &header(SliceType::P, 1, 2, 2));
        assert_eq!(state(&dpb), (vec![0, 1], vec![]));
    }

    #[test]
    fn gaps_in_frame_num_insert_non_existing_frames() {
        let mut sps = sps(4, 4);
        sps.gaps_in_frame_num_value_allowed_flag = true;
        let mut dpb = Dpb::new();
        let mut idr = header(SliceType::I, 0, 0, 3);
        idr.nal_unit_type = 5;
        decode(&mut dpb, &sps, &idr);
        let cur = dpb
            .begin_picture(&sps, &header(SliceType::P, 3, 6, 2))
            .unwrap();
        assert_eq!(cur.non_existing.len(), 2);
        let ne: Vec<u32> = dpb
            .references()
            .filter(|s| s.non_existing)
            .map(|s| s.frame_num)
            .collect();
        assert_eq!(ne, [1, 2]);
        dpb.finish_picture(&sps).unwrap();
        assert_eq!(state(&dpb).0, [0, 1, 2, 3]);
        // A gap longer than the DPB keeps only its last frames.
        dpb.begin_picture(&sps, &header(SliceType::P, 13, 26, 2))
            .unwrap();
        dpb.finish_picture(&sps).unwrap();
        assert_eq!(state(&dpb).0, [10, 11, 12, 13]);
        // Without the SPS flag a gap is a loss.
        let mut strict = sps.clone();
        strict.gaps_in_frame_num_value_allowed_flag = false;
        assert!(
            dpb.begin_picture(&strict, &header(SliceType::P, 6, 12, 2))
                .is_err()
        );
    }

    #[test]
    fn field_pairs_share_a_store() {
        let sps = sps(4, 4);
        let mut dpb = Dpb::new();
        let mut top = header(SliceType::I, 0, 0, 3);
        top.nal_unit_type = 5;
        top.field_pic_flag = true;
        let a = decode(&mut dpb, &sps, &top);
        assert!(a.awaiting_second_field);
        let mut bottom = header(SliceType::P, 0, 1, 3);
        bottom.field_pic_flag = true;
        bottom.bottom_field_flag = true;
        let cur = dpb.begin_picture(&sps, &bottom).unwrap();
        assert!(cur.second_field);
        assert_eq!(cur.key, a.key);
        // The second field references its own first field.
        let mut q = bottom.clone();
        q.num_ref_idx_l0_active_minus1 = 0;
        let l = dpb.ref_pic_lists(&sps, &q).unwrap();
        assert_eq!(
            l.list0,
            [Some(RefPicture {
                key: a.key,
                parity: Some(Parity::Top)
            })]
        );
        let b = dpb.finish_picture(&sps).unwrap();
        assert_eq!(b.key, a.key);
        let s = dpb.store(a.key).unwrap();
        assert!(s.is_short_term_frame());
        assert_eq!((s.top().poc, s.bottom().poc), (0, 1));
    }
}
