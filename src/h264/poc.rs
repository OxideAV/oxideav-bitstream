//! H.264 picture order count (§8.2.1, types 0 / 1 / 2).
//!
//! [`PocState`] carries what the derivation needs from earlier
//! pictures: `prevPicOrderCntMsb` / `prevPicOrderCntLsb` of the previous
//! reference picture (type 0, §8.2.1.1) and `prevFrameNumOffset` /
//! `prevFrameNum` of the previous picture (types 1 and 2, §8.2.1.2 /
//! §8.2.1.3), including the `memory_management_control_operation` 5
//! resets. Call [`PocState::derive`] when a picture starts and
//! [`PocState::finish`] once it is decoded (after reference marking has
//! told you whether it carried MMCO 5).

use super::H264Sps;
use super::slice::SliceHeader;
use crate::BitstreamError;

/// The counts of one picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Poc {
    /// `TopFieldOrderCnt` (meaningful unless the picture is a bottom field).
    pub top_field_order_cnt: i32,
    /// `BottomFieldOrderCnt` (meaningful unless the picture is a top field).
    pub bottom_field_order_cnt: i32,
    /// `PicOrderCnt( CurrPic )` (eq. 8-1).
    pub pic_order_cnt: i32,
    /// `PicOrderCntMsb` (type 0 only).
    pub pic_order_cnt_msb: i32,
    /// `FrameNumOffset` (types 1 and 2 only).
    pub frame_num_offset: i32,
}

/// Which part of a frame a picture is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PictureStructure {
    #[default]
    Frame,
    TopField,
    BottomField,
}

impl PictureStructure {
    /// From `field_pic_flag` / `bottom_field_flag`.
    pub fn of(h: &SliceHeader) -> Self {
        match (h.field_pic_flag, h.bottom_field_flag) {
            (false, _) => PictureStructure::Frame,
            (true, false) => PictureStructure::TopField,
            (true, true) => PictureStructure::BottomField,
        }
    }

    pub fn is_field(self) -> bool {
        self != PictureStructure::Frame
    }
}

impl Poc {
    fn with_structure(mut self, s: PictureStructure) -> Self {
        self.pic_order_cnt = match s {
            PictureStructure::Frame => self.top_field_order_cnt.min(self.bottom_field_order_cnt),
            PictureStructure::TopField => self.top_field_order_cnt,
            PictureStructure::BottomField => self.bottom_field_order_cnt,
        };
        self
    }

    /// The counts after `memory_management_control_operation` 5
    /// (§8.2.1): `tempPicOrderCnt = PicOrderCnt( CurrPic )` is subtracted
    /// from both field counts, so the picture's own count becomes 0.
    pub fn after_mmco5(self, s: PictureStructure) -> Self {
        let temp = self.pic_order_cnt;
        Poc {
            top_field_order_cnt: self.top_field_order_cnt - temp,
            bottom_field_order_cnt: self.bottom_field_order_cnt - temp,
            ..self
        }
        .with_structure(s)
    }
}

/// Cross-picture state of the §8.2.1 derivations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PocState {
    /// `prevPicOrderCntMsb` for the next picture (type 0).
    pub prev_pic_order_cnt_msb: i32,
    /// `prevPicOrderCntLsb` for the next picture (type 0).
    pub prev_pic_order_cnt_lsb: i32,
    /// `prevFrameNumOffset` for the next picture (types 1 / 2).
    pub prev_frame_num_offset: i32,
    /// `prevFrameNum` for the next picture (types 1 / 2).
    pub prev_frame_num: u32,
}

/// The parts of a picture the derivation reads.
#[derive(Debug, Clone, Copy)]
struct Input {
    idr: bool,
    reference: bool,
    frame_num: u32,
    structure: PictureStructure,
    pic_order_cnt_lsb: u32,
    delta_pic_order_cnt_bottom: i32,
    delta_pic_order_cnt: [i32; 2],
}

impl PocState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Derive the counts of the picture whose first slice header is `h`.
    pub fn derive(&self, sps: &H264Sps, h: &SliceHeader) -> Result<Poc, BitstreamError> {
        self.derive_input(
            sps,
            Input {
                idr: h.is_idr(),
                reference: h.nal_ref_idc != 0,
                frame_num: h.frame_num,
                structure: PictureStructure::of(h),
                pic_order_cnt_lsb: h.pic_order_cnt_lsb,
                delta_pic_order_cnt_bottom: h.delta_pic_order_cnt_bottom,
                delta_pic_order_cnt: h.delta_pic_order_cnt,
            },
        )
    }

    /// Counts of a "non-existing" frame inferred by §8.2.5.2 (frame_num
    /// `frame_num`, a non-IDR reference frame with zero deltas). Type 0
    /// streams give such frames no counts; the result is then zero.
    pub fn derive_non_existing(
        &self,
        sps: &H264Sps,
        frame_num: u32,
    ) -> Result<Poc, BitstreamError> {
        if sps.pic_order_cnt_type == 0 {
            return Ok(Poc::default());
        }
        self.derive_input(
            sps,
            Input {
                idr: false,
                reference: true,
                frame_num,
                structure: PictureStructure::Frame,
                pic_order_cnt_lsb: 0,
                delta_pic_order_cnt_bottom: 0,
                delta_pic_order_cnt: [0; 2],
            },
        )
    }

    fn derive_input(&self, sps: &H264Sps, p: Input) -> Result<Poc, BitstreamError> {
        let overflow = || BitstreamError::invalid("picture order count overflows 32 bits");
        let mut out = Poc::default();
        match sps.pic_order_cnt_type {
            0 => {
                let max_lsb = sps.max_pic_order_cnt_lsb() as i64;
                let (prev_msb, prev_lsb) = if p.idr {
                    (0i64, 0i64)
                } else {
                    (
                        i64::from(self.prev_pic_order_cnt_msb),
                        i64::from(self.prev_pic_order_cnt_lsb),
                    )
                };
                let lsb = i64::from(p.pic_order_cnt_lsb);
                // eq. 8-3
                let msb = if lsb < prev_lsb && prev_lsb - lsb >= max_lsb / 2 {
                    prev_msb + max_lsb
                } else if lsb > prev_lsb && lsb - prev_lsb > max_lsb / 2 {
                    prev_msb - max_lsb
                } else {
                    prev_msb
                };
                let msb = i32::try_from(msb).map_err(|_| overflow())?;
                out.pic_order_cnt_msb = msb;
                let base = msb
                    .checked_add(p.pic_order_cnt_lsb as i32)
                    .ok_or_else(overflow)?;
                // eq. 8-4 / 8-5
                match p.structure {
                    PictureStructure::Frame => {
                        out.top_field_order_cnt = base;
                        out.bottom_field_order_cnt = base
                            .checked_add(p.delta_pic_order_cnt_bottom)
                            .ok_or_else(overflow)?;
                    }
                    PictureStructure::TopField => out.top_field_order_cnt = base,
                    PictureStructure::BottomField => out.bottom_field_order_cnt = base,
                }
            }
            1 => {
                let frame_num_offset = self.frame_num_offset(sps, &p)?;
                out.frame_num_offset = frame_num_offset;
                let cycle = sps.offsets_for_ref_frame.len() as i64;
                // eq. 8-7
                let mut abs_frame_num = if cycle != 0 {
                    i64::from(frame_num_offset) + i64::from(p.frame_num)
                } else {
                    0
                };
                if !p.reference && abs_frame_num > 0 {
                    abs_frame_num -= 1;
                }
                let delta_per_cycle: i64 = sps
                    .offsets_for_ref_frame
                    .iter()
                    .map(|&o| i64::from(o))
                    .sum();
                // eq. 8-8 / 8-9
                let mut expected: i64 = 0;
                if abs_frame_num > 0 {
                    let cycle_cnt = (abs_frame_num - 1) / cycle;
                    let in_cycle = (abs_frame_num - 1) % cycle;
                    expected = cycle_cnt * delta_per_cycle;
                    for &o in &sps.offsets_for_ref_frame[..=in_cycle as usize] {
                        expected += i64::from(o);
                    }
                }
                if !p.reference {
                    expected += i64::from(sps.offset_for_non_ref_pic);
                }
                let t2b = i64::from(sps.offset_for_top_to_bottom_field);
                let d = [
                    i64::from(p.delta_pic_order_cnt[0]),
                    i64::from(p.delta_pic_order_cnt[1]),
                ];
                let fit = |v: i64| i32::try_from(v).map_err(|_| overflow());
                // eq. 8-10
                match p.structure {
                    PictureStructure::Frame => {
                        let top = expected + d[0];
                        out.top_field_order_cnt = fit(top)?;
                        out.bottom_field_order_cnt = fit(top + t2b + d[1])?;
                    }
                    PictureStructure::TopField => out.top_field_order_cnt = fit(expected + d[0])?,
                    PictureStructure::BottomField => {
                        out.bottom_field_order_cnt = fit(expected + t2b + d[0])?
                    }
                }
            }
            2 => {
                let frame_num_offset = self.frame_num_offset(sps, &p)?;
                out.frame_num_offset = frame_num_offset;
                // eq. 8-12
                let temp: i64 = if p.idr {
                    0
                } else if !p.reference {
                    2 * (i64::from(frame_num_offset) + i64::from(p.frame_num)) - 1
                } else {
                    2 * (i64::from(frame_num_offset) + i64::from(p.frame_num))
                };
                let temp = i32::try_from(temp).map_err(|_| overflow())?;
                // eq. 8-13
                match p.structure {
                    PictureStructure::Frame => {
                        out.top_field_order_cnt = temp;
                        out.bottom_field_order_cnt = temp;
                    }
                    PictureStructure::TopField => out.top_field_order_cnt = temp,
                    PictureStructure::BottomField => out.bottom_field_order_cnt = temp,
                }
            }
            t => {
                return Err(BitstreamError::invalid(format!("pic_order_cnt_type={t}")));
            }
        }
        Ok(out.with_structure(p.structure))
    }

    /// eq. 8-6 / 8-11.
    fn frame_num_offset(&self, sps: &H264Sps, p: &Input) -> Result<i32, BitstreamError> {
        if p.idr {
            return Ok(0);
        }
        if self.prev_frame_num > p.frame_num {
            self.prev_frame_num_offset
                .checked_add(sps.max_frame_num() as i32)
                .ok_or_else(|| BitstreamError::invalid("FrameNumOffset overflows 32 bits"))
        } else {
            Ok(self.prev_frame_num_offset)
        }
    }

    /// Record a decoded picture. `poc` is what [`PocState::derive`]
    /// returned for it (before any MMCO 5 adjustment) and `mmco5`
    /// whether it carried `memory_management_control_operation` 5.
    pub fn finish(&mut self, sps: &H264Sps, h: &SliceHeader, poc: &Poc, mmco5: bool) {
        let structure = PictureStructure::of(h);
        // Types 1 / 2: the previous picture in decoding order.
        if mmco5 {
            self.prev_frame_num_offset = 0;
            self.prev_frame_num = 0;
        } else {
            self.prev_frame_num_offset = poc.frame_num_offset;
            self.prev_frame_num = h.frame_num;
        }
        // Type 0: the previous reference picture (§8.2.1.1).
        if sps.pic_order_cnt_type == 0 && h.nal_ref_idc != 0 {
            if mmco5 {
                self.prev_pic_order_cnt_msb = 0;
                self.prev_pic_order_cnt_lsb = if structure == PictureStructure::BottomField {
                    0
                } else {
                    poc.after_mmco5(structure).top_field_order_cnt
                };
            } else {
                self.prev_pic_order_cnt_msb = poc.pic_order_cnt_msb;
                self.prev_pic_order_cnt_lsb = h.pic_order_cnt_lsb as i32;
            }
        }
    }

    /// Step the type 1 / 2 state over a "non-existing" frame without
    /// deriving its counts (constant time).
    pub fn skip_non_existing(&mut self, sps: &H264Sps, frame_num: u32) {
        if self.prev_frame_num > frame_num {
            self.prev_frame_num_offset = self
                .prev_frame_num_offset
                .saturating_add(sps.max_frame_num() as i32);
        }
        self.prev_frame_num = frame_num;
    }

    /// Record a "non-existing" frame of §8.2.5.2 (it is the previous
    /// picture for types 1 and 2; type 0 ignores it).
    pub fn finish_non_existing(&mut self, frame_num: u32, poc: &Poc) {
        self.prev_frame_num_offset = poc.frame_num_offset;
        self.prev_frame_num = frame_num;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sps(poc_type: u8) -> H264Sps {
        H264Sps {
            pic_order_cnt_type: poc_type,
            log2_max_frame_num_minus4: 0,
            log2_max_pic_order_cnt_lsb_minus4: 0,
            frame_mbs_only_flag: false,
            ..H264Sps::default()
        }
    }

    fn pic(idr: bool, nal_ref_idc: u8, frame_num: u32, lsb: u32) -> SliceHeader {
        SliceHeader {
            nal_unit_type: if idr { 5 } else { 1 },
            nal_ref_idc,
            frame_num,
            pic_order_cnt_lsb: lsb,
            ..SliceHeader::default()
        }
    }

    #[test]
    fn type0_msb_follows_lsb_wrap() {
        // MaxPicOrderCntLsb 16.
        let sps = sps(0);
        let mut st = PocState::new();
        let mut run = |h: SliceHeader| {
            let p = st.derive(&sps, &h).unwrap();
            st.finish(&sps, &h, &p, false);
            p.pic_order_cnt
        };
        assert_eq!(run(pic(true, 1, 0, 0)), 0);
        assert_eq!(run(pic(false, 1, 1, 6)), 6);
        assert_eq!(run(pic(false, 1, 2, 12)), 12);
        // 2 < 12 and 12 − 2 ≥ 8: PicOrderCntMsb += 16 (eq. 8-3).
        assert_eq!(run(pic(false, 1, 3, 2)), 18);
        // A non-reference picture does not move prevPicOrderCntLsb.
        assert_eq!(run(pic(false, 0, 4, 0)), 16);
        // 14 > 2 and 14 − 2 > 8: PicOrderCntMsb −= 16.
        assert_eq!(run(pic(false, 1, 4, 14)), 14);
    }

    #[test]
    fn type0_fields_and_bottom_delta() {
        let sps = sps(0);
        let st = PocState::new();
        let mut h = pic(true, 1, 0, 4);
        h.delta_pic_order_cnt_bottom = 1;
        let p = st.derive(&sps, &h).unwrap();
        assert_eq!(
            (
                p.top_field_order_cnt,
                p.bottom_field_order_cnt,
                p.pic_order_cnt
            ),
            (4, 5, 4)
        );
        let mut b = pic(false, 1, 0, 5);
        b.field_pic_flag = true;
        b.bottom_field_flag = true;
        let p = st.derive(&sps, &b).unwrap();
        assert_eq!(p.bottom_field_order_cnt, 5);
        assert_eq!(p.pic_order_cnt, 5);
    }

    #[test]
    fn type1_expected_counts() {
        let mut sps = sps(1);
        // Cycle of two reference frames: +4, +2; non-reference −2.
        sps.offsets_for_ref_frame = vec![4, 2];
        sps.offset_for_non_ref_pic = -2;
        sps.offset_for_top_to_bottom_field = 1;
        let mut st = PocState::new();
        let mut run = |h: SliceHeader| {
            let p = st.derive(&sps, &h).unwrap();
            st.finish(&sps, &h, &p, false);
            (p.top_field_order_cnt, p.bottom_field_order_cnt)
        };
        assert_eq!(run(pic(true, 1, 0, 0)), (0, 1));
        // absFrameNum 1: cycle 0, in-cycle 0 → 4.
        assert_eq!(run(pic(false, 1, 1, 0)), (4, 5));
        // absFrameNum 2: in-cycle 1 → 4 + 2 = 6.
        assert_eq!(run(pic(false, 1, 2, 0)), (6, 7));
        // Non-reference frame_num 3: absFrameNum 3 − 1 = 2 → 6 − 2 = 4.
        assert_eq!(run(pic(false, 0, 3, 0)), (4, 5));
        // absFrameNum 3: cycle 1 (6), in-cycle 0 → 10.
        assert_eq!(run(pic(false, 1, 3, 0)), (10, 11));
        // frame_num wraps at MaxFrameNum 16: FrameNumOffset 16.
        let mut wrap = pic(false, 1, 0, 0);
        wrap.frame_num = 0;
        let p = st.derive(&sps, &wrap).unwrap();
        assert_eq!(p.frame_num_offset, 16);
    }

    #[test]
    fn type2_doubles_frame_num_and_mmco5_resets() {
        let sps = sps(2);
        let mut st = PocState::new();
        let h = pic(true, 1, 0, 0);
        let p = st.derive(&sps, &h).unwrap();
        st.finish(&sps, &h, &p, false);
        let h = pic(false, 1, 1, 0);
        let p = st.derive(&sps, &h).unwrap();
        assert_eq!(p.pic_order_cnt, 2);
        st.finish(&sps, &h, &p, true);
        assert_eq!(p.after_mmco5(PictureStructure::Frame).pic_order_cnt, 0);
        // After MMCO 5: prevFrameNum 0, prevFrameNumOffset 0.
        let h = pic(false, 0, 1, 0);
        assert_eq!(st.derive(&sps, &h).unwrap().pic_order_cnt, 1);
    }
}
