//! H.264 scaling lists in effect for a picture (§7.4.2.1.1 / §7.4.2.2,
//! Table 7-2 fall-back rules A and B, default lists of Tables 7-3 /
//! 7-4) and the zig-zag / field scans of Tables 8-13 / 8-14.
//!
//! Lists are produced in **coding order** — the order
//! `scaling_list()` transmits them, which is the zig-zag scan order of
//! §8.5.6 / §8.5.7. [`to_raster_4x4`] / [`to_raster_8x8`] apply the
//! inverse zig-zag scan for consumers that want row-major matrices.

use super::{H264Pps, H264ScalingLists, H264Sps};

/// `Default_4x4_Intra` (Table 7-3), coding order.
pub const DEFAULT_4X4_INTRA: [u8; 16] = [
    6, 13, 13, 20, 20, 20, 28, 28, 28, 28, 32, 32, 32, 37, 37, 42,
];
/// `Default_4x4_Inter` (Table 7-3), coding order.
pub const DEFAULT_4X4_INTER: [u8; 16] = [
    10, 14, 14, 20, 20, 20, 24, 24, 24, 24, 27, 27, 27, 30, 30, 34,
];
/// `Default_8x8_Intra` (Table 7-4), coding order.
pub const DEFAULT_8X8_INTRA: [u8; 64] = [
    6, 10, 10, 13, 11, 13, 16, 16, 16, 16, 18, 18, 18, 18, 18, 23, 23, 23, 23, 23, 23, 25, 25, 25,
    25, 25, 25, 25, 27, 27, 27, 27, 27, 27, 27, 27, 29, 29, 29, 29, 29, 29, 29, 31, 31, 31, 31, 31,
    31, 33, 33, 33, 33, 33, 36, 36, 36, 36, 38, 38, 38, 40, 40, 42,
];
/// `Default_8x8_Inter` (Table 7-4), coding order.
pub const DEFAULT_8X8_INTER: [u8; 64] = [
    9, 13, 13, 15, 13, 15, 17, 17, 17, 17, 19, 19, 19, 19, 19, 21, 21, 21, 21, 21, 21, 22, 22, 22,
    22, 22, 22, 22, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 27, 27, 27, 27, 27,
    27, 28, 28, 28, 28, 28, 30, 30, 30, 30, 32, 32, 32, 33, 33, 35,
];

/// Table 8-13 zig-zag scan: raster position (row * 4 + column) of scan index `idx`.
pub const ZIGZAG_4X4: [u8; 16] = [0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15];
/// Table 8-13 field scan: raster position of scan index `idx`.
pub const FIELD_SCAN_4X4: [u8; 16] = [0, 4, 1, 8, 12, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
/// Table 8-14 8x8 zig-zag scan: raster position (row * 8 + column).
pub const ZIGZAG_8X8: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];
/// Table 8-14 8x8 field scan: raster position.
pub const FIELD_SCAN_8X8: [u8; 64] = [
    0, 8, 16, 1, 9, 24, 32, 17, 2, 25, 40, 48, 56, 33, 10, 3, 18, 41, 49, 57, 26, 11, 4, 19, 34,
    42, 50, 58, 27, 12, 5, 20, 35, 43, 51, 59, 28, 13, 6, 21, 36, 44, 52, 60, 29, 14, 22, 37, 45,
    53, 61, 30, 7, 15, 38, 46, 54, 62, 23, 31, 39, 47, 55, 63,
];

/// The twelve picture-level scaling lists (Table 7-2 indices: 4x4 lists
/// 0..=5 = Intra Y/Cb/Cr, Inter Y/Cb/Cr; 8x8 lists 6..=11 = Intra Y,
/// Inter Y, Intra Cb, Inter Cb, Intra Cr, Inter Cr), coding order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScalingMatrix {
    pub list_4x4: [[u8; 16]; 6],
    /// `list_8x8[k]` is Table 7-2 index `6 + k`.
    pub list_8x8: [[u8; 64]; 6],
}

impl Default for ScalingMatrix {
    /// `Flat_4x4_16` / `Flat_8x8_16` (eq. 7-8 / 7-9).
    fn default() -> Self {
        ScalingMatrix {
            list_4x4: [[16; 16]; 6],
            list_8x8: [[16; 64]; 6],
        }
    }
}

impl ScalingMatrix {
    /// The 4x4 lists as row-major matrices.
    pub fn raster_4x4(&self) -> [[u8; 16]; 6] {
        self.list_4x4.map(|l| to_raster_4x4(&l))
    }

    /// The 8x8 lists as row-major matrices.
    pub fn raster_8x8(&self) -> [[u8; 64]; 6] {
        self.list_8x8.map(|l| to_raster_8x8(&l))
    }
}

/// Inverse zig-zag scan of a 4x4 list (coding order → row-major).
pub fn to_raster_4x4(list: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (k, &pos) in ZIGZAG_4X4.iter().enumerate() {
        out[pos as usize] = list[k];
    }
    out
}

/// Inverse zig-zag scan of an 8x8 list (coding order → row-major).
pub fn to_raster_8x8(list: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (k, &pos) in ZIGZAG_8X8.iter().enumerate() {
        out[pos as usize] = list[k];
    }
    out
}

#[derive(Clone, Copy)]
enum List {
    L4([u8; 16]),
    L8([u8; 64]),
}

fn default_list(i: usize) -> List {
    match i {
        0..=2 => List::L4(DEFAULT_4X4_INTRA),
        3..=5 => List::L4(DEFAULT_4X4_INTER),
        6 | 8 | 10 => List::L8(DEFAULT_8X8_INTRA),
        _ => List::L8(DEFAULT_8X8_INTER),
    }
}

/// Table 7-2: the index whose list a missing list `i` copies (`None`
/// for the four class heads 0, 3, 6, 7).
fn fallback_index(i: usize) -> Option<usize> {
    match i {
        1 | 2 | 4 | 5 => Some(i - 1),
        8..=11 => Some(i - 2),
        _ => None,
    }
}

fn coded(lists: &H264ScalingLists, i: usize) -> Option<List> {
    if i >= lists.coded_count as usize || !lists.present[i] {
        return None;
    }
    Some(if lists.use_default[i] {
        default_list(i)
    } else if i < 6 {
        List::L4(lists.list_4x4[i])
    } else {
        List::L8(lists.list_8x8[i - 6])
    })
}

fn store(m: &mut ScalingMatrix, i: usize, l: List) {
    match l {
        List::L4(v) => m.list_4x4[i] = v,
        List::L8(v) => m.list_8x8[i - 6] = v,
    }
}

fn get(m: &ScalingMatrix, i: usize) -> List {
    if i < 6 {
        List::L4(m.list_4x4[i])
    } else {
        List::L8(m.list_8x8[i - 6])
    }
}

/// The sequence-level lists of `sps` (§7.4.2.1.1): flat without a
/// matrix, fall-back rule A for lists the SPS leaves out.
pub fn sequence_scaling_matrix(sps: &H264Sps) -> ScalingMatrix {
    let mut m = ScalingMatrix::default();
    let Some(lists) = sps.seq_scaling_lists.as_ref() else {
        return m;
    };
    for i in 0..12 {
        let l = match coded(lists, i) {
            Some(l) => l,
            None => match fallback_index(i) {
                Some(j) => get(&m, j),
                None => default_list(i),
            },
        };
        store(&mut m, i, l);
    }
    m
}

/// The picture-level lists in effect for pictures using `pps` with
/// `sps` (§7.4.2.2): the sequence-level lists without a PPS matrix;
/// otherwise the PPS lists with fall-back rule A (no SPS matrix) or B
/// (SPS matrix present) for the lists it leaves out.
pub fn picture_scaling_matrix(sps: &H264Sps, pps: &H264Pps) -> ScalingMatrix {
    let seq = sequence_scaling_matrix(sps);
    let Some(lists) = pps.pic_scaling_lists.as_ref() else {
        return seq;
    };
    let rule_b = sps.seq_scaling_lists.is_some();
    let mut m = ScalingMatrix::default();
    for i in 0..12 {
        let l = match coded(lists, i) {
            Some(l) => l,
            None => match fallback_index(i) {
                Some(j) => get(&m, j),
                None if rule_b => get(&seq, i),
                None => default_list(i),
            },
        };
        store(&mut m, i, l);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(coded_count: u8, present: &[usize], default: &[usize]) -> H264ScalingLists {
        let mut l = H264ScalingLists {
            coded_count,
            ..H264ScalingLists::default()
        };
        for &i in present {
            l.present[i] = true;
            if i < 6 {
                l.list_4x4[i] = [i as u8 + 1; 16];
            } else {
                l.list_8x8[i - 6] = [i as u8 + 1; 64];
            }
        }
        for &i in default {
            l.present[i] = true;
            l.use_default[i] = true;
        }
        l
    }

    #[test]
    fn flat_without_matrices() {
        let m = picture_scaling_matrix(&H264Sps::default(), &H264Pps::default());
        assert_eq!(m, ScalingMatrix::default());
    }

    #[test]
    fn rule_a_in_the_sps() {
        let sps = H264Sps {
            seq_scaling_lists: Some(lists(8, &[1], &[6])),
            ..H264Sps::default()
        };
        let m = sequence_scaling_matrix(&sps);
        assert_eq!(m.list_4x4[0], DEFAULT_4X4_INTRA, "0: default");
        assert_eq!(m.list_4x4[1], [2; 16], "1: coded");
        assert_eq!(m.list_4x4[2], [2; 16], "2: copies 1");
        assert_eq!(m.list_4x4[3], DEFAULT_4X4_INTER, "3: default");
        assert_eq!(m.list_4x4[5], DEFAULT_4X4_INTER, "5: copies 4 = 3");
        assert_eq!(m.list_8x8[0], DEFAULT_8X8_INTRA);
        assert_eq!(m.list_8x8[1], DEFAULT_8X8_INTER);
        assert_eq!(m.list_8x8[2], DEFAULT_8X8_INTRA, "8 copies 6");
    }

    #[test]
    fn rule_b_takes_sequence_lists_for_class_heads() {
        let sps = H264Sps {
            seq_scaling_lists: Some(lists(8, &[0, 3], &[])),
            ..H264Sps::default()
        };
        let pps = H264Pps {
            pic_scaling_lists: Some(lists(6, &[4], &[])),
            ..H264Pps::default()
        };
        let m = picture_scaling_matrix(&sps, &pps);
        assert_eq!(m.list_4x4[0], [1; 16], "0: sequence list (rule B)");
        assert_eq!(m.list_4x4[1], [1; 16], "1: picture list 0");
        assert_eq!(m.list_4x4[3], [4; 16], "3: sequence list");
        assert_eq!(m.list_4x4[4], [5; 16], "4: coded");
        assert_eq!(m.list_4x4[5], [5; 16], "5: picture list 4");
        // Without an SPS matrix the same PPS falls back to rule A.
        let m = picture_scaling_matrix(&H264Sps::default(), &pps);
        assert_eq!(m.list_4x4[0], DEFAULT_4X4_INTRA);
        assert_eq!(m.list_4x4[3], DEFAULT_4X4_INTER);
    }

    #[test]
    fn raster_conversion_inverts_the_zigzag() {
        let list: [u8; 16] = core::array::from_fn(|i| i as u8);
        let r = to_raster_4x4(&list);
        assert_eq!(&r[..8], &[0, 1, 5, 6, 2, 4, 7, 12]);
        let l8: [u8; 64] = core::array::from_fn(|i| i as u8);
        let r8 = to_raster_8x8(&l8);
        // First row of Figure 8-9 (a).
        assert_eq!(&r8[..8], &[0, 1, 5, 6, 14, 15, 27, 28]);
        assert_eq!(&r8[56..], &[35, 36, 48, 49, 57, 58, 62, 63]);
    }
}
