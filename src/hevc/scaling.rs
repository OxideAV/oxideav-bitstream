//! HEVC scaling lists in effect (§7.4.5): `scaling_list_data()` of the
//! PPS or SPS — or the default lists of Tables 7-5 / 7-6 — with list
//! prediction (`scaling_list_pred_matrix_id_delta`, eq. 7-42 / 7-43)
//! and the DC values resolved, plus the up-right diagonal scan of
//! §6.5.3 for row-major conversion.

use super::{HevcPps, HevcScalingListData, HevcSps};

/// Table 7-6, `ScalingList[ 1..3 ][ 0..2 ]` (intra), coding order.
pub const DEFAULT_8X8_INTRA: [u8; 64] = [
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 16, 17, 16, 17, 18, 17, 18, 18, 17, 18, 21, 19, 20,
    21, 20, 19, 21, 24, 22, 22, 24, 24, 22, 22, 24, 25, 25, 27, 30, 27, 25, 25, 29, 31, 35, 35, 31,
    29, 36, 41, 44, 41, 36, 47, 54, 54, 47, 65, 70, 65, 88, 88, 115,
];
/// Table 7-6, `ScalingList[ 1..3 ][ 3..5 ]` (inter), coding order.
pub const DEFAULT_8X8_INTER: [u8; 64] = [
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 20, 20, 20,
    20, 20, 20, 20, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 28, 28, 28, 28, 28,
    28, 33, 33, 33, 33, 33, 41, 41, 41, 41, 54, 54, 54, 71, 71, 91,
];

/// The lists in effect, `ScalingList[ sizeId ][ matrixId ][ i ]` in
/// coding (up-right diagonal) order. `sizeId` 0 uses the first 16
/// entries. For `sizeId` 3 every matrixId is filled: 0 and 3 as coded,
/// 1 / 2 / 4 / 5 from the 16x16 lists (eq. 7-50, used for 4:4:4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HevcScalingLists {
    pub lists: [[[u8; 64]; 6]; 4],
    /// `scaling_list_dc_coef_minus8 + 8`: `[0]` 16x16, `[1]` 32x32.
    pub dc: [[u8; 6]; 2],
}

impl HevcScalingLists {
    /// Tables 7-5 / 7-6 with DC 16.
    pub fn default_lists() -> Self {
        let mut lists = [[[16u8; 64]; 6]; 4];
        for size in lists.iter_mut().skip(1) {
            for (m, l) in size.iter_mut().enumerate() {
                *l = if m < 3 {
                    DEFAULT_8X8_INTRA
                } else {
                    DEFAULT_8X8_INTER
                };
            }
        }
        HevcScalingLists {
            lists,
            dc: [[16; 6]; 2],
        }
    }

    /// Resolve coded `scaling_list_data()`.
    pub fn from_data(d: &HevcScalingListData) -> Self {
        let defaults = Self::default_lists();
        let mut out = defaults.clone();
        for size in 0..4 {
            let step = if size == 3 { 3 } else { 1 };
            for m in (0..6).step_by(step) {
                if d.pred_mode_flag[size][m] {
                    let coded: &[u8] = match size {
                        0 => &d.list_4x4[m],
                        1 => &d.list_8x8[m],
                        2 => &d.list_16x16[m],
                        _ => &d.list_32x32[m],
                    };
                    out.lists[size][m] = [16; 64];
                    out.lists[size][m][..coded.len()].copy_from_slice(coded);
                    if size > 1 {
                        out.dc[size - 2][m] = (d.dc_coef_minus8[size - 2][m] + 8) as u8;
                    }
                } else {
                    let delta = d.pred_matrix_id_delta[size][m] as usize * step;
                    if delta == 0 || delta > m {
                        out.lists[size][m] = defaults.lists[size][m];
                        if size > 1 {
                            out.dc[size - 2][m] = 16;
                        }
                    } else {
                        // eq. 7-42 / 7-43; the DC follows the reference.
                        let r = m - delta;
                        out.lists[size][m] = out.lists[size][r];
                        if size > 1 {
                            out.dc[size - 2][m] = out.dc[size - 2][r];
                        }
                    }
                }
            }
        }
        // eq. 7-50 / 7-51: 32x32 chroma lists come from the 16x16 ones.
        for m in [1, 2, 4, 5] {
            out.lists[3][m] = out.lists[2][m];
            out.dc[1][m] = out.dc[0][m];
        }
        out
    }

    /// The lists for pictures using `pps`: `None` when
    /// `scaling_list_enabled_flag` is 0 (flat scaling, `m = 16`).
    /// Otherwise the PPS data, else the SPS data, else the defaults
    /// (§7.4.3.2.1 / §7.4.3.3.1).
    pub fn in_effect(sps: &HevcSps, pps: &HevcPps) -> Option<Self> {
        if !sps.scaling_list_enabled_flag {
            return None;
        }
        Some(
            match pps
                .scaling_list_data
                .as_ref()
                .or(sps.scaling_list_data.as_ref())
            {
                Some(d) => Self::from_data(d),
                None => Self::default_lists(),
            },
        )
    }

    /// List `[size][matrix]` as a row-major matrix (16 entries for size 0,
    /// else 64 for the 8x8 grid the larger sizes are upsampled from).
    pub fn raster(&self, size: usize, matrix: usize) -> Vec<u8> {
        let n = if size == 0 { 4 } else { 8 };
        let scan = diagonal_scan(n);
        let mut out = vec![0u8; n * n];
        for (i, &(x, y)) in scan.iter().enumerate() {
            out[y * n + x] = self.lists[size][matrix][i];
        }
        out
    }
}

/// §6.5.3 up-right diagonal scan of an `n`x`n` block: `(x, y)` of each
/// scan position.
pub fn diagonal_scan(n: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(n * n);
    let (mut x, mut y) = (0i64, 0i64);
    while out.len() < n * n {
        while y >= 0 {
            if (x as usize) < n && (y as usize) < n {
                out.push((x as usize, y as usize));
            }
            y -= 1;
            x += 1;
        }
        y = x;
        x = 0;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagonal_scan_starts_down_the_first_column() {
        let s = diagonal_scan(4);
        assert_eq!(&s[..6], &[(0, 0), (0, 1), (1, 0), (0, 2), (1, 1), (2, 0)]);
        assert_eq!(s[15], (3, 3));
    }

    #[test]
    fn prediction_copies_list_and_dc() {
        let mut d = HevcScalingListData::default();
        // sizeId 2: matrix 0 explicit with DC 20, matrix 1 predicted
        // from it, matrix 2 default (delta 0).
        d.pred_mode_flag[2][0] = true;
        d.list_16x16[0] = [30; 64];
        d.dc_coef_minus8[0][0] = 12;
        d.pred_matrix_id_delta[2][1] = 1;
        let l = HevcScalingLists::from_data(&d);
        assert_eq!(l.lists[2][1], [30; 64]);
        assert_eq!(l.dc[0][1], 20);
        assert_eq!(l.lists[2][2], DEFAULT_8X8_INTRA);
        assert_eq!(l.dc[0][2], 16);
        assert_eq!(l.lists[0][0][..16], [16; 16]);
        // 32x32 chroma follows 16x16 (eq. 7-50).
        assert_eq!(l.lists[3][1], [30; 64]);
        assert_eq!(l.lists[3][3], DEFAULT_8X8_INTER);
    }
}
