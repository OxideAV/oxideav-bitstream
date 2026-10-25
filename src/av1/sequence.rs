//! AV1 sequence header OBU (§5.5) without envelope restrictions: every
//! operating point, `decoder_model_info()` and the per-point operating
//! parameters, which the frame header parser of [`super::frame`] needs
//! (`temporal_point_info()`, `buffer_removal_time`).

use super::{AV1_IDENTITY_COLOR_DESCRIPTION, Av1ColorConfig, Av1TimingInfo};
use crate::BitstreamError;
use crate::bit_reader::BitReader;

/// `SELECT_SCREEN_CONTENT_TOOLS` / `SELECT_INTEGER_MV`.
pub const SELECT: u8 = 2;

/// `decoder_model_info()` (§5.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DecoderModelInfo {
    pub buffer_delay_length_minus_1: u8,
    pub num_units_in_decoding_tick: u32,
    pub buffer_removal_time_length_minus_1: u8,
    pub frame_presentation_time_length_minus_1: u8,
}

/// One operating point of the sequence header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct OperatingPoint {
    pub idc: u16,
    pub seq_level_idx: u8,
    pub seq_tier: bool,
    pub decoder_model_present: bool,
    pub decoder_buffer_delay: u32,
    pub encoder_buffer_delay: u32,
    pub low_delay_mode_flag: bool,
    pub initial_display_delay_present: bool,
    pub initial_display_delay_minus_1: u8,
}

impl OperatingPoint {
    /// Whether an OBU with these ids belongs to the operating point
    /// (§7.1 drop rule): every OBU when `idc` is 0.
    pub fn contains(&self, temporal_id: u8, spatial_id: u8) -> bool {
        self.idc == 0
            || ((self.idc >> temporal_id) & 1 != 0
                && (self.idc >> (u32::from(spatial_id) + 8)) & 1 != 0)
    }
}

/// `sequence_header_obu()` (§5.5.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SequenceHeader {
    pub seq_profile: u8,
    pub still_picture: bool,
    pub reduced_still_picture_header: bool,
    pub timing_info: Option<Av1TimingInfo>,
    pub decoder_model_info: Option<DecoderModelInfo>,
    pub initial_display_delay_present_flag: bool,
    pub operating_points: Vec<OperatingPoint>,
    pub frame_width_bits_minus_1: u8,
    pub frame_height_bits_minus_1: u8,
    pub max_frame_width_minus_1: u32,
    pub max_frame_height_minus_1: u32,
    pub frame_id_numbers_present_flag: bool,
    pub delta_frame_id_length_minus_2: u8,
    pub additional_frame_id_length_minus_1: u8,
    pub use_128x128_superblock: bool,
    pub enable_filter_intra: bool,
    pub enable_intra_edge_filter: bool,
    pub enable_interintra_compound: bool,
    pub enable_masked_compound: bool,
    pub enable_warped_motion: bool,
    pub enable_dual_filter: bool,
    pub enable_order_hint: bool,
    pub enable_jnt_comp: bool,
    pub enable_ref_frame_mvs: bool,
    pub seq_choose_screen_content_tools: bool,
    /// [`SELECT`] when chosen per frame.
    pub seq_force_screen_content_tools: u8,
    pub seq_choose_integer_mv: bool,
    /// [`SELECT`] when chosen per frame.
    pub seq_force_integer_mv: u8,
    /// `OrderHintBits`.
    pub order_hint_bits: u8,
    pub enable_superres: bool,
    pub enable_cdef: bool,
    pub enable_restoration: bool,
    pub color_config: Av1ColorConfig,
    pub film_grain_params_present: bool,
}

impl SequenceHeader {
    /// `equal_picture_interval` (false without timing info).
    pub fn equal_picture_interval(&self) -> bool {
        self.timing_info
            .is_some_and(|t| t.num_ticks_per_picture_minus_1.is_some())
    }

    /// `idLen` of §5.9.2 (only meaningful with frame ids).
    pub fn frame_id_length(&self) -> u32 {
        u32::from(self.additional_frame_id_length_minus_1)
            + u32::from(self.delta_frame_id_length_minus_2)
            + 3
    }

    /// `NumPlanes`.
    pub fn num_planes(&self) -> usize {
        if self.color_config.monochrome { 1 } else { 3 }
    }

    pub fn max_frame_width(&self) -> u32 {
        self.max_frame_width_minus_1 + 1
    }

    pub fn max_frame_height(&self) -> u32 {
        self.max_frame_height_minus_1 + 1
    }
}

/// Parse a sequence header OBU payload.
pub fn parse_sequence_header_obu(payload: &[u8]) -> Result<SequenceHeader, BitstreamError> {
    let mut r = BitReader::new(payload);
    let mut s = SequenceHeader {
        seq_profile: r.u(3) as u8,
        still_picture: r.u(1) != 0,
        reduced_still_picture_header: r.u(1) != 0,
        ..SequenceHeader::default()
    };
    if s.seq_profile > 2 {
        return Err(BitstreamError::invalid(format!(
            "seq_profile={}",
            s.seq_profile
        )));
    }
    if s.reduced_still_picture_header {
        if !s.still_picture {
            return Err(BitstreamError::invalid(
                "reduced_still_picture_header without still_picture",
            ));
        }
        s.operating_points.push(OperatingPoint {
            seq_level_idx: r.u(5) as u8,
            ..OperatingPoint::default()
        });
    } else {
        if r.u(1) != 0 {
            let mut t = Av1TimingInfo {
                num_units_in_display_tick: r.u(32),
                time_scale: r.u(32),
                num_ticks_per_picture_minus_1: None,
            };
            if r.u(1) != 0 {
                t.num_ticks_per_picture_minus_1 = Some(r.uvlc());
            }
            s.timing_info = Some(t);
            if r.u(1) != 0 {
                s.decoder_model_info = Some(DecoderModelInfo {
                    buffer_delay_length_minus_1: r.u(5) as u8,
                    num_units_in_decoding_tick: r.u(32),
                    buffer_removal_time_length_minus_1: r.u(5) as u8,
                    frame_presentation_time_length_minus_1: r.u(5) as u8,
                });
            }
        }
        s.initial_display_delay_present_flag = r.u(1) != 0;
        let count = r.u(5) + 1;
        for _ in 0..count {
            let mut op = OperatingPoint {
                idc: r.u(12) as u16,
                seq_level_idx: r.u(5) as u8,
                ..OperatingPoint::default()
            };
            if op.seq_level_idx > 7 {
                op.seq_tier = r.u(1) != 0;
            }
            if let Some(dm) = s.decoder_model_info {
                op.decoder_model_present = r.u(1) != 0;
                if op.decoder_model_present {
                    let n = u32::from(dm.buffer_delay_length_minus_1) + 1;
                    op.decoder_buffer_delay = r.u(n);
                    op.encoder_buffer_delay = r.u(n);
                    op.low_delay_mode_flag = r.u(1) != 0;
                }
            }
            if s.initial_display_delay_present_flag {
                op.initial_display_delay_present = r.u(1) != 0;
                if op.initial_display_delay_present {
                    op.initial_display_delay_minus_1 = r.u(4) as u8;
                }
            }
            s.operating_points.push(op);
        }
    }
    s.frame_width_bits_minus_1 = r.u(4) as u8;
    s.frame_height_bits_minus_1 = r.u(4) as u8;
    s.max_frame_width_minus_1 = r.u(u32::from(s.frame_width_bits_minus_1) + 1);
    s.max_frame_height_minus_1 = r.u(u32::from(s.frame_height_bits_minus_1) + 1);
    if !s.reduced_still_picture_header {
        s.frame_id_numbers_present_flag = r.u(1) != 0;
    }
    if s.frame_id_numbers_present_flag {
        s.delta_frame_id_length_minus_2 = r.u(4) as u8;
        s.additional_frame_id_length_minus_1 = r.u(3) as u8;
        if s.frame_id_length() > 16 {
            return Err(BitstreamError::invalid("AV1 frame id length above 16 bits"));
        }
    }
    s.use_128x128_superblock = r.u(1) != 0;
    s.enable_filter_intra = r.u(1) != 0;
    s.enable_intra_edge_filter = r.u(1) != 0;
    if s.reduced_still_picture_header {
        s.seq_force_screen_content_tools = SELECT;
        s.seq_force_integer_mv = SELECT;
    } else {
        s.enable_interintra_compound = r.u(1) != 0;
        s.enable_masked_compound = r.u(1) != 0;
        s.enable_warped_motion = r.u(1) != 0;
        s.enable_dual_filter = r.u(1) != 0;
        s.enable_order_hint = r.u(1) != 0;
        if s.enable_order_hint {
            s.enable_jnt_comp = r.u(1) != 0;
            s.enable_ref_frame_mvs = r.u(1) != 0;
        }
        s.seq_choose_screen_content_tools = r.u(1) != 0;
        s.seq_force_screen_content_tools = if s.seq_choose_screen_content_tools {
            SELECT
        } else {
            r.u(1) as u8
        };
        s.seq_force_integer_mv = SELECT;
        if s.seq_force_screen_content_tools > 0 {
            s.seq_choose_integer_mv = r.u(1) != 0;
            if !s.seq_choose_integer_mv {
                s.seq_force_integer_mv = r.u(1) as u8;
            }
        }
        if s.enable_order_hint {
            s.order_hint_bits = r.u(3) as u8 + 1;
        }
    }
    s.enable_superres = r.u(1) != 0;
    s.enable_cdef = r.u(1) != 0;
    s.enable_restoration = r.u(1) != 0;
    s.color_config = color_config(&mut r, s.seq_profile);
    s.film_grain_params_present = r.u(1) != 0;
    if r.bit_pos() > r.total_bits() {
        return Err(BitstreamError::unexpected_end("AV1 sequence header"));
    }
    Ok(s)
}

fn color_config(r: &mut BitReader<'_>, profile: u8) -> Av1ColorConfig {
    let mut c = Av1ColorConfig::default();
    let high = r.u(1) != 0;
    c.bit_depth = if profile == 2 && high {
        if r.u(1) != 0 { 12 } else { 10 }
    } else if high {
        10
    } else {
        8
    };
    c.monochrome = profile != 1 && r.u(1) != 0;
    if r.u(1) != 0 {
        c.color_description = Some((r.u(8) as u8, r.u(8) as u8, r.u(8) as u8));
    }
    if c.monochrome {
        c.color_range = r.u(1) != 0;
        c.subsampling_x = true;
        c.subsampling_y = true;
        return c;
    }
    if c.color_description == Some(AV1_IDENTITY_COLOR_DESCRIPTION) {
        c.color_range = true;
    } else {
        c.color_range = r.u(1) != 0;
        match profile {
            0 => {
                c.subsampling_x = true;
                c.subsampling_y = true;
            }
            1 => {}
            _ => {
                if c.bit_depth == 12 {
                    c.subsampling_x = r.u(1) != 0;
                    if c.subsampling_x {
                        c.subsampling_y = r.u(1) != 0;
                    }
                } else {
                    c.subsampling_x = true;
                }
            }
        }
        if c.subsampling_x && c.subsampling_y {
            c.chroma_sample_position = r.u(2) as u8;
        }
    }
    c.separate_uv_delta_q = r.u(1) != 0;
    c
}
