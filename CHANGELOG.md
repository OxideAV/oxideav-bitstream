# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- H.266 / VVC SPS structural parse (ITU-T H.266 (V4) (01/2026) §7.3.2.4
  + §7.3.3.1 + §7.3.3.2). New `parse_sps()` decodes the fixed-prefix
  geometry fields (`sps_seq_parameter_set_id`,
  `sps_video_parameter_set_id`, `sps_max_sublayers_minus1`,
  `sps_chroma_format_idc`, `sps_log2_ctu_size_minus5`,
  `sps_ptl_dpb_hrd_params_present_flag`,
  `sps_pic_width_max_in_luma_samples`,
  `sps_pic_height_max_in_luma_samples`, `sps_subpic_info_present_flag`,
  `sps_bitdepth_minus8`) plus an optional `profile_tier_level()` decode
  (general profile/tier/level codes, per-sublayer level codes,
  `ptl_num_sub_profiles` + `general_sub_profile_idc[]`). The
  `general_constraints_info()` block (7.3.3.2) is walked so the
  reader stays positioned, but its individual constraint flags are
  not surfaced. SPSs that use subpicture signalling
  (`sps_subpic_info_present_flag = 1`) return
  `BitstreamError::Unsupported` until a later round implements the
  subpic walk. Three new lib tests and one new integration test
  exercise the path (no-PTL 1080p Main10 fixture, 4K Main10 fixture
  with PTL + 2× sub-profile + sublayer level, subpic = 1 fixture,
  truncated + wrong-NAL-type negative cases, end-to-end Annex-B
  AU walk through `split_annex_b` + `parse_sps`).
- New `h266` module: H.266 / VVC structural NAL-walker (ITU-T H.266
  (V4) (01/2026) §7.3.1.1 / §7.3.1.2 / §7.4.2.2 Table 5). Covers
  Annex-B start-code splitter (3- and 4-byte forms), EBSP-to-RBSP
  emulation-prevention stripper, two-byte `nal_unit_header()` decode
  (`forbidden_zero_bit`, `nuh_reserved_zero_bit`, `nuh_layer_id`,
  `nal_unit_type`, `nuh_temporal_id_plus1`, `TemporalId` derived),
  the full set of `NAL_TYPE_*` constants from Table 5, and the
  `is_vcl` / `is_irap` / `is_parameter_set` classifiers. Parameter-set
  / picture-header parsing deferred to later rounds when the HW-accel
  bridges grow VVC support. New integration test
  `tests/h266_nal_walker.rs` walks a synthetic VPS / SPS / PPS / PH /
  IDR_W_RADL access unit end-to-end.
- HEVC PPS parser extended past `entropy_coding_sync_enabled_flag`
  (9 new fields: `pps_loop_filter_across_slices_enabled_flag`,
  `deblocking_filter_control_present_flag`,
  `deblocking_filter_override_enabled_flag`,
  `pps_deblocking_filter_disabled_flag`, `pps_beta_offset_div2`,
  `pps_tc_offset_div2`, `lists_modification_present_flag`,
  `log2_parallel_merge_level_minus2`,
  `slice_segment_header_extension_present_flag`) plus
  `num_long_term_ref_pics_sps` on SPS. Unblocks HEVC migration in
  oxideav-vdpau and HEVC decoder in oxideav-vaapi.
- New `vp8` module: VP8 keyframe header parser (RFC6386 §9.1).
- New `vp9` module: lifted from `oxideav-vdpau::vp9` (uncompressed
  header per VP9 spec). The vdpau crate's inline copy will migrate
  to depend on this in a follow-up commit.
- New `mpeg2` module: lifted from `oxideav-vdpau::mpeg2` (sequence /
  picture / extension headers per ITU-T H.262).
- New `vc1` module: VC-1 sequence + entry-point + picture header
  parser (SMPTE 421M Advanced profile, Annex-G start codes).
- New `ivf` module: shared IVF demuxer used by VP8 and VP9 fixtures.

- **Round 1: scaffold + minimal IDR/keyframe header parsers** for
  H.264, HEVC and AV1.
  - Shared `BitstreamError` and `bit_reader` module (`u(n)`, `ue(v)`,
    `se(v)`, byte alignment) used by every codec sub-module. No
    `unsafe`, no third-party deps.
  - `h264` module: Annex-B NAL splitter, emulation-prevention stripper,
    SPS / PPS / minimal slice-header parsers and a one-shot
    `parse_idr_only` walk. Carries enough fields to populate
    `VAPictureParameterBufferH264`, `VdpPictureInfoH264` and
    `VkVideoDecodeH264PictureInfoKHR`. Ported and cleaned up from
    `crates/oxideav-vdpau/src/h264.rs` (Round 3 seed).
  - `hevc` module: VPS / SPS / PPS and minimal slice-segment header
    parsers, plus `parse_idr_only`. Reduced syntax — refuses inputs
    that use scaling lists, PCM, SCC extensions, multiple short-term
    or long-term RPS, tiles or WPP.
  - `av1` module: leb128 reader, OBU walker (`parse_obu_stream`),
    sequence-header and frame-header parsers for KEY_FRAME-only
    streams. Refuses everything outside of the still-image / single
    keyframe envelope (no decoder model, no operating points beyond
    [0], no film grain).
- Tests:
  - `tests/h264_idr.rs` — baseline + high profile fixtures, asserts
    profile_idc, level_idc, coded width/height, slice_type=I, idr_pic_id=0.
  - `tests/hevc_idr.rs` — Main-profile fixture, asserts profile/level,
    pic_width/height_in_luma_samples, chroma_format=1, bit_depth=8.
  - `tests/av1_keyframe.rs` — aomenc-produced single keyframe OBU
    stream, asserts max_frame_width/height, profile, bit_depth,
    monochrome=0, frame_type=KEY_FRAME.
