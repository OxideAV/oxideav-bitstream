# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- H.266 / VVC structural VPS parser (ITU-T H.266 (V4) (01/2026) §7.3.2.3).
  New `parse_vps()` decodes the fixed-prefix fields a HW bridge needs:
  `vps_video_parameter_set_id` u(4), `vps_max_layers_minus1` u(6),
  `vps_max_sublayers_minus1` u(3), and the per-layer `vps_layer_id[i]`
  u(6) array. The inter-layer dependency block, OLS configuration,
  per-OLS PTL array, DPB and HRD parameter blocks, and the extension
  flag are out of scope for this round — multi-layer VPSs
  (`vps_max_layers_minus1 > 0`) return `BitstreamError::Unsupported`
  so HW bridges fall back to a software path, and
  `vps_max_sublayers_minus1 > 6` (out of §7.4.3.3 range) returns
  `BitstreamError::InvalidData`. Seven new lib tests (minimal
  single-layer fixture, single-layer with sublayers + non-zero
  `vps_layer_id`, multi-layer Unsupported, out-of-range
  sublayer-count InvalidData, wrong-NAL-type, truncated, and a
  `BitWriter`-built round-trip fixture) plus one new integration
  test walking a synthetic Annex-B VPS + SPS + IDR_W_RADL AU through
  `split_annex_b` + `parse_vps`.

- `bit_reader::BitReader::peek_bits(n)` — read `n` bits MSB-first
  without advancing `bit_pos`, same past-the-end zero-fill contract as
  `u(n)`. Lets codec parsers inspect a marker bit (e.g. an Annex-B
  start-code prefix candidate or an OBU continuation indicator) before
  committing to a branch.
- `bit_reader::BitReader::more_rbsp_data()` — ITU-T H.264 §7.2 /
  H.265 §7.2 / H.266 §7.2 `more_rbsp_data()` lifted from a private
  function inside `h264.rs` to a first-class `BitReader` method. The
  in-crate `h264::parse_pps` callsite now goes through the public API
  instead of reaching at `pub(crate)` `bytes` / `bit_pos` fields, and
  HEVC / H.266 RBSP-shaped parsers can use the same primitive without
  duplicating the scan.
- `bit_reader::BitReader::read_rbsp_trailing_bits()` — ITU-T H.264
  §7.3.2.11 / H.265 §7.3.2.11 / H.266 §7.3.10 `rbsp_trailing_bits()`.
  Consumes the `rbsp_stop_one_bit` and asserts every
  `alignment_zero_bit` up to the next byte boundary is `0`, returning a
  precise `InvalidData` / `UnexpectedEnd` on a malformed marker. Pairs
  with `more_rbsp_data()` so a parser that wants strict marker
  validation no longer needs an ad-hoc per-codec implementation.
- Eleven unit tests on the three new methods (peek non-advancement,
  past-end zero padding, minimal stop-byte case, payload-then-marker
  flow, every malformed-marker error path) plus three new
  `roundtrip_props.rs` invariants: `peek_bits` agrees with `u` at every
  start offset for every width 0..=32 over many random buffers,
  `rbsp_trailing_bits()` round-trips against `BitWriter` for every
  payload length 0..=23, and `more_rbsp_data` flips from `true` to
  `false` exactly as the payload is consumed.
- The `fuzz/reader.rs` target now hammers `peek_bits`,
  `more_rbsp_data`, and `read_rbsp_trailing_bits` on attacker bytes so
  the foundational reader surface stays panic-free end-to-end.

### Changed

- `h264::parse_pps` no longer carries its own `more_rbsp_data` helper
  that reached at `BitReader::bytes` / `bit_pos` through
  `pub(crate)` visibility; it now calls the public method on the
  reader. Behaviour is identical (the helper was lifted verbatim into
  the reader), but the codec module no longer needs internal-visibility
  access to its bit-IO dependency.

- `bit_writer::BitWriter` — an MSB-first bit writer that is the exact
  algebraic inverse of `bit_reader::BitReader`. Provides `write_bit`,
  `write_bits(u32, n)`, `write_bits_u64(u64, n)`, `write_ue`,
  `write_se`, `align_to_byte`, `finish`/`as_bytes`. A value written at
  bit offset `p` and read back at the same offset round-trips exactly,
  so codec parsers can now re-emit the fields they parse without an
  ad-hoc per-crate packer. `write_ue` rejects `u32::MAX` (no
  representable code); `write_se` rejects magnitudes that overflow the
  `2·|v|` mapping.
- `tests/roundtrip_props.rs` — a dependency-free property/invariant
  suite (deterministic LCG, fixed seeds) that exercises the foundational
  primitives across their full ranges: `write_bits` → `u` for every
  width 1..=32, `write_bits_u64` → `u64` for 1..=64, `ue`/`se` exact
  inverses, mixed-field concatenation with no inter-field bleed,
  byte-alignment symmetry between writer and reader, over-read past EOF
  yielding zero and never panicking, `ue` over a malformed all-zero run
  returning a clean `Err` (not a panic), and `read_leb128` round-trips
  against a local LEB128 encoder plus truncated/offset-past-end clean
  errors.
- `fuzz/` cargo-fuzz crate with a `reader` target that drives
  `BitReader` through an input-controlled opcode tape (reading far past
  EOF), runs `read_leb128` at every offset and `parse_obu_stream` over
  raw bytes, and asserts the `BitWriter` → `BitReader` round-trip on a
  structured view of the input. None of the surfaces may panic.

### Fixed

- `bit_reader::BitReader::ue` could panic with "attempt to shift left
  with overflow" on a 32-bit all-zero (or otherwise zero-padded) buffer:
  the leading-zero loop exited via end-of-stream with `leading_zeros ==
  32`, and the `1u32 << leading_zeros` term overflowed. The guard is now
  `>= 32` (the largest representable `ue(v)` value is `u32::MAX - 1`, at
  31 leading zeros) and the end-of-stream exit path is checked too, so a
  32-or-more-leading-zero code returns `BitstreamError::InvalidData`
  rather than panicking. Found by the new property suite.

- H.266 / VVC PPS structural parse (ITU-T H.266 (V4) (01/2026) §7.3.2.5).
  New `parse_pps()` decodes the fixed-prefix fields a HW bridge needs:
  `pps_pic_parameter_set_id`, `pps_seq_parameter_set_id`,
  `pps_mixed_nalu_types_in_pic_flag`, `pps_pic_width_in_luma_samples`,
  `pps_pic_height_in_luma_samples`, `pps_conformance_window_flag` plus
  the four optional `pps_conf_win_*_offset` ue(v) values,
  `pps_scaling_window_explicit_signalling_flag` plus the four optional
  signed `pps_scaling_win_*_offset` se(v) values,
  `pps_output_flag_present_flag`, `pps_no_pic_partition_flag`, and
  `pps_subpic_id_mapping_present_flag`. Parsing stops there — the
  remaining tile / slice partitioning, cabac, weighted-pred and
  deblocking blocks are deferred to later rounds. Five new lib tests
  cover the 64×32 minimal fixture, a 1920×1080 fixture with both
  conformance + scaling windows at zero offsets, a 320×240 fixture
  with signed scaling-window offsets `(1, -2, 3, -4)` and
  `pps_subpic_id_mapping_present_flag = 1`, plus truncated /
  wrong-NAL-type negative cases. One new integration test walks an
  Annex-B VPS + SPS + PPS + IDR_W_RADL AU end-to-end through
  `split_annex_b` + `parse_pps`.
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
