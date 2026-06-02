# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- H.266 / VVC picture-header structural-prefix parser (ITU-T H.266
  §7.3.2.7 / §7.3.2.8). New `parse_picture_header()` decodes a PH NAL
  body (`NAL_TYPE_PH`) through `ph_pic_parameter_set_id` — the always-
  present prefix a HW bridge needs to classify the picture for
  random-access entry-point selection:
  `ph_gdr_or_irap_pic_flag` u(1), `ph_non_ref_pic_flag` u(1),
  optional `ph_gdr_pic_flag` u(1), `ph_inter_slice_allowed_flag` u(1),
  optional `ph_intra_slice_allowed_flag` u(1) and
  `ph_pic_parameter_set_id` ue(v). Parsing stops there because the next
  field (`ph_pic_order_cnt_lsb`) is `u(v)` with a width derived from
  the active SPS (`sps_log2_max_pic_order_cnt_lsb_minus4 + 4` per
  §7.4.3.4 / §7.4.3.8) which a context-free parser cannot resolve
  yet — routing that SPS context through the parser is deferred to a
  later round. `ph_pic_parameter_set_id > 63` (above the
  `pps_pic_parameter_set_id` u(6) envelope from §7.4.3.5) returns
  `BitstreamError::InvalidData`. The result struct (`VvcPictureHeader`)
  exposes `is_irap()`, `is_gdr()` and `intra_slice_allowed()`
  convenience accessors that resolve the §7.4.3.8 inference rules
  (`ph_intra_slice_allowed_flag` is inferred to 1 when not signalled).
  A new public constant `PH_PIC_PARAMETER_SET_ID_MAX = 63` documents
  the validated envelope.
- Nine new h266 unit tests cover (a) an IRAP picture
  (`gdr_or_irap = 1`, `gdr_pic = 0`), (b) a GDR non-reference picture
  (`gdr_or_irap = 1`, `gdr_pic = 1`, `non_ref = 1`), (c) a non-IRAP
  inter-only picture (no `ph_gdr_pic_flag`, `intra = 0`), (d) a
  picture with `inter_allowed = 0` exercising the inferred-intra path,
  (e) wrong-NAL-type rejection, (f) truncated input, (g)
  oversized-`ph_pic_parameter_set_id` rejection, (h) emulation-
  prevention-byte stripping via `ebsp_to_rbsp` and (i) the 2x2x{1,2}x2x
  {1,2} Cartesian product of every legal signalled/inferred flag
  combination. Plus one new `tests/h266_nal_walker.rs` integration
  test walking a synthetic VPS + SPS + PPS + PH + IDR_W_RADL Annex-B
  access unit through `split_annex_b` → `parse_nal_header` →
  `parse_picture_header`.
- Two new `tests/roundtrip_props.rs` invariants: a 1152-path exhaustive
  sweep that crosses every signalled/inferred flag combination with
  every legal `ph_pic_parameter_set_id` (0..=63), and a boundary-
  rejection sweep across the 16 values immediately above the spec
  maximum.

- `BitReader::i(n)` — read `n` MSB-first bits and interpret as a two's
  complement signed integer (H.264 §7.2 / H.265 §7.2 / H.266 §7.2
  `i(n)` descriptor). Accepts widths in `1..=32`; the full-width case
  (`n == 32`) round-trips the entire `i32` range including `i32::MIN`
  and `i32::MAX`. Past-the-end bits remain zero per the reader's
  documented over-read contract.
- `BitWriter::write_i(value, n)` — exact inverse of the new reader.
  Refuses any value outside the representable
  `-(2^(n-1)) .. 2^(n-1) - 1` range (no silent truncation), so the
  round-trip contract is total for accepted inputs.
- `BitReader::signed_magnitude(n)` / `BitWriter::write_signed_magnitude`
  — read/write a signed value as `n` magnitude bits followed by a 1-bit
  sign (`1` = negative), the layout used by VP9's
  `loop_filter_ref_deltas` and a number of legacy headers. Widths in
  `1..=31`; canonical encoding of zero is sign=0, so a hand-crafted
  "negative zero" input decodes back to positive zero (the writer
  picks the canonical form on re-emission).
- `BitReader::te(x_max)` / `BitWriter::write_te(value, x_max)` —
  H.264 §9.1.2 truncated Exp-Golomb. When `x_max == 1` the code
  collapses to a single bit equal to `1 - value`; for larger `x_max`
  the helpers delegate to `ue` / `write_ue`. `x_max == 0` is rejected
  (no spec-defined code) and the writer additionally enforces
  `value <= x_max`.
- `BitReader::read_bytes(n)` / `BitWriter::write_bytes(bytes)` —
  byte-aligned slice helpers. Both reject unaligned positions with
  `InvalidData` and the reader returns `UnexpectedEnd` on a short
  buffer without advancing the cursor, so failures are recoverable.
- Five new property-style invariants in `roundtrip_props.rs` exercising
  every new helper: `i(n)` round-trip for every width 1..=32 (1500
  random values per width), the out-of-range rejection sweep for every
  width 1..=31, `signed_magnitude` round-trip for every width 1..=31
  (1500 random values per width) plus the negative-zero canonicalisation
  invariant, `te(v)` round-trip across a handful of representative
  `x_max` values, and the `read_bytes` / `write_bytes` round-trip with
  interleaved bit fields. Plus a dozen new unit tests in the
  `bit_reader` / `bit_writer` modules covering the boundary cases
  (full 8-bit enumeration of `i(n)` decoding, rejection paths, etc.).

- `av1::write_obu` — the inverse of `av1::read_obu`. Builds a
  fully-framed OBU (`obu_header [obu_extension_header] obu_size payload`)
  from an `ObuHeader` + payload byte slice and appends it to a
  caller-provided `Vec<u8>`, returning the `(start, end)` byte range
  covering the framed OBU. Round-trip contract: feeding `start` back
  through `read_obu` reproduces the same `ObuHeader`, a payload range
  whose length matches `payload.len()`, and `next_offset == end`. The
  emitter validates every spec-required bit-field width up-front (`obu_type`
  ≤ 15, `temporal_id` ≤ 7, `spatial_id` ≤ 3, payload size ≤
  `LEB128_MAX`) and refuses non-zero `temporal_id`/`spatial_id` paired
  with `extension_flag=0` (which the reader would silently zero), so
  the inverse pair is total. LOBF's `obu_has_size_field=1` requirement
  is enforced. Buffer is left untouched on rejection. Three new public
  width-bound constants (`OBU_TYPE_MAX`, `OBU_TEMPORAL_ID_MAX`,
  `OBU_SPATIAL_ID_MAX`) document the field widths. Ten new av1 unit
  tests cover the empty-TD canonical form, payload-size round-trips at
  the 1-byte / 2-byte size-field boundaries (0, 1, 16, 127, 128, 1024),
  the full Cartesian product of legal `(temporal_id, spatial_id)`
  pairs through the extension byte, append-without-clobber, every
  validation rejection path (size-field-clear, oversized `obu_type`,
  oversized `temporal_id`/`spatial_id`, non-zero IDs without extension
  flag), multi-byte leb128 size emission, the max-legal-IDs corner,
  and a two-OBU concatenation walk.
- Three new `roundtrip_props.rs` invariants exercising `write_obu`: a
  400-iteration random-payload round-trip against `read_obu` across all
  seven canonical OBU types and the LCG-shuffled extension-byte ID
  space; a validator that every documented rejection path returns
  `InvalidData` with the buffer untouched; and a 32-OBU concatenation
  that walks the entire synthetic temporal unit back through `read_obu`
  in lock-step, asserting the `next_offset` chain `parse_obu_stream`
  itself depends on.
- The `fuzz/reader.rs` target now hammers `write_obu` alongside the
  other writer surfaces — pulling shape bytes out of attacker input to
  drive `(obu_type, extension_flag, temporal_id, spatial_id,
  payload_len)`, asserting either `write_obu → read_obu == identity`
  on accepted inputs or a buffer-preserving clean error on rejected
  ones.

## [0.0.2](https://github.com/OxideAV/oxideav-bitstream/compare/v0.0.1...v0.0.2) - 2026-05-30

### Other

- write_leb128 — minimal-length encoder, inverse of read_leb128
- structural VPS parser (7.3.2.3, single-layer)
- peek_bits + more_rbsp_data + read_rbsp_trailing_bits
- add BitWriter + round-trip property suite + reader fuzz target; fix ue() shift-overflow panic
- structural PPS parser (7.3.2.5)
- structural SPS parser (7.3.2.4) + profile_tier_level (7.3.3)
- structural Annex-B NAL walker + 2-byte NAL header decoder
- sequence + entry-point + picture header parser (SMPTE 421M)
- lift sequence/picture/extension header parser from oxideav-vdpau
- lift uncompressed-header parser from oxideav-vdpau
- keyframe header parser + ivf demuxer
- extend PPS parser past entropy_coding_sync + add SPS num_long_term_ref_pics_sps

### Added

- `av1::write_leb128` — the inverse of `av1::read_leb128`. Appends the
  minimal-length unsigned LEB128 encoding (AV1 §4.10) of a `u64` to a
  caller-provided `Vec<u8>` and returns the number of bytes written. The
  AV1 reader is capped at 8 bytes (56 payload bits); the writer exposes
  that bound as a new public constant `av1::LEB128_MAX` and rejects any
  value above it with `BitstreamError::InvalidData` rather than silently
  truncating, so the round-trip contract is total: every value the
  writer accepts decodes back identically through `read_leb128`. Buffer
  is left untouched on rejection (a refused write does not append). Five
  new av1 unit tests cover the 1-byte / 2-byte / 3-byte size classes,
  the 2^56-1 maximum (eight-byte encoding `[0xff;7] || 0x7f`), the
  rejection paths at `LEB128_MAX + 1` and `u64::MAX`, append-without-
  clobber semantics, and a 16-value spot-check across all size-class
  boundaries plus their immediate neighbours.
- Three new `roundtrip_props.rs` invariants: `write_leb128` is an exact
  inverse of `read_leb128` over the canonical size-class edges + 5000
  random values masked into the 56-bit envelope (also asserting the
  encoded length matches the canonical `ceil(bits_needed/7)` minimal
  form, with a one-byte floor for `v == 0`); rejection of out-of-range
  values leaves the buffer unchanged; appending past an existing prefix
  preserves the prefix bytes and round-trips through `read_leb128` at
  the prefix's end offset.
- The `fuzz/reader.rs` target now hammers `write_leb128` alongside the
  reader surfaces — pulling 8-byte chunks out of attacker input,
  optionally masking into `LEB128_MAX`, and asserting either
  `write_leb128 → read_leb128 == identity` on accepted values or a
  buffer-preserving clean error on rejected ones.

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
