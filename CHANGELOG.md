# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- hevc: byte-exact VPS/SPS/PPS writers — `write_vps`/`write_vps_nal`,
  `write_sps`/`write_sps_nal` and `write_pps`/`write_pps_nal` are full
  inverses of the parsers (§7.3.2.1/§7.3.2.2.1/§7.3.2.3.1 +
  `rbsp_trailing_bits()`, canonical layer-0/TID-0 NAL headers,
  emulation-prevention encoding), pinned byte-exact against the
  reference fixture's parameter sets and against synthetic streams
  covering scaling lists, PCM, explicit + inter-predicted ST-RPS,
  long-term pics, VUI/HRD, tiles, the range extensions and
  cprms-inherited VPS HRD entries. Hand-built structs are validated
  structurally (gate-flag/`Option` consistency, list-length vs.
  declared-count checks, §7.4.8 re-derivation of inter-predicted RPS
  resolved vectors); unrepresentable inputs (`vps_extension_flag`,
  non-zero `sps/pps_extension_4bits`, multilayer/3D/SCC extensions)
  are refused as `Unsupported`.
- hevc: lossless parse retention backing the writers —
  `HevcProfileTierLevel` now keeps the 48 constraint/reserved bits,
  the inter-flag reserved run and every coded sub-layer profile/level
  entry (`HevcSubLayerPtl`/`HevcSubLayerProfile`); VPS/SPS keep the
  raw sub-layer ordering tables (`HevcSubLayerOrderingInfo`) and
  present flags; `HevcShortTermRps` records its raw §7.3.7 coding
  (`HevcStRpsCoding`); VPS entries keep `vps_reserved_0xffff_16bits`
  and per-entry `cprms_present_flag` (new `HevcVpsHrdEntry` replaces
  the `(idx, hrd)` tuple); SPS/PPS keep `*_extension_present_flag` +
  `*_extension_4bits`.

### Changed
- hevc: the per-sub-layer DPB cap (`max_dec_pic_buffering_minus1 ≤ 15`,
  §A.4.2) is now enforced on **every** coded VPS/SPS ordering-info
  entry, not just the highest sub-layer's.
- h264: complete SPS parse — scaling lists (§7.3.2.1.1.1 `scaling_list()`
  with `UseDefaultScalingMatrixFlag` and freeze-after-zero semantics) and
  full VUI/HRD (Annex E §E.1.1/§E.1.2: aspect ratio incl. Extended_SAR,
  overscan, video signal type + colour description, chroma loc, timing
  info, NAL/VCL HRD with CPB schedule entries, low-delay flag,
  pic_struct, bitstream restriction). New types `H264ScalingLists`,
  `H264Vui`, `H264HrdParameters`, `H264CpbEntry`; helpers
  `sample_aspect_ratio()` (Table E-1), `field_rate()`/`frame_rate()`
  (§E.2.1), `bit_rate()`/`cpb_size()` (§E.2.2).
- h264: PPS scaling lists via new `parse_pps_with_sps` /
  `parse_pps_nal_with_sps` (§7.3.2.2 list count depends on the active
  SPS `chroma_format_idc`); `parse_idr_only` feeds the SPS context
  through automatically.
- h264: hostile-input guards — `delta_scale` range (−128..=127,
  §7.4.2.1.1.1) and `cpb_cnt_minus1 ≤ 31` (§E.2.2) bound all loops.

- h264: SEI parsing — `h264::sei` module with §7.3.2.3/§7.3.2.3.1
  `sei_rbsp()`/`sei_message()` framing (0xFF run-length payloadType /
  payloadSize accumulation, declared-size-vs-actual-bytes validation)
  plus byte-exact framing writers (`write_sei_message` /
  `write_sei_rbsp`). Typed decoders: buffering_period (§D.1.2, HRD
  field widths from the active SPS), pic_timing (§D.1.3 incl. the full
  clock-timestamp ladder, NumClockTS per Table D-1, reserved
  pic_struct rejected), user_data_registered_itu_t_t35 (§D.1.6),
  user_data_unregistered (§D.1.7), recovery_point (§D.1.8); every
  other type surfaced raw per §D.2.1.

- h264: byte-exact SPS/PPS writers — `write_sps`/`write_sps_nal` and
  `write_pps`/`write_pps_nal` are full inverses of the parsers
  (§7.3.2.1.1 / §7.3.2.2 + `rbsp_trailing_bits()`, NAL wrapping with
  emulation-prevention insertion). parse→write reproduces both h264
  fixtures' SPS and PPS RBSP bytes exactly. Parser now also retains
  the POC-type-1 offset fields (`offset_for_non_ref_pic`,
  `offset_for_top_to_bottom_field`, `offsets_for_ref_frame`) and the
  coded scaling-list count, and bounds
  `num_ref_frames_in_pic_order_cnt_cycle` to 0..=255 (§7.4.2.1.1).
  PPS records `high_profile_tail_present` so the optional §7.3.2.2
  tail round-trips bit-for-bit.

- hevc: SPS/PPS walk driven to the extension flags — every former
  `Unsupported` refusal except SCC/multilayer/3D payloads now parses:
  scaling_list_data (§7.3.4 with §7.4.5 range checks), PCM block,
  short-term RPS with the full §7.4.8 inter-set-prediction derivation
  (7-59..7-71) resolved to `DeltaPocS0/S1` form, long-term RPS,
  VUI/HRD (§E.2.1/§E.2.2/§E.2.3 incl. sub-pic HRD fields and
  per-sub-layer CPB schedules), SPS/PPS range extensions
  (§7.3.2.2.2/§7.3.2.3.2), PPS tile grid + WPP. New types
  `HevcScalingListData`, `HevcShortTermRps`, `HevcVui`,
  `HevcHrdParameters`, `HevcCpbEntry`, `HevcTiles`,
  `Hevc{Sps,Pps}RangeExtension`, `HevcDefaultDisplayWindow`; helpers
  `sample_aspect_ratio()` (Table E.1), `picture_rate()` (§E.3.1),
  `num_negative_pics()`/`num_positive_pics()`/`num_delta_pocs()`
  (7-63/7-64/7-71).
- hevc: hostile-input bounds — `sps_max_dec_pic_buffering_minus1 ≤ 15`
  (§A.4.2 MaxDpbSize cap), `num_short_term_ref_pic_sets ≤ 64`,
  `num_long_term_ref_pics_sps ≤ 32` (§7.4.3.2.1), `cpb_cnt_minus1 ≤ 31`
  (§E.3.2), `chroma_qp_offset_list_len_minus1 ≤ 5` (§7.4.3.3.2),
  tile column/row counts checked against remaining payload bits.

- av1: metadata OBU family (§5.8) — `parse_metadata_obu` /
  `write_metadata_obu` covering HDR CLL (§5.8.3), HDR MDCV (§5.8.4),
  scalability incl. the full `scalability_structure()` (§5.8.5/§5.8.6,
  SCALABILITY_SS), ITU-T T.35 (§5.8.2 with the last-non-zero-byte
  trailing rule enforced both ways) and timecode (§5.8.7 ladder);
  reserved/user-private types surfaced raw per the §5.8.1 note. All
  five families round-trip through the writer, including end-to-end
  framing through `write_obu`/`read_obu`.

- nal: framing converters — `split_length_prefixed`,
  `annex_b_to_length_prefixed`, `length_prefixed_to_annex_b` re-frame
  elementary streams between Annex-B start-code form (ITU-T Annex B)
  and 1..4-byte big-endian length-prefixed form (ISO base-media
  sample framing) without touching NAL bodies. Declared lengths are
  validated against actual bytes; oversize NALs that cannot fit the
  prefix width are refused.

- hevc: SEI module (`hevc::sei`) — §7.3.5 `sei_message()` framing
  (prefix type 39 + suffix type 40 NALs both accepted) with byte-exact
  framing writers, plus typed decoders for ITU-T T.35 (§D.2.6),
  user_data_unregistered (§D.2.7), recovery_point (§D.2.8, signed
  `recovery_poc_cnt`), mastering_display_colour_volume (§D.2.28, type
  137) and content_light_level_info (§D.2.35, type 144); everything
  else surfaced raw per §D.3.1.
- fuzz: parsers target now drives H.264 SEI (context-free + SPS-coupled
  decode), HEVC SEI, AV1 metadata, and the framing converters at every
  prefix width, and asserts parse→write→parse fixed points (H.264
  SPS/PPS/SEI, HEVC SEI, AV1 metadata, length-prefixed framing) on
  every successful parse.

- hevc: VPS walk completed through `vps_extension_flag` (§7.3.2.1) —
  base-layer flags, sub-layer ordering info (DPB/reorder/latency,
  §A.4.2 cap enforced), `vps_max_layer_id` + layer-set inclusion
  bitmasks (`vps_num_layer_sets_minus1 ≤ 1023` enforced), timing info,
  and the HRD list with the §7.4.3.1 `cprms_present_flag == 0`
  common-info inheritance from the previous entry.

### Fixed
- hevc: fuzz-found panic — a hostile SPS with out-of-range coding-block
  log2 fields drove `1u32 << CtbLog2SizeY` past 31 in the
  slice-segment-address width computation (and silently truncated
  through the u8 struct fields). The SPS parser now rejects
  `CtbLog2SizeY` outside 4..=6 (§A.3 profile conformance) and the
  slice-header parser bounds the shift defensively for
  caller-constructed SPS structs.
- H.264 / HEVC SPS parsers now reject an out-of-range
  `log2_max_frame_num_minus4` (H.264) and
  `log2_max_pic_order_cnt_lsb_minus4` (H.264 / HEVC) with
  `InvalidData`. The respective specs (H.264 §7.4.2.1.1,
  H.265 §7.4.3.2.1) constrain both to `0..=12`, so the dependent
  `frame_num` / `pic_order_cnt_lsb` fields are at most 16 bits. A
  malformed SPS carrying a larger value previously slipped through SPS
  parsing and then drove `BitReader::u(n > 32)` inside
  `parse_slice_header_minimal`, panicking the host application on a
  hostile fixture. Both fields are now validated at the SPS parse site,
  mirroring the existing H.266 bound on
  `sps_log2_max_pic_order_cnt_lsb_minus4`. Found by the new `parsers`
  fuzz target.

### Added

- `parsers` fuzz target (`fuzz/fuzz_targets/parsers.rs`) — a second
  panic-hardening harness covering the per-codec header *parsers* (the
  layer above the `BitReader` / `BitWriter` primitives the `reader`
  target already hammers). It drives every context-free `parse_*` entry
  point of the H.264, HEVC, H.266, MPEG-2, VC-1, VP8 and VP9 modules at
  several input-derived byte offsets, and feeds the context-dependent
  slice / picture / entry-point parsers an SPS / PPS / sequence-header
  context recovered from a prefix of the same input. The invariant under
  test is purely "no panic, no overflow, no out-of-bounds, no unbounded
  loop on any byte sequence." It immediately surfaced the SPS-width
  panic fixed above.

- `BitReader::uvlc()` and `BitWriter::write_uvlc(value)` — AV1 §4.10.3
  unsigned variable-length code, completing the §4.10 descriptor family
  alongside the `le(n)` sibling below, `leb128` (§4.10.5), `su(n)`
  (§4.10.6) and `ns(n)` (§4.10.7). Below `u32::MAX` the bit layout
  coincides with the H.26x `ue(v)` Exp-Golomb code, but the descriptors
  diverge at the top of the range: `ue(v)` rejects 32+ leading zeros as
  a syntax error while `uvlc()` *saturates* to `u32::MAX`, consuming
  the zero run through its terminating `1` bit and reading no suffix.
  Both directions are therefore total — every `u32` encodes (the
  saturation code is 32 zeros + the done bit, 33 bits) and every input
  decodes, so neither side returns a `Result`. This promotes the
  private `read_uvlc` helper previously buried in `av1.rs` (used by
  `timing_info()`'s `num_ticks_per_picture_minus_1`) to the shared
  descriptor surface, and fixes a positional divergence from the spec
  in that helper: it stopped after the 32nd leading zero, whereas
  §4.10.3 keeps consuming the run through the terminating bit — on a
  (hypothetical) stream with a 33+-zero run every subsequent field
  would have been misread. The shared reader follows the spec loop
  exactly; a dedicated test pins the post-saturation bit position with
  a sentinel field packed directly behind a 40-zero run.

- `BitReader::le(n)` and `BitWriter::write_le(value, n)` — AV1 §4.10.4
  unsigned little-endian `n`-**byte** number (the descriptor AV1 uses
  for byte-aligned tile-size fields, `tile_size_minus_1` coded as
  `le(TileSizeBytes)`). `n` counts bytes, not bits, and is capped at 8
  so the result fits a `u64`; `n == 0` is the trivial zero-bit read.
  The implementation is the spec's literal composition of `f(8)` reads
  assembled least-significant-byte first, so it is position-agnostic
  (the spec only employs it byte-aligned; callers wanting strictness
  can assert `byte_aligned()` first). The writer rejects `n > 8` and
  any value that does not fit in `n` bytes, with nothing appended on
  rejection.

  Test delta for the pair: 9 reader + 6 writer unit tests (known-value
  tables, the §4.10.3 saturation + long-run positional pins,
  end-of-stream run termination, little-endian assembly, unaligned
  `f(8)`-composition equivalence, past-the-end zero padding, rejection
  paths), 6 new `roundtrip_props.rs` invariants (uvlc round-trip over
  boundary + random values, uvlc/ue bit-layout agreement below
  saturation in both encode directions, the 33-bit saturation-code
  position, `le` round-trips across every width × bit offset, `le` vs
  `read_bytes` little-endian agreement, writer rejection hygiene), and
  the reader fuzz harness now drives `uvlc()` / `le(n)` on attacker
  bytes every opcode-tape iteration plus a structured `uvlc`+`le`
  writer→reader round-trip stage.

- `BitReader::su(n)` and `BitWriter::write_su(value, n)` — AV1 §4.10.6
  signed integer descriptor. Reads `n` bits as an unsigned `f(n)` value,
  then reinterprets the top bit as a sign per the spec arithmetic
  (`signMask = 1 << (n - 1); if (value & signMask) value -= 2 * signMask`)
  — two's-complement sign extension of an `n`-bit field. This is the same
  numeric mapping as the H.26x `i(n)` descriptor but is surfaced
  separately so AV1 parsers can cite §4.10.6 directly; AV1 uses it for
  `delta_q = su(1 + 6)` (§5.9.13) and the global-motion parameter reads
  (§5.9.24). Accepts widths `1..=32`; `n == 32` round-trips the full
  `i32` range including `i32::MIN`/`i32::MAX`. The reader rejects
  `n == 0` (the `signMask` shift is undefined for a zero-bit signed
  field) and `n > 32`; the writer rejects the same widths plus any value
  outside the representable `-(2^(n-1)) .. 2^(n-1) - 1` range (no silent
  truncation, so the round-trip is total for accepted inputs).

  Five new reader unit tests pin the spec's two's-complement decode for
  every raw pattern at widths `1..=8`, the §4.10.6 arithmetic example
  (`su(4)` of `0b1011` → `-5`), the full-width-32 `i32` endpoints, the
  `n == 1` `{0, -1}` alphabet, and the `n == 0` / `n > 32` rejections.
  Six new writer unit tests mirror the full `i8` round-trip, the spec
  example inverse (`-5` → `0b1011`), out-of-range and zero/oversize-width
  rejections, the full-`i32`-at-width-32 round-trip, and an exhaustive
  `1..=16` × full-range round-trip through the writer/reader pair. Three
  new `roundtrip_props.rs` invariants extend that to a 1500-value random
  round-trip per width `1..=32`, a per-width out-of-range rejection
  sweep, and a cross-check that `su(n)` and `i(n)` agree numerically at
  every bit offset for widths up to 24 (so a future divergence in either
  decoder is caught). The reader fuzz harness now also drives `su(n)` on
  attacker bytes every opcode-tape iteration and adds a structured
  `write_su` → `su` round-trip on attacker-derived `(value, n)` pairs.

- `BitReader::ns(n)` and `BitWriter::write_ns(value, n)` — AV1 §4.10.7
  non-symmetric unsigned integer descriptor. Outputs values in range
  `0..n`, emitting `FloorLog2(n)` bits for the lower part of the range
  and `FloorLog2(n) + 1` bits for the upper part. Used by the AV1
  syntax for tile sizes (`width_in_sbs_minus_1`, `height_in_sbs_minus_1`)
  and film-grain `subexp_final_bits` (§5.9.15 / §5.9.30). The reader
  rejects `n == 0` (the spec only defines `ns(n)` for `n >= 1`), caps
  `n` at `1 << 30` so the internal arithmetic always fits in `u32`,
  and short-circuits `n == 1` to return 0 without consuming any bits
  (the trivial single-value alphabet). The writer enforces
  `value < n`, the same `n == 0` and envelope rejections, and the
  same zero-bit emission for `n == 1`. Powers of two are handled per
  the spec (`w = FloorLog2(n) + 1` keeps a redundant high bit;
  decoders that compute `w` from `n - 1` would otherwise undershoot
  by one — patched explicitly).

  Six new in-module reader unit tests pin the spec's `n = 5` byte
  layout (codes `00, 01, 10, 110, 111`), confirm `n == 1` consumes
  zero bits, exercise the power-of-two branch on `n = 4`, walk the
  `n = 3` two-bit-for-everyone-but-zero pattern, and reject `n == 0`
  / `n` above the supported envelope. Five new writer unit tests
  mirror the reader's spec-table pinning, the zero-bit emission for
  `n == 1`, rejection of `value >= n`, rejection of `n == 0` and
  oversized `n`, and an exhaustive `1..=33` × `0..n` round-trip
  through the writer/reader pair. Four new `roundtrip_props.rs`
  invariants extend that to `n` up to 257 exhaustively (spanning the
  power-of-two boundary at 256), a 600-pair mixed-`n` packing test
  that catches alignment bugs the per-value tests miss, a check that
  `ns(1)` is invisible when sandwiched between two `u(8)` fields,
  and the writer's rejection-paths-leave-buffer-clean contract. The
  reader fuzz harness now also drives `ns(n)` on attacker bytes
  every opcode-tape iteration and adds a structured `write_ns` →
  `ns` round-trip on attacker-derived `(value, n)` pairs.

- `BitReader::peek_bits_u64(n)` — 64-bit counterpart of the existing
  `peek_bits`, symmetric with `BitReader::u64`. Inspects up to 64 bits
  ahead of the current `bit_pos` without advancing it, with the same
  past-the-end "zero bits" contract as `u64`. Borrows the reader
  `&self` so callers can peek without losing other borrows. Useful for
  parsers that need to inspect a wide marker (e.g. AV1's
  `reference_frame_id` u(v) class fields up to 16 bits, leb128-aware
  look-aheads on a 64-bit horizon) before deciding whether to commit
  to a branch. Five new in-module unit tests cover the bit-zero case
  matching `u64(64)`, every (offset, width) pair on a 16-byte buffer
  for widths 0..=64, past-end zero-padding (both fully past-end and
  partial straddle), agreement with `peek_bits` for widths up to 32,
  and the width-zero no-op. Three new `roundtrip_props.rs` invariants
  exercise the new primitive: a 120-iteration randomised
  every-offset-every-width parity check against `u64` (asserting
  `peek_bits` agreement for n ≤ 32 and the past-end-low-bits-zero
  contract), an empty-reader panic-hardening assertion across all
  widths 0..=64, and a 400-iteration writer ↔ peek round-trip across
  random `(value, width)` field sequences. The reader fuzz harness's
  opcode tape now also calls `peek_bits_u64` on every iteration so
  attacker bytes exercise the new surface.

- Access unit delimiter (AUD) parse + write for H.264, HEVC and H.266.
  Each codec module now exposes a public NAL-level entry point and its
  inverse:
  - `h264::parse_aud_nal` / `h264::write_aud_nal` (§7.3.2.4 /
    §7.4.2.4): surfaces the 3-bit `primary_pic_type` and verifies the
    `rbsp_trailing_bits()` marker. The writer accepts the full u(3)
    envelope (0..=7) and rejects oversized values as
    [`BitstreamError::InvalidData`]. Constant
    `H264_PRIMARY_PIC_TYPE_MAX = 7` documents the envelope.
  - `hevc::parse_aud_nal` / `hevc::write_aud_nal` (§7.3.2.5 /
    §7.4.3.5): surfaces the 3-bit `pic_type` field on a
    two-byte-NAL-header AUD. Per the H.265 spec's
    "Decoders … shall ignore reserved values" clause, the parser
    accepts the full u(3) range (0..=7) — including the reserved
    values 3..=7 — and returns them verbatim. The writer mirrors the
    same envelope so reserved values round-trip. Three documented
    `pic_type` constants (`HEVC_PIC_TYPE_I_ONLY = 0`,
    `HEVC_PIC_TYPE_P_OR_I = 1`, `HEVC_PIC_TYPE_B_P_OR_I = 2`) plus
    `HEVC_PIC_TYPE_MAX = 7`.
  - `h266::parse_aud` / `h266::write_aud` (§7.3.2.10 / §7.4.3.10):
    surfaces both `aud_irap_or_gdr_flag` u(1) and `aud_pic_type` u(3)
    on a `VvcAccessUnitDelimiter` struct. Same reserved-value contract
    as HEVC: 3..=7 round-trip unchanged. Writer rejects fields
    outside their u(1) / u(3) envelopes as
    [`BitstreamError::InvalidData`]. Constants `AUD_PIC_TYPE_I_ONLY`,
    `AUD_PIC_TYPE_P_OR_I`, `AUD_PIC_TYPE_B_P_OR_I` and
    `AUD_PIC_TYPE_MAX = 7` document the envelope.

  Each writer emits the canonical NAL header (H.264: `nal_ref_idc = 0`
  / type 9; HEVC: `layer_id = 0` / `tid_plus1 = 1` / type 35; H.266:
  `layer_id = 0` / `tid_plus1 = 1` / type 20) followed by a 1-byte
  RBSP packing the signalled field(s) plus the `rbsp_trailing_bits()`
  marker. The single-byte RBSP cannot trigger the
  `0x00 0x00 0x0{0..3}` start-code-emulation triple, so the encoded
  EBSP is byte-identical to the RBSP and no
  emulation-prevention stuffing is required.

  Twenty-five new in-module AUD tests cover the round-trip across
  every u(3) value, the canonical byte layout for representative
  inputs, reserved-value pass-through (HEVC + H.266), out-of-range
  field rejection on the writer side, wrong-NAL-type rejection,
  truncated-input rejection, header-only-NAL rejection, and
  missing-stop-bit rejection. Five new `roundtrip_props.rs`
  invariants exercise the writer / parser pair across the full u(3)
  range for each codec (with `0..=255` oversized-value rejection on
  the writer side), and pin the exact emitted byte layout for three
  representative inputs (one per codec).

- `BitWriter::write_rbsp_trailing_bits()` — the exact inverse of
  [`BitReader::read_rbsp_trailing_bits`]. Writes a single
  `rbsp_stop_one_bit` (= 1) followed by enough `alignment_zero_bit`
  values to push the bit cursor to the next byte boundary. Three new
  `bit_writer` unit tests cover the byte-boundary canonical case
  (writer at bit 0 -> emits `0x80`), the
  start-at-every-bit-position-then-reader-accepts-marker invariant
  (`prefix_bits ∈ 0..8`), and the seven-payload-bits-fill-one-byte
  case (`0xff` is a valid AUD RBSP). The H.264, HEVC and H.266 AUD
  writers above use this helper to terminate their 1-byte RBSPs.

- IVF muxer (`ivf::write_header`, `ivf::write_frame`, `ivf::write_all`)
  — the inverse of the existing demuxer (`parse_header`, `parse_frame`,
  `parse_all`). `write_header` emits a 32-byte `DKIF` global header
  exactly matching the reader's strict fixed-byte checks (version = 0
  LE u16, `header_len` = 32 LE u16, zeroed reserved tail). `write_frame`
  appends a 12-byte per-frame header (LE u32 size + LE u64 timestamp)
  followed by the payload bytes. `write_all` is a convenience that
  emits the global header plus an iterator of `(timestamp, payload)`
  frames in one allocation. Each writer returns the
  `(start, end)` byte range covering the appended block so callers
  composing a larger container can locate the new bytes. `write_frame`
  validates `payload.len() <= IVF_FRAME_PAYLOAD_MAX` (the u32 wire
  envelope) and `write_all` does the same pre-flight sweep across every
  frame, leaving the output buffer untouched on rejection — mirroring
  the rejection contract on `av1::write_obu` / `av1::write_leb128`.
  Three new public byte-length constants document the wire-format
  envelope: `IVF_HEADER_LEN = 32`, `IVF_FRAME_HEADER_LEN = 12`,
  `IVF_FRAME_PAYLOAD_MAX = u32::MAX as usize`. Ten new `ivf` unit
  tests cover the lone-header round-trip, prefix-preserving append,
  reserved-tail zeroing, single-frame and empty-payload round-trips,
  multi-frame `write_all` ↔ `parse_all`, the empty-frame-list case,
  documented byte-offset placement, in-order concatenation of two
  frames, and the boundary constant pinning. Five new
  `roundtrip_props.rs` invariants exercise the writer: a 5000-iteration
  randomised global-header round-trip across four FourCCs and every
  u16/u32 field width, a 2000-iteration frame round-trip with payload
  lengths in 0..=4096, a 200-stream multi-frame `write_all`
  round-trip with 0..=16 frames per stream and per-frame payload
  lengths up to 255 bytes, a 200-iteration "returned-range locates
  appended block" check on top of a hand-written prefix, and a
  fixed-byte-layout pin that matches the reader's strict checks.
  The `fuzz/reader.rs` target now also (a) calls `parse_header`,
  `parse_frame` and `parse_all` on attacker bytes (panic-hardening),
  and (b) drives `write_all` + an incremental `write_header` +
  `write_frame` sequence from attacker-derived fields and asserts the
  two paths produce byte-identical output that `parse_all` recovers.

- New `nal` module hosting the shared
  `emulation_prevention_three_byte` (`0x03`) byte-level helpers used by
  every NAL-framed codec in the crate. `nal::ebsp_to_rbsp` (the
  stripper) is identical to the byte-identical copies previously
  carried by `h264`, `hevc` and `h266`; those three modules now
  re-export the shared definition so a future drift can no longer
  affect just one codec. `nal::rbsp_to_ebsp` is the inverse — the
  encoder-side inserter that takes an RBSP built through `BitWriter`
  and emits a wire-framed EBSP. It escapes every `0x00 0x00 X` triple
  with `X ∈ {0x00, 0x01, 0x02, 0x03}` per ITU-T H.264 §7.4.1.1 /
  H.265 §7.4.1.1 / H.266 §7.4.2.1, and appends the trailing escape
  guard the spec mandates when the RBSP ends on a `0x00 0x00`
  suffix. Eleven new `nal` unit tests cover canonical triple
  stripping, every escaped third-byte value (0x00..=0x03), the
  unescaped third-byte boundary at 0x04, longer interior zero runs
  whose escapes overlap, the trailing-zero-guard round-trip, the
  unaffected-bytes pass-through, and the empty-input identity. Three
  new `roundtrip_props.rs` invariants: a 11-length × 200-iteration
  random RBSP round-trip through the inverse pair plus 14
  hand-constructed edge cases (empty, lone `0x00`, three-zero clusters,
  the all-zeros sequence at lengths 8 and 9, interior triple-zero
  windows); a "no forbidden window" scan asserting the framed EBSP
  contains no `0x00 0x00 0x00` or `0x00 0x00 0x01` triple at any
  offset; and a re-export identity check that the three codec
  modules' `ebsp_to_rbsp` produce byte-identical output to the shared
  `nal::ebsp_to_rbsp` on a representative fixture.

### Changed

- `h264::ebsp_to_rbsp`, `hevc::ebsp_to_rbsp` and `h266::ebsp_to_rbsp`
  are now `pub use` re-exports of `nal::ebsp_to_rbsp`. Behaviour is
  bit-identical to the previous private copies (which were already
  byte-equivalent across the three modules); the function signature
  is unchanged so every existing caller (`tests/h264_idr.rs`,
  `h264::parse_sps_nal`, `hevc::parse_sps_nal`, the H.266 SPS / PPS /
  picture-header routes, etc.) continues to type-check without
  modification. The module-level rustdoc on each codec now points at
  the shared helper.

- H.266 / VVC SPS parser extended past `sps_bitdepth_minus8` (ITU-T
  H.266 §7.3.2.4). Three new structural fields are surfaced on
  `VvcSps`: `sps_entropy_coding_sync_enabled_flag` u(1) (the WPP
  enable HW bridges need for the per-picture VA-API / Vulkan
  parameter), `sps_entry_point_offsets_present_flag` u(1), and
  `sps_log2_max_pic_order_cnt_lsb_minus4` u(4). The new field drives
  the bit-width of `ph_pic_order_cnt_lsb` (7.3.2.8) via
  `MaxPicOrderCntLsb = 1 << (sps_log2_max_pic_order_cnt_lsb_minus4 +
  4)`, surfaced as the `VvcSps::poc_lsb_width()` and
  `VvcSps::max_pic_order_cnt_lsb()` convenience accessors plus a new
  public constant `SPS_LOG2_MAX_PIC_ORDER_CNT_LSB_MINUS4_MAX = 12`
  (the spec envelope dictated by `MaxPicOrderCntLsb ≤ 2^16`). Values
  outside `0..=12` return `BitstreamError::InvalidData`.
- H.266 / VVC SPS-context picture-header parser
  `parse_picture_header_with_sps(nal_body, &VvcSps)` (ITU-T H.266
  §7.3.2.8). Extends the context-free `parse_picture_header()` by
  threading the active SPS through, so the parser can resolve the
  `ph_pic_order_cnt_lsb` u(v) width (from
  `sps_log2_max_pic_order_cnt_lsb_minus4 + 4`) and decode that field
  plus the conditional `ph_recovery_poc_cnt` ue(v) that follows when
  `ph_gdr_pic_flag = 1`. Two new optional fields on `VvcPictureHeader`
  surface those values (`ph_pic_order_cnt_lsb: Option<u32>`,
  `ph_recovery_poc_cnt: Option<u32>`); both are `Some(_)` only on the
  SPS-context path and `None` on the context-free
  `parse_picture_header()` path. Everything past
  `ph_recovery_poc_cnt` (the `NumExtraPhBits` array, the
  `sps_poc_msb_cycle_flag` block, every ALF / LMCS / scaling-list /
  virtual-boundary / RPL / partition-constraint / deblocking /
  QP-delta sub-block gated on later `sps_*` / `pps_*` flags) stays
  out of scope.
- Nine new h266 unit tests cover (a) IRAP picture with 4-bit POC LSB
  decoding through the SPS context, (b) a GDR picture exercising the
  `ph_recovery_poc_cnt` path with an 8-bit POC LSB, (c) a non-IRAP
  picture with `inter_allowed = 0` confirming the inferred-intra
  branch survives the SPS-context route, (d) a 16-bit POC LSB at the
  spec maximum (`sps_log2_max_pic_order_cnt_lsb_minus4 = 12`,
  `poc_lsb = 0xffff`), (e) wrong-NAL-type rejection on
  `parse_picture_header_with_sps`, (f) truncated input rejection on
  the SPS-context entry, (g) oversized-`ph_pic_parameter_set_id`
  rejection through the same entry, (h) the new SPS envelope check
  (`sps_log2_max_pic_order_cnt_lsb_minus4 = 13` → InvalidData) using
  the existing 1080p fixture with one byte rewritten, and (i) an
  independent SPS round-trip through `BitWriter` that asserts the
  three new fields decode to their written values. Plus one new
  `tests/h266_nal_walker.rs` integration test driving a synthetic
  Annex-B VPS + SPS + PPS + PH + IDR_W_RADL AU end-to-end through
  `split_annex_b` → `parse_nal_header` → `parse_sps` →
  `parse_picture_header_with_sps` and asserting the recovered
  `ph_pic_order_cnt_lsb`.
- One new `tests/roundtrip_props.rs` invariant: a 1092-path
  exhaustive sweep that drives `parse_picture_header_with_sps`
  through every legal POC LSB width
  (`sps_log2_max_pic_order_cnt_lsb_minus4 = 0..=12`) with both an
  IRAP and a GDR picture per width, exercising endpoint values
  (`0` and `2^width - 1`) and 40 random mid-range values per width.

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
  - `tests/av1_keyframe.rs` — reference-encoder-produced single keyframe OBU
    stream, asserts max_frame_width/height, profile, bit_depth,
    monochrome=0, frame_type=KEY_FRAME.
