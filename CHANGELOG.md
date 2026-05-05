# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
