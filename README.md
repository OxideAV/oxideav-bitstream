# oxideav-bitstream

[![CI](https://github.com/OxideAV/oxideav-bitstream/actions/workflows/ci.yml/badge.svg)](https://github.com/OxideAV/oxideav-bitstream/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/oxideav-bitstream.svg)](https://crates.io/crates/oxideav-bitstream) [![docs.rs](https://docs.rs/oxideav-bitstream/badge.svg)](https://docs.rs/oxideav-bitstream) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Minimal IDR / keyframe header parsing for H.264, HEVC and AV1, used by the
[oxideav](https://github.com/OxideAV/oxideav) framework's hardware-accel
bridge crates ([`oxideav-vaapi`](https://github.com/OxideAV/oxideav-vaapi),
[`oxideav-vdpau`](https://github.com/OxideAV/oxideav-vdpau),
[`oxideav-vulkan-video`](https://github.com/OxideAV/oxideav-vulkan-video))
to populate slice-data API parameter buffers.

## Why a parser-only crate?

VA-API, VDPAU and Vulkan Video all expect the host application to do
the **header parsing** itself and submit a fully-populated parameter
buffer (`VAPictureParameterBufferH264`, `VdpPictureInfoH264`,
`VkVideoDecodeH264PictureInfoKHR`, and the analogous structs for HEVC
and AV1). The GPU only handles the slice data once the parameters are
in hand.

That parser layer is universal across the three back-ends — the
underlying bitstream syntax is the same — but the *full* SW codec
crates (`oxideav-h264`, `oxideav-h265`, `oxideav-av1`) drag in DCT,
entropy decode, motion compensation and filtering. Linking those just
to recover a few dozen integer fields is wasteful.

So this crate exists to host the **minimal** parsing logic that all
three HW bridges share, without the SW-codec baggage.

## Scope

| | H.264 | HEVC | H.266 | AV1 |
| - | - | - | - | - |
| Annex-B / OBU framing | yes | yes | yes | yes (leb128 sizes, OBU walker + emitter) |
| NAL header decode | yes | yes | yes | n/a |
| Sequence header (SPS / VPS+SPS / Sequence-Header OBU) | **complete** — scaling lists (§7.3.2.1.1.1) + full VUI/HRD (Annex E) | **complete** — scaling lists (§7.3.4), PCM, ST-RPS w/ §7.4.8 inter-set derivation, LT-RPS, VUI/HRD (§E.2.1–E.2.3), range extension | structural VPS (7.3.2.3, single-layer) + SPS (7.3.2.4 + 7.3.3) | yes |
| Picture parameter set (PPS / Frame-Header OBU) | **complete** incl. scaling lists via `parse_pps_with_sps` | **complete** — tiles, WPP, scaling lists, range extension | structural PPS (7.3.2.5 prefix) + PH structural prefix (7.3.2.8) plus `parse_picture_header_with_sps` through `ph_recovery_poc_cnt` | yes |
| SPS/PPS **writers** (byte-exact parse→write inverses) | yes — pinned byte-exact on both fixtures | yes — VPS+SPS+PPS, pinned byte-exact on the fixture (lossless PTL / ST-RPS-coding / ordering-info retention) | deferred | n/a |
| SEI / metadata | framing (§7.3.2.3) + buffering_period / pic_timing / itu_t_t35 / user_data_unregistered / recovery_point (§D.1), writer included | deferred | deferred | metadata OBU §5.8 — HDR CLL/MDCV, scalability structure, ITU-T T.35, timecode; parse + write |
| Minimal slice header (IDR / I-slice / KEY_FRAME) | yes | yes | deferred | yes |
| Access unit delimiter (AUD) parse + write | yes (`primary_pic_type` u(3)) | yes (`pic_type` u(3), incl. reserved-value pass-through) | yes (`aud_irap_or_gdr_flag` u(1) + `aud_pic_type` u(3), incl. reserved-value pass-through) | n/a (OBU framing handles AU boundaries) |
| DCT, entropy decode, motion compensation, in-loop filtering | no | no | no | no |
| FMO / ASO / multiple slice groups | rejected | n/a | n/a | n/a |
| SCC / multilayer / 3D extension payloads | n/a | rejected (presence flags parse) | n/a | n/a |
| AV1 decoder model / operating points beyond [0] / film grain | n/a | n/a | n/a | rejected |

The crate refuses inputs that fall outside the supported envelope with
`BitstreamError::Unsupported(reason)` rather than silently producing
garbage parameter buffers, and enforces the specs' declared value
ranges (`delta_scale`, `cpb_cnt_minus1`, DPB sizes, RPS counts, …) so
hostile counts can never drive unbounded loops or oversized reads.

H.266 (VVC), VP9, VP8, MPEG-2 and VC-1 have landed as additional
modules; their scope is incremental — see each module's rustdoc for
what's parsed today versus deferred.

## Module layout

```
src/
├── lib.rs           # re-exports each codec module + BitstreamError
├── bit_reader.rs    # shared u(n) / u64(n) / ue(v) / se(v) / i(n) /
│                    # te(v) / ns(n) / su(n) / uvlc() / le(n) /
│                    # signed_magnitude(n) / read_bytes
│                    # reader, peek_bits / peek_bits_u64,
│                    # more_rbsp_data, read_rbsp_trailing_bits
├── bit_writer.rs    # MSB-first writer — inverse of bit_reader
│                    # (write_bits / write_ue / write_se / write_i /
│                    # write_te / write_ns / write_su / write_uvlc /
│                    # write_le / write_signed_magnitude / write_bytes)
├── nal.rs           # shared ebsp_to_rbsp + rbsp_to_ebsp (H.264 7.4.1.1 /
│                    # H.265 7.4.1.1 / H.266 7.3.1.1 +7.4.2.1)
├── h264.rs          # H.264 SPS / PPS / minimal slice header
│                    # (re-exports ebsp_to_rbsp from nal)
├── hevc.rs          # HEVC VPS / SPS / PPS / minimal slice header
│                    # (re-exports ebsp_to_rbsp from nal)
├── h266.rs          # H.266 Annex-B walker + NAL header + structural VPS / SPS /
│                    # PPS + picture-header structural prefix (7.3.2.8)
│                    # (re-exports ebsp_to_rbsp from nal)
├── h266/aps.rs      # H.266 adaptation parameter set (7.3.2.6) — ALF /
│                    # LMCS / scaling-list payloads, parse + byte-exact write
├── mpeg2.rs         # MPEG-2 sequence + picture + extension headers
├── vc1.rs           # VC-1 sequence + entry-point + picture header
├── vp8.rs           # VP8 keyframe header + IVF demuxer
├── vp9.rs           # VP9 uncompressed header
├── ivf.rs           # IVF demuxer + muxer (VP8 / VP9 / AV1 fixtures)
└── av1.rs           # AV1 leb128 reader+writer, OBU walker+emitter, key-frame headers
```

## NAL byte-framing helpers

`nal::ebsp_to_rbsp` strips `emulation_prevention_three_byte` (`0x03`)
bytes from an encapsulated byte sequence payload to recover the raw
byte sequence payload before bit-level parsing. `nal::rbsp_to_ebsp` is
its inverse — for encoders that build an RBSP through `BitWriter` and
need to frame it for the wire. The rule is identical for H.264, HEVC
and H.266, so the three codec modules re-export the shared
implementation rather than carrying private copies.

Round-trip contract: `ebsp_to_rbsp(&rbsp_to_ebsp(x)) == x` for any
byte slice `x`, including the trailing-zero guard case
(`x = [.., 0x00, 0x00]` → `[.., 0x00, 0x00, 0x03]` → `[.., 0x00, 0x00]`).

`nal` also converts between the two elementary-stream framings:
`annex_b_to_length_prefixed` / `length_prefixed_to_annex_b` /
`split_length_prefixed` re-frame Annex-B start-code streams to and
from the 1–4-byte big-endian length-prefixed form used by ISO
base-media sample framing, validating every declared length against
the actual bytes.

## Bit-IO descriptors

The shared `BitReader` / `BitWriter` cover every syntax descriptor the
VCL specs use. Each pair is an exact round-trip inverse:

| Descriptor          | Reader                          | Writer                            | Spec                           |
| ------------------- | ------------------------------- | --------------------------------- | ------------------------------ |
| `u(n)`              | `u(n)` / `u64(n)`               | `write_bits` / `write_bits_u64`   | H.264 §7.2                     |
| Look-ahead peek     | `peek_bits(n)` / `peek_bits_u64(n)` | (n/a — peek does not advance) | (helper)                       |
| `i(n)` 2's-complement signed | `i(n)`                  | `write_i`                         | H.264 §7.2 / H.265 §7.2        |
| `ue(v)` unsigned Exp-Golomb | `ue`                     | `write_ue`                        | H.264 §9.1                     |
| `se(v)` signed Exp-Golomb | `se`                       | `write_se`                        | H.264 §9.1.1                   |
| `te(v)` truncated Exp-Golomb | `te(x_max)`             | `write_te(value, x_max)`          | H.264 §9.1.2                   |
| `ns(n)` non-symmetric unsigned (AV1 tile sizes / film-grain) | `ns(n)` | `write_ns(value, n)` | AV1 §4.10.7 |
| `su(n)` signed integer from n bits (AV1 delta_q / global-motion) | `su(n)` | `write_su(value, n)` | AV1 §4.10.6 |
| `uvlc()` unsigned variable-length code, total over `u32` — saturates to `u32::MAX` at 32+ leading zeros instead of erroring like `ue(v)` (AV1 timing_info) | `uvlc()` | `write_uvlc(value)` | AV1 §4.10.3 |
| `le(n)` little-endian n-**byte** unsigned (AV1 tile sizes) | `le(n)` | `write_le(value, n)` | AV1 §4.10.4 |
| Signed magnitude (`n` bits + 1 sign) | `signed_magnitude(n)` | `write_signed_magnitude` | VP9 §6.2.7 + legacy headers    |
| Aligned byte slice  | `read_bytes(n)`                 | `write_bytes(&[u8])`              | (helper)                       |
| `rbsp_trailing_bits()` marker | `read_rbsp_trailing_bits` | `write_rbsp_trailing_bits`        | H.264 §7.3.2.11 / H.265 §7.3.2.11 / H.266 §7.3.10 |
| LEB128 (AV1)        | `av1::read_leb128`              | `av1::write_leb128`               | AV1 §4.10                      |
| EBSP ↔ RBSP byte stuffing | `nal::ebsp_to_rbsp`        | `nal::rbsp_to_ebsp`               | H.264 / H.265 §7.4.1.1, H.266 §7.3.1.1 + §7.4.2.1 |
| Annex-B / OBU framing | per-module                   | per-module                        | per-codec                      |

There is **no** cross-codec abstraction in v0. Each codec sub-module
exposes its own `parse_*` entry points and result structs, and a
convenience `parse_idr_only` (`parse_keyframe_only` for AV1) that
walks a complete Annex-B / OBU stream, finds the first
IDR / keyframe access unit, and returns the parsed parameters
plus a slice (or set of slices) of bytes the HW decoder consumes.

## Fuzzing

`fuzz/` holds two `cargo fuzz` panic-hardening targets. Because this
crate parses attacker-controlled bitstream bytes to populate GPU
parameter buffers, every entry point must return `Ok` / `Err` — never
panic, overflow, slice out of bounds, or loop unboundedly — on *any*
input.

- `reader` — hammers the foundational `BitReader` / `BitWriter`
  primitives (`u(n)` / `u64(n)` / `ue` / `se` / `ns` / `su` / `uvlc` /
  `le` / skips / peeks) plus the AV1 LEB128 / OBU walkers and the IVF
  demuxer, and fuzzes the writer→reader round-trip invariant.
- `parsers` — drives the per-codec header parsers (H.264 incl. SEI,
  HEVC, H.266, MPEG-2, VC-1, VP8, VP9, AV1 metadata, framing
  converters) at multiple input-derived byte offsets, feeds the
  context-dependent slice / picture / SEI / entry-point parsers an
  SPS / PPS / sequence-header context recovered from a prefix of the
  same input, and asserts the parse→write→parse fixed points (H.264
  SPS/PPS/SEI, AV1 metadata, length-prefixed framing) on every
  successful parse. It found a panic where a malformed H.264 / HEVC
  SPS with an out-of-range `log2_max_frame_num_minus4` /
  `log2_max_pic_order_cnt_lsb_minus4` drove a `>32`-bit `BitReader::u`
  read in the slice-header parser; the SPS parsers now reject those
  values per H.264 §7.4.2.1.1 / H.265 §7.4.3.2.1.

## No `unsafe`

This crate contains zero `unsafe` blocks. Bit reading is software,
no FFI involved.

## Workspace clean-room policy

The bitstream-syntax tables in this crate are written from the
relevant spec PDFs:

- ITU-T H.264 (a.k.a. ISO/IEC 14496-10 — AVC),
- ITU-T H.265 (a.k.a. ISO/IEC 23008-2 — HEVC),
- ITU-T H.266 (a.k.a. ISO/IEC 23090-3 — VVC),
- ITU-T H.262 (a.k.a. ISO/IEC 13818-2 — MPEG-2),
- SMPTE ST 421 (VC-1),
- AV1 Bitstream & Decoding Process Specification (av1.org),
- RFC 6386 (VP8 Data Format and Decoding Guide).

Following a public spec PDF is the canonical clean-room move and is
allowed under the workspace policy. No third-party codec source is
consulted; external encoders are used only as black-box CLI tools to
generate test fixtures.

## License

MIT.
