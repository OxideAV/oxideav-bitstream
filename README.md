# oxideav-bitstream

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
| Annex-B / OBU framing | yes | yes | yes | yes (leb128 sizes) |
| NAL header decode | yes | yes | yes | n/a |
| Sequence header (SPS / VPS+SPS / Sequence-Header OBU) | yes | yes | structural VPS (7.3.2.3, single-layer) + SPS (7.3.2.4 + 7.3.3) | yes |
| Picture header (PPS / Frame-Header OBU) | yes | yes | structural PPS (7.3.2.5 prefix) + PH structural prefix (7.3.2.7 / 7.3.2.8 through `ph_pic_parameter_set_id`) plus an SPS-context variant (`parse_picture_header_with_sps`) that extends through `ph_pic_order_cnt_lsb` u(v) and `ph_recovery_poc_cnt` ue(v) | yes |
| Minimal slice header (IDR / I-slice / KEY_FRAME) | yes | yes | deferred | yes |
| DCT, entropy decode, motion compensation, in-loop filtering | no | no | no | no |
| Scaling lists | rejected | rejected | n/a | n/a |
| FMO / ASO / multiple slice groups | rejected | n/a | n/a | n/a |
| Tiles / WPP | n/a | rejected | n/a | n/a |
| AV1 decoder model / operating points beyond [0] / film grain | n/a | n/a | n/a | rejected |

The crate refuses inputs that fall outside the supported envelope with
`BitstreamError::Unsupported(reason)` rather than silently producing
garbage parameter buffers.

H.266 (VVC), VP9, VP8, MPEG-2 and VC-1 have landed as additional
modules; their scope is incremental — see each module's rustdoc for
what's parsed today versus deferred.

## Module layout

```
src/
├── lib.rs           # re-exports each codec module + BitstreamError
├── bit_reader.rs    # shared u(n) / u64(n) / ue(v) / se(v) / i(n) /
│                    # te(v) / signed_magnitude(n) / read_bytes reader,
│                    # peek_bits, more_rbsp_data, read_rbsp_trailing_bits
├── bit_writer.rs    # MSB-first writer — inverse of bit_reader
│                    # (write_bits / write_ue / write_se / write_i /
│                    # write_te / write_signed_magnitude / write_bytes)
├── h264.rs          # H.264 SPS / PPS / minimal slice header
├── hevc.rs          # HEVC VPS / SPS / PPS / minimal slice header
├── h266.rs          # H.266 Annex-B walker + NAL header + structural VPS / SPS /
│                    # PPS + picture-header structural prefix (7.3.2.8)
├── mpeg2.rs         # MPEG-2 sequence + picture + extension headers
├── vc1.rs           # VC-1 sequence + entry-point + picture header
├── vp8.rs           # VP8 keyframe header + IVF demuxer
├── vp9.rs           # VP9 uncompressed header
├── ivf.rs           # IVF frame demuxer (VP8 / VP9 / AV1 fixtures)
└── av1.rs           # AV1 leb128 reader+writer, OBU walker+emitter, key-frame headers
```

## Bit-IO descriptors

The shared `BitReader` / `BitWriter` cover every syntax descriptor the
VCL specs use. Each pair is an exact round-trip inverse:

| Descriptor          | Reader                          | Writer                            | Spec                           |
| ------------------- | ------------------------------- | --------------------------------- | ------------------------------ |
| `u(n)`              | `u(n)` / `u64(n)`               | `write_bits` / `write_bits_u64`   | H.264 §7.2                     |
| `i(n)` 2's-complement signed | `i(n)`                  | `write_i`                         | H.264 §7.2 / H.265 §7.2        |
| `ue(v)` unsigned Exp-Golomb | `ue`                     | `write_ue`                        | H.264 §9.1                     |
| `se(v)` signed Exp-Golomb | `se`                       | `write_se`                        | H.264 §9.1.1                   |
| `te(v)` truncated Exp-Golomb | `te(x_max)`             | `write_te(value, x_max)`          | H.264 §9.1.2                   |
| Signed magnitude (`n` bits + 1 sign) | `signed_magnitude(n)` | `write_signed_magnitude` | VP9 §6.2.7 + legacy headers    |
| Aligned byte slice  | `read_bytes(n)`                 | `write_bytes(&[u8])`              | (helper)                       |
| LEB128 (AV1)        | `av1::read_leb128`              | `av1::write_leb128`               | AV1 §4.10                      |
| Annex-B / OBU framing | per-module                   | per-module                        | per-codec                      |

There is **no** cross-codec abstraction in v0. Each codec sub-module
exposes its own `parse_*` entry points and result structs, and a
convenience `parse_idr_only` (`parse_keyframe_only` for AV1) that
walks a complete Annex-B / OBU stream, finds the first
IDR / keyframe access unit, and returns the parsed parameters
plus a slice (or set of slices) of bytes the HW decoder consumes.

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
allowed under the workspace policy. We deliberately do **not** consult
ffmpeg / libavcodec, x264, x265, libde265, libaom, dav1d, rav1e or
libgav1 source. ffmpeg and aomenc are used only as black-box CLI tools
to generate test fixtures.

## License

MIT.
