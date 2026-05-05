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

| | H.264 | HEVC | AV1 |
| - | - | - | - |
| Annex-B / OBU framing | yes | yes | yes (leb128 sizes) |
| Sequence header (SPS / VPS+SPS / Sequence-Header OBU) | yes | yes | yes |
| Picture header (PPS / Frame-Header OBU) | yes | yes | yes |
| Minimal slice header (IDR / I-slice / KEY_FRAME) | yes | yes | yes |
| DCT, entropy decode, motion compensation, in-loop filtering | no | no | no |
| Scaling lists | rejected | rejected | n/a |
| FMO / ASO / multiple slice groups | rejected | n/a | n/a |
| Tiles / WPP | n/a | rejected | n/a |
| AV1 decoder model / operating points beyond [0] / film grain | n/a | n/a | rejected |

The crate refuses inputs that fall outside the supported envelope with
`BitstreamError::Unsupported(reason)` rather than silently producing
garbage parameter buffers.

VP9 and MPEG-2 are deliberately deferred — when those back-ends grow,
they'll join this crate as additional modules.

## Module layout

```
src/
├── lib.rs           # re-exports h264, hevc, av1 + BitstreamError
├── bit_reader.rs    # shared u(n) / ue(v) / se(v) reader
├── h264.rs          # H.264 SPS / PPS / minimal slice header
├── hevc.rs          # HEVC VPS / SPS / PPS / minimal slice header
└── av1.rs           # AV1 leb128 + OBU walker + key-frame headers
```

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
- AV1 Bitstream & Decoding Process Specification (av1.org).

Following a public spec PDF is the canonical clean-room move and is
allowed under the workspace policy. We deliberately do **not** consult
ffmpeg / libavcodec, x264, x265, libde265, libaom, dav1d, rav1e or
libgav1 source. ffmpeg and aomenc are used only as black-box CLI tools
to generate test fixtures.

## License

MIT.
