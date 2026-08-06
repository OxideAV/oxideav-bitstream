//! VP9 uncompressed-header parser end-to-end test against an
//! reference-encoder-produced 320×240 single-keyframe IVF fixture
//! lifted from oxideav-vdpau's Round 4 tests.

use oxideav_bitstream::ivf::{parse_all, IVF_FOURCC_VP90};
use oxideav_bitstream::vp9::parse_uncompressed_header;

const FIXTURE: &[u8] = include_bytes!("fixtures/vp9_320x240_1frame.ivf");

#[test]
fn vp9_ivf_header_is_vp90_320x240() {
    let (hdr, frames) = parse_all(FIXTURE).expect("parse_all IVF");
    assert_eq!(&hdr.fourcc, &IVF_FOURCC_VP90);
    assert_eq!(hdr.width, 320);
    assert_eq!(hdr.height, 240);
    assert!(!frames.is_empty());
}

#[test]
fn vp9_keyframe_parses_to_320x240_profile0_8bit() {
    let (_hdr, frames) = parse_all(FIXTURE).unwrap();
    let payload = frames[0].payload;
    let h = parse_uncompressed_header(payload).expect("parse_uncompressed_header");

    // Bit-depth / profile / chroma sampling.
    assert_eq!(h.profile, 0);
    assert_eq!(h.frame_type, 0, "keyframe");
    assert!(h.show_frame);
    assert_eq!(h.bit_depth, 8);
    assert!(h.subsampling_x, "4:2:0 chroma");
    assert!(h.subsampling_y, "4:2:0 chroma");

    // Dimensions.
    assert_eq!(h.frame_width, 320);
    assert_eq!(h.frame_height, 240);

    // Loop filter / quant / segmentation / tiles per the §6.2-correct
    // walk (an earlier round skipped the refresh_frame_context /
    // frame_parallel_decoding_mode / frame_context_idx bits and
    // pinned a 4-bit-shifted misparse here; the encoder actually
    // codes the spec-default ref deltas [1, 0, -1, -1] explicitly).
    assert_eq!(h.base_q_idx, 37);
    assert_eq!(h.loop_filter_level, 2);
    assert_eq!(h.loop_filter_sharpness, 0);
    assert!(h.loop_filter_mode_ref_delta_enabled);
    assert_eq!(h.loop_filter_ref_deltas, [1, 0, -1, -1]);
    assert_eq!(h.loop_filter_mode_deltas, [0, 0]);
    assert!(!h.segmentation_enabled);
    assert_eq!(h.log2_tile_cols, 0);
    assert_eq!(h.log2_tile_rows, 0);

    // The uncompressed header occupies 18 bytes including alignment,
    // and the compressed header is 186 bytes.
    assert_eq!(h.uncompressed_header_size, 18);
    assert_eq!(h.compressed_header_size, 186);

    // Keyframe metadata: coded entropy-refresh pair + reset context.
    assert_eq!(h.refresh_frame_flags, 0xff);
    assert!(h.refresh_frame_context);
    assert!(h.frame_parallel_decoding_mode);
    assert_eq!(h.coded_frame_context_idx, 0);
    assert_eq!(h.frame_context_idx, 0);
    assert!(!h.intra_only);
}

#[test]
fn vp9_uncompressed_header_writer_is_byte_exact_on_fixture() {
    use oxideav_bitstream::vp9::write_uncompressed_header;
    let (_hdr, frames) = parse_all(FIXTURE).unwrap();
    let payload = frames[0].payload;
    let h = parse_uncompressed_header(payload).expect("parse");
    let rewritten = write_uncompressed_header(&h).expect("write");
    assert_eq!(
        rewritten,
        payload[..h.uncompressed_header_size as usize],
        "byte-exact uncompressed-header round-trip"
    );
    // And the writer's bytes re-parse to the identical struct (the
    // sizes describe the same layout since the bytes match).
    let mut extended = rewritten.clone();
    extended.extend_from_slice(&payload[h.uncompressed_header_size as usize..]);
    assert_eq!(parse_uncompressed_header(&extended).unwrap(), h);
}

#[test]
fn vp9_truncated_input_is_rejected() {
    assert!(parse_uncompressed_header(&[0u8; 4]).is_err());
}

#[test]
fn vp9_rejects_invalid_frame_marker() {
    // Frame marker is the top 2 bits = 2 (binary 10). Anything else
    // is invalid. Synthesise a payload where the top 2 bits are 0.
    let buf = [0u8; 16];
    assert!(matches!(
        parse_uncompressed_header(&buf),
        Err(oxideav_bitstream::BitstreamError::InvalidData(_))
    ));
}
