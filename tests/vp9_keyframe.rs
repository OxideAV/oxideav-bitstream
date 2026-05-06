//! VP9 uncompressed-header parser end-to-end test against an
//! ffmpeg/libvpx-vp9-encoded 320×240 single-keyframe IVF fixture
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

    // Loop filter / segmentation / tiles values measured against the
    // exact same fixture used by oxideav-vdpau.
    assert_eq!(h.base_q_idx, 28);
    assert_eq!(h.loop_filter_level, 48);
    assert_eq!(h.loop_filter_sharpness, 1);
    assert!(h.segmentation_enabled);
    assert!(!h.segmentation_update_map);
    assert!(!h.segmentation_update_data);
    assert_eq!(h.log2_tile_cols, 0);
    assert_eq!(h.log2_tile_rows, 1);

    // The uncompressed header occupies 14 bytes including alignment,
    // and the compressed header is 3596 bytes. Both numbers come
    // from libvpx-vp9's encode of the testsrc2 320×240 fixture.
    assert_eq!(h.uncompressed_header_size, 14);
    assert_eq!(h.compressed_header_size, 3596);

    // Keyframe metadata defaults that the parser sets.
    assert_eq!(h.refresh_frame_flags, 0xff);
    assert!(h.refresh_frame_context);
    assert!(!h.intra_only);
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
