#![no_main]

//! Stream-level fuzz harness: the input is an elementary stream fed
//! through the stateful front ends hardware bridges drive picture by
//! picture — parameter-set bookkeeping, complete slice / frame headers
//! and the reference state machines (H.264 POC + DPB marking + list
//! construction). Nothing may panic, overflow or loop unboundedly, and
//! the state machines must keep their invariants (every list has the
//! active size; the DPB stays bounded).

use libfuzzer_sys::fuzz_target;
use oxideav_bitstream::h264;
use oxideav_bitstream::h264::stream::{H264Event, H264Parser};

fuzz_target!(|data: &[u8]| {
    drive_h264(data);
    drive_hevc(data);
    drive_vp9(data);
});

/// VP9: an IVF stream (or, failing that, the input as one chunk) of
/// frames / superframes through the header state machine and the
/// §8.6.1 / §8.8.1 derivations.
fn drive_vp9(data: &[u8]) {
    use oxideav_bitstream::vp9::frame::{Vp9State, split_superframe};
    let chunks: Vec<&[u8]> = match oxideav_bitstream::ivf::parse_all(data) {
        Ok((_, frames)) => frames.iter().map(|f| f.payload).collect(),
        Err(_) => vec![data],
    };
    let mut st = Vp9State::new();
    for chunk in chunks {
        for frame in split_superframe(chunk) {
            if let Ok(h) = st.decode_frame_header(frame) {
                let _ = h.loop_filter_levels();
                for seg in 0..8 {
                    let _ = (h.dc_quant(0, seg), h.ac_quant(1, seg));
                }
                assert!(h.uncompressed_header_size <= frame.len());
            }
        }
    }
}

fn drive_hevc(data: &[u8]) {
    use oxideav_bitstream::hevc::dpb::HevcDpb;
    use oxideav_bitstream::hevc::stream::{HevcEvent, HevcParser, nal_units};
    let mut parser = HevcParser::new();
    let mut dpb = HevcDpb::new();
    let mut skipping = false;
    for nal in nal_units(data) {
        let slice = match parser.process_nal(nal) {
            Ok(HevcEvent::Slice(s)) => s,
            Ok(HevcEvent::EndOfSequence) => {
                dpb.end_of_sequence();
                continue;
            }
            _ => continue,
        };
        let Some((sps, _)) = parser.active(&slice) else {
            continue;
        };
        let sps = sps.clone();
        if slice.first_of_picture {
            if dpb.current().is_some() && !skipping {
                let _ = dpb.finish_picture();
            }
            match dpb.begin_picture(&sps, &slice.header) {
                Ok(c) => skipping = c.skip,
                Err(_) => continue,
            }
        }
        if dpb.current().is_none() || skipping {
            continue;
        }
        if let Ok(l) = dpb.ref_pic_lists(&slice.header) {
            let h = &slice.header;
            if h.slice_type.is_inter() {
                assert_eq!(l.list0.len(), h.num_ref_idx_l0_active_minus1 as usize + 1);
            }
        }
        assert!(
            dpb.references().count() <= 16,
            "HEVC DPB grows without bound"
        );
    }
}

fn drive_h264(data: &[u8]) {
    let mut parser = H264Parser::new();
    let mut dpb = h264::dpb::Dpb::new();
    let mut active: Option<h264::H264Sps> = None;
    for nal in h264::stream::nal_units(data) {
        let Ok(H264Event::Slice(slice)) = parser.process_nal(nal) else {
            continue;
        };
        let Some((sps, _)) = parser.active(&slice) else {
            continue;
        };
        let sps = sps.clone();
        if !slice.primary {
            continue;
        }
        if slice.first_of_picture {
            if let Some(prev) = active.take()
                && dpb.current().is_some()
            {
                let _ = dpb.finish_picture(&prev);
            }
            if dpb.begin_picture(&sps, &slice.header).is_err() {
                continue;
            }
            active = Some(sps.clone());
        }
        if dpb.current().is_none() {
            continue;
        }
        if let Ok(l) = dpb.ref_pic_lists(&sps, &slice.header) {
            let h = &slice.header;
            if h.slice_type.has_list0() {
                assert_eq!(l.list0.len(), h.num_ref_idx_l0_active_minus1 as usize + 1);
            }
        }
        assert!(dpb.references().count() <= 64, "DPB grows without bound");
    }
    if let Some(prev) = active
        && dpb.current().is_some()
    {
        let _ = dpb.finish_picture(&prev);
    }
}
