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
});

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
