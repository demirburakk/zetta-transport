#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    zetta_transport::fuzzing::decode_frames(data);
});
