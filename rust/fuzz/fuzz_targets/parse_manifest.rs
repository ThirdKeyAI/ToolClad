//! Property: the strict manifest loader never panics on any input; it either
//! returns a manifest or an error.
#![no_main]

use libfuzzer_sys::fuzz_target;
use toolclad::LoadOptions;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // An explicit, empty custom-type set keeps every run independent of the
    // filesystem around the fuzzer.
    let options = LoadOptions {
        custom_types: Some(Default::default()),
        ..Default::default()
    };
    let _ = toolclad::parse_manifest_with(text, options);
});
