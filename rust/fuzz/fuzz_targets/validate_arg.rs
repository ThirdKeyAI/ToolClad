//! Property: the argument validator never panics, and never returns a value
//! for a string-derived type that contains whitespace, a quote, a backslash,
//! a control character or a leading `-`/`+` without the matching opt-in
//! (`msf_options` may keep its ASCII space separator).
//!
//! No definition sets `block_internal`, so no input triggers DNS.
#![no_main]

use libfuzzer_sys::fuzz_target;
use toolclad::types::ArgDef;
use toolclad::validator::{validate_arg_mode, STRING_DERIVED_TYPES};

const TYPES: &[&str] = &[
    "string",
    "path",
    "regex_match",
    "url",
    "scope_target",
    "duration",
    "msf_options",
    "integer",
    "number",
    "port",
    "boolean",
    "enum",
    "ip_address",
    "cidr",
];

fn is_control(c: char) -> bool {
    let cp = c as u32;
    cp < 0x20 || (0x7f..=0x9f).contains(&cp)
}

fuzz_target!(|data: &[u8]| {
    // First byte picks the type and the mode; the rest is the value.
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(value) = std::str::from_utf8(rest) else {
        return;
    };
    let type_name = TYPES[selector as usize % TYPES.len()];
    let exec_mode = selector & 0x80 != 0;
    let def = ArgDef {
        type_name: type_name.to_string(),
        pattern: (type_name == "regex_match").then(|| ".*".to_string()),
        allowed: (type_name == "enum").then(|| vec!["a".to_string(), "b c".to_string()]),
        ..Default::default()
    };

    let Ok(out) = validate_arg_mode("v", &def, value, exec_mode) else {
        return;
    };
    if !STRING_DERIVED_TYPES.contains(&type_name) {
        return;
    }
    let space_ok = type_name == "msf_options";
    assert!(
        !out.chars().any(|c| c.is_whitespace() && !(space_ok && c == ' ')),
        "{type_name}: {value:?} -> {out:?} contains whitespace"
    );
    assert!(
        !out.contains(['\'', '"', '\\']),
        "{type_name}: {value:?} -> {out:?} contains a quote or backslash"
    );
    assert!(
        !out.chars().any(is_control),
        "{type_name}: {value:?} -> {out:?} contains a control character"
    );
    assert!(
        !out.starts_with(['-', '+']),
        "{type_name}: {value:?} -> {out:?} starts with '-' or '+'"
    );
});
