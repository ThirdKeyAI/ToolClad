use serde::Deserialize;
use std::collections::HashMap;
use toolclad::types::{ArgDef, CustomTypeDef};
use toolclad::validator::{validate_arg, validate_arg_with_custom_types};
#[derive(Deserialize)]
struct Case {
    name: String,
    value: String,
    repeat: usize,
    error: bool,
    pattern: Option<String>,
}
#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}
#[test]
fn literal_text_vectors_and_custom_types() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/literal_text_vectors.json")).unwrap();
    assert_eq!(vectors.cases.len(), 12);
    for case in vectors.cases {
        let value = case.value.repeat(case.repeat);
        let def = ArgDef {
            type_name: "literal_text".into(),
            required: true,
            pattern: case.pattern.clone(),
            ..Default::default()
        };
        let custom: CustomTypeDef = serde_json::from_value(
            serde_json::json!({"base":"literal_text", "pattern":case.pattern}),
        )
        .unwrap();
        let custom_types = HashMap::from([("source_text".into(), custom)]);
        let alias = ArgDef {
            type_name: "source_text".into(),
            ..def.clone()
        };
        for result in [
            validate_arg("value", &def, &value),
            validate_arg_with_custom_types("value", &alias, &value, &custom_types),
        ] {
            if case.error {
                assert!(result.is_err(), "{}", case.name);
            } else {
                assert_eq!(result.unwrap(), value, "{}", case.name);
            }
        }
    }
}
