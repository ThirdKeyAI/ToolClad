use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};
use toolclad::types::{ArgDef, CustomTypeDef};
use toolclad::validator::{validate_arg, validate_arg_with_custom_types};
#[derive(Deserialize)]
struct Case {
    name: String,
    value: String,
    error: bool,
    rust_value: Option<String>,
}
#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}
#[test]
fn relative_path_contract_and_aliases() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/path_vectors.json")).unwrap();
    let root = std::env::temp_dir().join(format!("toolclad-path-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let old = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();
    for case in &vectors.cases {
        if !case.error {
            if let Some(parent) = Path::new(&case.value).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&case.value, "synthetic fixture").unwrap();
        }
    }
    for kind in ["path", "credential_file"] {
        let def = ArgDef {
            type_name: kind.into(),
            ..Default::default()
        };
        let alias = ArgDef {
            type_name: "relative_file".into(),
            ..Default::default()
        };
        let custom: CustomTypeDef =
            serde_json::from_value(serde_json::json!({"base":kind})).unwrap();
        let types = HashMap::from([("relative_file".into(), custom)]);
        for case in &vectors.cases {
            for result in [
                validate_arg("value", &def, &case.value),
                validate_arg_with_custom_types("value", &alias, &case.value, &types),
            ] {
                if case.error {
                    assert!(result.is_err(), "{}", case.name);
                } else {
                    assert_eq!(
                        result.unwrap(),
                        case.rust_value.as_ref().unwrap_or(&case.value).as_str(),
                        "{}",
                        case.name
                    );
                }
            }
        }
        if kind == "credential_file" {
            for value in ["data", "missing.txt"] {
                assert!(validate_arg("value", &def, value).is_err());
            }
        }
    }
    std::env::set_current_dir(old).unwrap();
    fs::remove_dir_all(root).unwrap();
}
