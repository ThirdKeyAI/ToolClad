use serde::Deserialize;
use std::collections::HashMap;
#[derive(Deserialize)]
struct Case {
    name: String,
    manifest: String,
    args: HashMap<String, String>,
    expected_argv: Vec<String>,
    error: bool,
}
#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}
#[test]
fn shared_execution_vectors() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/execution_vectors.json")).unwrap();
    assert_eq!(vectors.cases.len(), 17);
    for case in vectors.cases {
        let manifest = toolclad::parse_manifest(&case.manifest).unwrap();
        let result = toolclad::executor::build_command(&manifest, &case.args);
        if case.error {
            assert!(result.is_err(), "{} should refuse", case.name);
        } else {
            assert_eq!(
                shlex::split(&result.unwrap()).unwrap(),
                case.expected_argv,
                "{}",
                case.name
            );
        }
    }
}
