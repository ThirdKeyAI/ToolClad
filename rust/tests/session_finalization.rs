use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    manifest: String,
    expected: Option<bool>,
}

#[test]
fn session_finalization_contract() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../tests/session_finalization_vectors.json"
    ))
    .unwrap();
    for case in cases {
        let result = toolclad::parse_manifest(&case.manifest);
        match case.expected {
            Some(expected) => assert_eq!(
                result.unwrap().session.unwrap().commands["finish"].finalize,
                expected,
                "{}",
                case.name
            ),
            None => assert!(
                result.is_err(),
                "{} must reject a non-boolean finalizer",
                case.name
            ),
        }
    }
}
