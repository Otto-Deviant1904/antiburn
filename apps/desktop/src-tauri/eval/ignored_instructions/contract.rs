use serde_json::Value;
use std::collections::BTreeSet;

const FIXTURE: &str = include_str!("data/contracts/direct_cases.json");

fn cases(fixture: &Value) -> &Vec<Value> {
    fixture["cases"].as_array().expect("cases array")
}

fn case<'a>(cases: &'a [Value], id: &str) -> &'a Value {
    cases
        .iter()
        .find(|value| value["id"] == id)
        .unwrap_or_else(|| panic!("missing case {id}"))
}

fn event_ids(value: &Value) -> BTreeSet<&str> {
    value["evidence_chunks"]
        .as_array()
        .expect("evidence chunks")
        .iter()
        .flat_map(|chunk| chunk["events"].as_array().expect("events"))
        .map(|event| event["id"].as_str().expect("event ID"))
        .collect()
}

#[test]
fn fixture_declares_expected_fields_and_valid_local_bindings() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("valid fixture");
    assert_eq!(fixture["schema_version"], 2);
    let contract = &fixture["deterministic_contract"];
    let fields = contract["expected_fields"].as_array().expect("field list");
    for field in [
        "instruction.source",
        "instruction.section",
        "instruction.text",
        "evidence_chunks[].chunk_id",
        "evidence_chunks[].events[].id",
        "expected.assessment",
        "expected.finding_event_ids",
    ] {
        assert!(fields.iter().any(|value| value == field), "missing {field}");
    }

    let cases = cases(&fixture);
    for value in cases {
        assert!(value["instruction"]["text"].as_str().is_some());
        assert!(value["instruction"]["source"].as_str().is_some());
        assert!(value["expected"]["assessment"].as_str().is_some());
        for event_id in value["expected"]["finding_event_ids"]
            .as_array()
            .expect("finding IDs")
        {
            assert!(event_ids(value).contains(event_id.as_str().expect("event ID")));
        }
    }

    for binding in contract["bindings"].as_array().expect("bindings") {
        let owner = case(cases, binding["case_id"].as_str().unwrap());
        let target = binding["event_id"].as_str().unwrap();
        assert!(event_ids(owner).contains(target), "unbound target {target}");
    }
}

#[test]
fn fixture_records_order_boundaries_forbidden_claims_and_counterfactuals() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("valid fixture");
    let contract = &fixture["deterministic_contract"];
    let cases = cases(&fixture);

    for boundary in contract["boundaries"].as_array().expect("boundaries") {
        let owner = case(cases, boundary["case_id"].as_str().unwrap());
        let ids = event_ids(owner);
        assert!(ids.contains(boundary["before_event"].as_str().unwrap()));
        assert!(ids.contains(boundary["milestone_event"].as_str().unwrap()));
    }

    for forbidden in contract["forbidden_claims"].as_array().expect("claims") {
        let owner = case(cases, forbidden["case_id"].as_str().unwrap());
        let claim = forbidden["claim"].as_str().unwrap();
        let expected = &owner["expected"];
        assert!(expected["must_not_claim"] == claim || expected["assessment"] == "unassessed");
    }

    for pair in contract["counterfactual_pairs"].as_array().expect("pairs") {
        let left = case(cases, pair["left"].as_str().unwrap());
        let right = case(cases, pair["right"].as_str().unwrap());
        let expected = pair["expected"].as_array().expect("pair expectations");
        assert_eq!(left["expected"]["assessment"], expected[0]);
        assert_eq!(right["expected"]["assessment"], expected[1]);
        assert_ne!(
            left["expected"]["assessment"],
            right["expected"]["assessment"]
        );
    }
}
