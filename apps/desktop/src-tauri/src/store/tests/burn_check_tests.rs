use serde_json::json;

use super::*;

const CHECK_IDS: &[&str] = &["ignored_instructions", "future_check"];

#[test]
fn full_page_progress_and_multi_page_result_keep_separate_bounds() {
    let store = store();
    let mut record = session("large-assessment", 10_000);
    record.activity_cursor = "before-enable".to_owned();
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 1);
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    record.activity_cursor = "after-enable".to_owned();
    record.updated_at_epoch = Some(29_000);
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 2);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    let input = input(&candidate, "large-revision");
    assert!(
        store
            .queue_burn_check_assessment(&input, 40_000, 180)
            .unwrap()
    );
    assert!(
        store
            .claim_burn_check_assessment(&input, 40_000, 300, 180)
            .unwrap()
    );
    let progress = json!({"answers": "x".repeat(500_000)}).to_string();
    assert!(
        store
            .save_burn_check_progress(&input, &progress, 40_001, 300, 180)
            .unwrap()
    );
    let combined_progress =
        json!({"carried": "x".repeat(300_000), "answers": "y".repeat(300_000)}).to_string();
    assert!(
        store
            .save_burn_check_progress(&input, &combined_progress, 40_001, 300, 180)
            .unwrap()
    );
    let result = json!({"unassessed": "x".repeat(700_000)}).to_string();
    assert!(
        store
            .complete_burn_check_assessment(&input, &result, 40_002, 180)
            .unwrap()
    );
    let stored = store
        .burn_check_assessment(&input.key, "ignored_instructions")
        .unwrap()
        .unwrap();
    assert_eq!(stored.result_json.as_deref(), Some(result.as_str()));
    assert_eq!(stored.progress_json, "{}");
    assert!(
        store
            .complete_burn_check_assessment(
                &input,
                &json!({"x": "x".repeat(1024 * 1024)}).to_string(),
                40_003,
                180
            )
            .is_err()
    );
}

#[test]
fn enablement_captures_source_positions_for_timestamp_less_activity() {
    let store = store();
    let mut record = session("position-boundary", 10_000);
    record.activity_cursor = "before".to_owned();
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    store
        .lock()
        .execute(
            "INSERT INTO turn (environment_key, agent, session_id, claim_fence, source_key,
            thread_id, turn_index, scope, role, input_tokens, cache_read_tokens,
            cache_write_tokens, output_tokens, is_compaction_boundary)
         VALUES (?1, ?2, ?3, 1, 'source', 'thread', 7, 'main', 'assistant', 0, 0, 0, 0, 0)",
            params![
                record.key.environment_key,
                record.key.agent,
                record.key.session_id
            ],
        )
        .unwrap();
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    record.activity_cursor = "after".to_owned();
    record.updated_at_epoch = Some(29_000);
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 1);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(candidate.boundary_positions.get("source"), Some(&7));
}

#[test]
fn unsupported_candidates_do_not_starve_later_sessions_in_the_bounded_batch() {
    let store = store();
    let mut records = (0..17)
        .map(|index| {
            let mut record = session(&format!("candidate-{index:02}"), 10_000);
            record.activity_cursor = "before-enable".to_owned();
            record.source_fingerprint = Some(format!("source-{index}"));
            record
        })
        .collect::<Vec<_>>();
    store
        .upsert_sessions(&records, &crate::agents::evidence_cohort())
        .unwrap();
    for record in &records {
        publish_ready(&store, record, 1);
    }
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    for record in &mut records {
        record.activity_cursor = "after-enable".to_owned();
        record.updated_at_epoch = Some(29_000);
        store
            .upsert_sessions(
                std::slice::from_ref(record),
                &crate::agents::evidence_cohort(),
            )
            .unwrap();
        publish_ready(&store, record, 2);
    }

    let first = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 16)
        .unwrap();
    assert_eq!(first.len(), 16);
    for candidate in &first {
        store
            .record_burn_check_candidate_issue(candidate, true, 0, 40_000)
            .unwrap();
    }
    let next = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 16)
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].session.key.session_id, "candidate-16");
}

#[test]
fn legacy_limited_history_assessments_can_resume() {
    let store = store();
    let record = session("historical-page-limit", 10_000);
    store
        .upsert_sessions(
            std::slice::from_ref(&record),
            &crate::agents::evidence_cohort(),
        )
        .unwrap();
    publish_ready(&store, &record, 1);
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    assert_eq!(store.enqueue_burn_checks(20_000, 7).unwrap(), 1);
    for category in ["request_limit", "assessment_page_limit"] {
        store
            .lock()
            .execute(
                "UPDATE burn_check_assessment
                    SET status = 'failed', last_error_category = ?1,
                        next_attempt_at_epoch = NULL
                  WHERE environment_key = ?2 AND agent = ?3 AND session_id = ?4
                    AND check_id = 'ignored_instructions'",
                params![
                    category,
                    record.key.environment_key,
                    record.key.agent,
                    record.key.session_id
                ],
            )
            .unwrap();
        assert_eq!(
            store
                .burn_check_candidates("ignored_instructions", 30_000, 180, 10)
                .unwrap()
                .len(),
            1,
            "{category} can resume"
        );
        assert_eq!(store.enqueue_burn_checks(30_000, 7).unwrap(), 1);
        assert_eq!(
            store
                .historical_burn_check_status(30_000, 180)
                .unwrap()
                .ready,
            1
        );
    }
}

#[test]
fn unavailable_evidence_retries_without_erasing_a_current_result() {
    let store = store();
    let mut record = session("retryable-evidence", 10_000);
    record.activity_cursor = "before-enable".to_owned();
    record.source_fingerprint = Some("same-source".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 1);
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    record.activity_cursor = "after-enable".to_owned();
    record.updated_at_epoch = Some(29_000);
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 2);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    let input = input(&candidate, "current-revision");
    store
        .queue_burn_check_assessment(&input, 40_000, 180)
        .unwrap();
    store
        .claim_burn_check_assessment(&input, 40_000, 300, 180)
        .unwrap();
    store
        .complete_burn_check_assessment(&input, r#"{"findings":["retained"]}"#, 40_001, 180)
        .unwrap();

    store
        .record_burn_check_candidate_issue(&candidate, false, 50_000, 40_002)
        .unwrap();
    let assessment = store
        .burn_check_assessment(&record.key, "ignored_instructions")
        .unwrap()
        .unwrap();
    assert_eq!(assessment.status, "failed");
    assert_eq!(
        assessment.input_revision.as_deref(),
        Some("current-revision")
    );
    assert_eq!(
        assessment.result_json.as_deref(),
        Some(r#"{"findings":["retained"]}"#)
    );
    assert!(
        store
            .burn_check_candidates("ignored_instructions", 49_999, 180, 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .burn_check_candidates("ignored_instructions", 50_000, 180, 10)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn activity_boundaries_are_shared_per_check_and_stale_results_are_rejected() {
    let store = store();
    let mut record = session("assessment-boundary", 10_000);
    record.activity_cursor = "cursor-one".to_owned();
    record.source_fingerprint = Some("fingerprint-one".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 7);

    assert_eq!(
        store
            .capture_burn_check_boundaries(CHECK_IDS, 20_000)
            .unwrap(),
        2
    );
    assert!(
        store
            .burn_check_candidates("ignored_instructions", 30_000, 180, 10)
            .unwrap()
            .is_empty()
    );

    record.updated_at_epoch = Some(29_000);
    record.activity_cursor = "cursor-two".to_owned();
    record.source_fingerprint = Some("fingerprint-two".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 8);

    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .expect("new activity after enablement is eligible");
    assert_eq!(candidate.boundary_at_epoch, 20_000);
    let input = input(&candidate, "revision-one");
    assert!(
        store
            .queue_burn_check_assessment(&input, 40_000, 180)
            .unwrap()
    );
    assert!(
        store
            .burn_check_candidates("ignored_instructions", 40_001, 180, 10)
            .unwrap()
            .iter()
            .any(|queued| queued.session.key == record.key)
    );
    assert!(
        store
            .queue_burn_check_assessment(&input, 40_001, 180)
            .unwrap()
    );
    assert!(
        store
            .claim_burn_check_assessment(&input, 40_000, 300, 180)
            .unwrap()
    );
    assert!(
        !store
            .claim_burn_check_assessment(&input, 40_001, 300, 180)
            .unwrap()
    );
    assert!(
        store
            .save_burn_check_progress(&input, r#"{"completed":1}"#, 40_002, 300, 180)
            .unwrap()
    );

    record.updated_at_epoch = Some(40_003);
    record.activity_cursor = "cursor-three".to_owned();
    record.source_fingerprint = Some("fingerprint-three".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 9);
    assert!(
        !store
            .complete_burn_check_assessment(&input, r#"{"findings":[]}"#, 40_004, 180)
            .unwrap()
    );
    let assessment = store
        .burn_check_assessment(&record.key, "ignored_instructions")
        .unwrap()
        .unwrap();
    assert_eq!(assessment.status, "superseded");
    assert_eq!(assessment.result_json, None);
}

#[test]
fn usage_tracking_allows_unbounded_requests_and_caches_exact_responses() {
    let store = store();
    let mut record = session("assessment-usage", 10_000);
    record.activity_cursor = "cursor-one".to_owned();
    record.source_fingerprint = Some("fingerprint-one".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 8);
    store
        .capture_burn_check_boundaries(CHECK_IDS, 20_000)
        .unwrap();
    record.updated_at_epoch = Some(29_000);
    record.activity_cursor = "cursor-two".to_owned();
    record.source_fingerprint = Some("fingerprint-two".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 9);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    let input = input(&candidate, "usage-revision");
    assert!(
        store
            .queue_burn_check_assessment(&input, 40_000, 180)
            .unwrap()
    );
    assert!(
        store
            .claim_burn_check_assessment(&input, 40_000, 300, 180)
            .unwrap()
    );

    let mut reservation_ids = Vec::new();
    for _ in 0..70 {
        match store
            .reserve_burn_check_usage(&input, "synthetic-provider", "model-v1", 8_192, 40_001, 180)
            .unwrap()
        {
            BurnCheckReservation::Reserved(id) => reservation_ids.push(id),
            other => panic!("unexpected reservation result: {other:?}"),
        }
    }
    let BurnCheckReservation::Reserved(over_64_requests) = store
        .reserve_burn_check_usage(&input, "synthetic-provider", "model-v1", 8_192, 40_001, 180)
        .unwrap()
    else {
        panic!("usage tracking must not cap assessment requests");
    };
    reservation_ids.push(over_64_requests);
    store
        .settle_burn_check_usage(&reservation_ids[0], Some(0), 40_002)
        .unwrap();
    store
        .settle_burn_check_usage(&reservation_ids[1], None, 40_002)
        .unwrap();
    store
        .settle_burn_check_usage(&reservation_ids[1], None, 40_003)
        .unwrap();
    let BurnCheckReservation::Reserved(reservation_id) = store
        .reserve_burn_check_usage(&input, "synthetic-provider", "model-v1", 8_192, 40_002, 180)
        .unwrap()
    else {
        panic!("usage tracking should permit the next request");
    };
    store
        .record_burn_check_response(
            &reservation_id,
            CachedAssessmentResponse {
                provider: "synthetic-provider".to_owned(),
                request_digest: "exact-request-digest".to_owned(),
                returned_model: "model-v1".to_owned(),
                response_json: json!({"answers": ["typed"]}).to_string(),
                input_tokens: 12,
                output_tokens: 1,
                created_at_epoch: 40_002,
            },
        )
        .unwrap();
    store
        .record_burn_check_response(
            &reservation_id,
            CachedAssessmentResponse {
                provider: "synthetic-provider".to_owned(),
                request_digest: "exact-request-digest".to_owned(),
                returned_model: "model-v1".to_owned(),
                response_json: json!({"answers": ["typed"]}).to_string(),
                input_tokens: 12,
                output_tokens: 1,
                created_at_epoch: 40_003,
            },
        )
        .unwrap();

    assert_eq!(
        store
            .cached_assessment_response("synthetic-provider", "exact-request-digest", 40_003)
            .unwrap()
            .unwrap()
            .input_tokens,
        12
    );
    assert!(
        store
            .cached_assessment_response("synthetic-provider", "another-digest", 40_003)
            .unwrap()
            .is_none()
    );
    store
        .record_burn_check_cache_hit(
            &input,
            "synthetic-provider",
            "model-v1",
            "ignored_instructions",
            "cache-hit-attempt",
        )
        .unwrap();
    store
        .record_burn_check_cache_hit(
            &input,
            "synthetic-provider",
            "model-v1",
            "ignored_instructions",
            "cache-hit-attempt",
        )
        .unwrap();
    let ledger: serde_json::Value = serde_json::from_str(
        &store
            .internal_value("internal:burnCheckUsageLedgerV1")
            .unwrap(),
    )
    .unwrap();
    let total_reserved: u64 = ledger["reservations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["input_tokens"].as_u64().unwrap())
        .sum();
    assert_eq!(total_reserved, 70 * 8_192 + 12);
    let usage = store.burn_check_usage_summary().unwrap();
    assert_eq!(usage.input_tokens, 12);
    assert_eq!(usage.output_tokens, 1);
    assert_eq!(usage.confirmed_calls, 2);
    assert_eq!(usage.cache_hits, 1);
    assert_eq!(usage.unknown_outcomes, 1);
    assert_eq!(usage.estimated_usd, None);
}

#[test]
fn deleting_a_session_forgets_its_reservation_identity_but_keeps_cost_totals() {
    let store = store();
    let mut record = session("usage-delete", 10_000);
    record.activity_cursor = "before-enable".to_owned();
    record.source_fingerprint = Some("same-source".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 1);
    store
        .capture_burn_check_boundaries(&["ignored_instructions"], 20_000)
        .unwrap();
    record.activity_cursor = "after-enable".to_owned();
    record.updated_at_epoch = Some(29_000);
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 2);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    let input = input(&candidate, "delete-revision");
    store
        .queue_burn_check_assessment(&input, 40_000, 180)
        .unwrap();
    store
        .claim_burn_check_assessment(&input, 40_000, 300, 180)
        .unwrap();
    let BurnCheckReservation::Reserved(reservation_id) = store
        .reserve_burn_check_usage(
            &input,
            "typesafe-systemone",
            "jev-1.13.0",
            8_192,
            40_001,
            180,
        )
        .unwrap()
    else {
        panic!("usage reservation should be available");
    };
    store
        .record_burn_check_response(
            &reservation_id,
            CachedAssessmentResponse {
                provider: "typesafe-systemone".to_owned(),
                request_digest: "delete-exact-request".to_owned(),
                returned_model: "jev-1.13.0".to_owned(),
                response_json: json!({"answers": ["typed"]}).to_string(),
                input_tokens: 123,
                output_tokens: 7,
                created_at_epoch: 40_002,
            },
        )
        .unwrap();
    let before_delete = store.burn_check_usage_summary().unwrap();
    assert_eq!(before_delete.input_tokens, 123);
    assert_eq!(before_delete.estimated_usd.as_deref(), Some("$0.000005166"));

    assert!(store.delete_session(&record.key).unwrap().is_some());

    let ledger = store
        .internal_value("internal:burnCheckUsageLedgerV1")
        .unwrap();
    assert!(!ledger.contains("usage-delete"));
    let ledger: serde_json::Value = serde_json::from_str(&ledger).unwrap();
    assert_eq!(ledger["reservations"][0]["session_key"], "");
    assert_eq!(ledger["reservations"][0]["input_tokens"], 123);
    assert_eq!(store.burn_check_usage_summary().unwrap(), before_delete);
}

#[test]
fn clearing_session_data_removes_assessment_progress_cache_and_usage() {
    let store = store();
    let mut record = session("assessment-clear", 10_000);
    record.activity_cursor = "cursor-one".to_owned();
    record.source_fingerprint = Some("fingerprint-one".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 8);
    store
        .capture_burn_check_boundaries(CHECK_IDS, 20_000)
        .unwrap();
    record.updated_at_epoch = Some(29_000);
    record.activity_cursor = "cursor-two".to_owned();
    record.source_fingerprint = Some("fingerprint-two".to_owned());
    store
        .upsert_sessions(&[record.clone()], &crate::agents::evidence_cohort())
        .unwrap();
    publish_ready(&store, &record, 9);
    let candidate = store
        .burn_check_candidates("ignored_instructions", 40_000, 180, 10)
        .unwrap()
        .pop()
        .unwrap();
    let input = input(&candidate, "clear-revision");
    store
        .queue_burn_check_assessment(&input, 40_000, 180)
        .unwrap();
    store
        .cache_assessment_response(CachedAssessmentResponse {
            provider: "synthetic-provider".to_owned(),
            request_digest: "digest-clear".to_owned(),
            returned_model: "model-v1".to_owned(),
            response_json: "{}".to_owned(),
            input_tokens: 1,
            output_tokens: 0,
            created_at_epoch: 40_000,
        })
        .unwrap();
    store.set_internal_value("internal:jevBurnCheckHistoryBatchEpochV1", "40000");

    let before_clear = time::OffsetDateTime::now_utc().unix_timestamp();
    store.clear_local_session_data().unwrap();

    assert!(
        store
            .burn_check_assessment(&record.key, "ignored_instructions")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.internal_value("internal:burnCheckUsageLedgerV1"),
        None
    );
    assert_eq!(
        store.internal_value("internal:burnCheckResponseCacheV1"),
        None
    );
    assert_eq!(
        store.internal_value("internal:jevBurnCheckHistoryBatchEpochV1"),
        None
    );
    assert!(
        store
            .internal_value("internal:burnChecksEnabledAtEpochV1")
            .unwrap()
            .parse::<i64>()
            .unwrap()
            >= before_clear
    );
}

fn publish_ready(store: &Store, record: &SessionRecord, fence: i64) {
    let has_content = store
        .lock()
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM turn_content AS content
                 JOIN turn ON turn.rowid = content.turn_rowid
                 WHERE turn.environment_key = ?1 AND turn.agent = ?2
                   AND turn.session_id = ?3 AND content.kind <> 'thinking'
                   AND length(content.content) > 0
             )",
            params![
                record.key.environment_key,
                record.key.agent,
                record.key.session_id
            ],
            |row| row.get::<_, bool>(0),
        )
        .unwrap();
    if !has_content {
        let mut row = super::turn_row(0);
        row.source_key = record.key.session_id.clone();
        row.thread_id = row.source_key.clone();
        row.content = vec![antiburn_local::analysis::ContentPart::new(
            antiburn_local::analysis::ContentKind::AssistantText,
            "synthetic session action",
        )];
        let key = antiburn_local::analysis::TurnSessionKey {
            environment_key: &record.key.environment_key,
            agent: &record.key.agent,
            session_id: &record.key.session_id,
        };
        antiburn_local::analysis::insert_turn_rows(&store.lock(), &key, 1, &[row]).unwrap();
    }
    let (generation, fingerprint): (i64, Option<String>) = store
        .lock()
        .query_row(
            "SELECT source_generation, source_fingerprint FROM session
              WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3",
            params![
                record.key.environment_key,
                record.key.agent,
                record.key.session_id
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    store
        .lock()
        .execute(
            "UPDATE session_evidence
                SET status = 'ready', analyzed_generation = ?4,
                    processed_fingerprint = ?5, parser_revision = ?6,
                    analyzer_revision = ?7, evidence_schema_revision = ?8,
                    evidence_json = '{}', claim_fence = ?9, published_fence = ?9
              WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3",
            params![
                record.key.environment_key,
                record.key.agent,
                record.key.session_id,
                generation,
                fingerprint,
                antiburn_local::analysis::PARSER_REVISION,
                antiburn_local::analysis::ANALYZER_REVISION,
                antiburn_local::analysis::EVIDENCE_SCHEMA_REVISION,
                fence,
            ],
        )
        .unwrap();
}

fn input(candidate: &BurnCheckCandidate, input_revision: &str) -> BurnCheckInput {
    BurnCheckInput {
        key: candidate.session.key.clone(),
        check_id: "ignored_instructions".to_owned(),
        incarnation: candidate.incarnation,
        source_generation: candidate.source_generation,
        source_fingerprint: candidate.source_fingerprint.clone(),
        activity_cursor: candidate.activity_cursor.clone(),
        published_fence: candidate.published_fence,
        input_revision: input_revision.to_owned(),
        evaluator_revision: antiburn_local::analysis::ignored_instructions::evaluator_revision(),
        boundary_at_epoch: candidate.boundary_at_epoch,
    }
}
