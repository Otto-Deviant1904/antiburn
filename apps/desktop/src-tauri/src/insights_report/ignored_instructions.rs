use super::findings::CurrentFindingSession;
use super::*;

/// Read the same current assessment used by the report for a bounded session list.
pub(crate) fn ignored_instruction_session_statuses(
    data_dir: &Path,
    keys: &[crate::store::SessionKey],
) -> Result<Vec<crate::dto::IgnoredInstructionSessionStatus>> {
    let connection = open_read_only(data_dir, REPORT_BUSY_TIMEOUT)?;
    let sql = "SELECT e.evidence_json, s.incarnation, s.source_generation,
                s.source_fingerprint, e.published_fence, e.status,
                 (e.analyzed_generation = s.source_generation
                  AND e.parser_revision = ?4 AND e.analyzer_revision = ?5
                  AND e.evidence_schema_revision = ?6),
                 EXISTS (
                     SELECT 1 FROM turn_content AS content
                     JOIN turn AS content_turn ON content_turn.rowid = content.turn_rowid
                     WHERE content_turn.environment_key = s.environment_key
                       AND content_turn.agent = s.agent
                       AND content_turn.session_id = s.session_id
                       AND content.kind <> 'thinking' AND length(content.content) > 0
                 )
           FROM session s LEFT JOIN session_evidence e
             ON e.environment_key = s.environment_key AND e.agent = s.agent
            AND e.session_id = s.session_id
          WHERE s.environment_key = ?1 AND s.agent = ?2 AND s.session_id = ?3
             AND EXISTS (SELECT 1 FROM setting WHERE key = 'internal:burnChecksEnabledAtEpochV1')"
        .to_owned();
    let mut statement = connection.prepare(&sql)?;
    keys.iter()
        .map(|key| {
            let row = statement
                .query_row(
                    params![
                        key.environment_key,
                        key.agent,
                        key.session_id,
                        PARSER_REVISION,
                        ANALYZER_REVISION,
                        EVIDENCE_SCHEMA_REVISION
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<bool>>(6)?,
                            row.get::<_, bool>(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                json,
                incarnation,
                generation,
                fingerprint,
                fence,
                status,
                current,
                has_content,
            )) = row
            else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Checking,
                    Some("Waiting for current session evidence."),
                ));
            };
            if !has_content {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::NotAssessed,
                    Some("This session has no saved content to check."),
                ));
            }
            let Some(json) = json else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Checking,
                    Some("Waiting for current session evidence."),
                ));
            };
            if status.as_deref() == Some("unsupported") {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::CouldntCheck,
                    Some("This session source format is not supported."),
                ));
            }
            if status.as_deref() == Some("failed") {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::CouldntCheck,
                    Some("Could not read complete session evidence."),
                ));
            }
            if current != Some(true) || status.as_deref() != Some("ready") {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Checking,
                    Some("Waiting for current session evidence."),
                ));
            }
            let Some(fence) = fence else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Checking,
                    Some("Waiting for published session evidence."),
                ));
            };
            let Ok(evidence) = serde_json::from_str::<SessionEvidence>(&json) else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::CouldntCheck,
                    Some("Could not read complete session evidence."),
                ));
            };
            let result = ignored_instruction_result_for(
                &connection,
                &evidence,
                IgnoredInstructionSessionIdentity {
                    environment_key: &key.environment_key,
                    agent: &key.agent,
                    session_id: &key.session_id,
                    incarnation,
                    source_generation: generation,
                    source_fingerprint: fingerprint.as_deref(),
                    published_fence: fence,
                },
            )?;
            let Some(result) = result else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Checking,
                    Some("Waiting for a current instruction assessment."),
                ));
            };
            let Some(session_findings) =
                ignored_instruction_findings_for_evidence(&evidence, &result)
            else {
                return Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::CouldntCheck,
                    Some("The current instruction assessment is unavailable."),
                ));
            };
            if !session_findings.is_empty() {
                Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Finding,
                    None,
                ))
            } else if ignored_result_has_scoped_no_issues(&result, &session_findings) {
                Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::Clean,
                    None,
                ))
            } else {
                Ok(ignored_session_status(
                    crate::dto::SessionHygieneStatus::CouldntCheck,
                    Some(ignored_assessment_reason(&result)),
                ))
            }
        })
        .collect()
}

fn ignored_session_status(
    status: crate::dto::SessionHygieneStatus,
    reason: Option<&'static str>,
) -> crate::dto::IgnoredInstructionSessionStatus {
    crate::dto::IgnoredInstructionSessionStatus { status, reason }
}

fn ignored_assessment_reason(
    result: &antiburn_local::analysis::ignored_instructions::AssessmentResult,
) -> &'static str {
    if result.coverage.processing_limit_reached || result.coverage.unselected_pairs > 0 {
        "The assessment limit prevented checking every eligible rule and action."
    } else if result
        .coverage
        .limitations
        .contains(&"current_file_not_historical_proof".to_owned())
    {
        "Current instruction files do not prove which rules applied during this session."
    } else if result
        .coverage
        .limitations
        .contains(&"source_evidence_is_partial".to_owned())
    {
        "The session evidence is incomplete."
    } else if !result.pending_rules.is_empty() {
        "The session has no observed completion boundary for an eventual instruction."
    } else if !result.unassessed_comparisons.is_empty() {
        "Some instruction comparisons did not reach a result."
    } else if result.coverage.selected_comparisons == 0 {
        "No eligible instruction and action comparison was available."
    } else {
        "The available assessment evidence is incomplete."
    }
}

pub(crate) fn current_ignored_instruction_result(
    connection: &rusqlite::Connection,
    session: &CurrentFindingSession,
) -> Result<Option<antiburn_local::analysis::ignored_instructions::AssessmentResult>> {
    ignored_instruction_result_for(
        connection,
        &session.evidence,
        IgnoredInstructionSessionIdentity {
            environment_key: &session.environment_key,
            agent: &session.agent,
            session_id: &session.session_id,
            incarnation: session.incarnation,
            source_generation: session.source_generation,
            source_fingerprint: session.source_fingerprint.as_deref(),
            published_fence: session.published_fence,
        },
    )
}

pub(crate) struct IgnoredInstructionSessionIdentity<'a> {
    pub environment_key: &'a str,
    pub agent: &'a str,
    pub session_id: &'a str,
    pub incarnation: u64,
    pub source_generation: i64,
    pub source_fingerprint: Option<&'a str>,
    pub published_fence: i64,
}

pub(crate) fn ignored_instruction_result_for(
    connection: &rusqlite::Connection,
    evidence: &SessionEvidence,
    identity: IgnoredInstructionSessionIdentity<'_>,
) -> Result<Option<antiburn_local::analysis::ignored_instructions::AssessmentResult>> {
    use antiburn_local::analysis::ignored_instructions::{CHECK_ID, source_supported};

    if !source_supported(evidence.capabilities.source_format) {
        return Ok(None);
    }
    let stored = connection
        .query_row(
            "SELECT result_revision, result_json
               FROM burn_check_assessment
              WHERE environment_key = ?1 AND agent = ?2 AND session_id = ?3
                AND check_id = ?4 AND incarnation = ?5 AND source_generation = ?6
                 AND source_fingerprint IS ?7 AND published_fence = ?8
                 AND status IN ('completed', 'failed', 'queued', 'running', 'superseded')
                 AND result_revision IS NOT NULL",
            params![
                identity.environment_key,
                identity.agent,
                identity.session_id,
                CHECK_ID,
                identity.incarnation,
                identity.source_generation,
                identity.source_fingerprint,
                identity.published_fence,
            ],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?;
    let Some((Some(revision), Some(result_json))) = stored else {
        return Ok(None);
    };
    let Ok(result) = serde_json::from_str::<
        antiburn_local::analysis::ignored_instructions::AssessmentResult,
    >(&result_json) else {
        return Ok(None);
    };
    if result.input_revision != revision
        || result.model_version != antiburn_local::analysis::ignored_instructions::ASSESSMENT_MODEL
        || ignored_instruction_findings_for_evidence(evidence, &result).is_none()
    {
        return Ok(None);
    }
    Ok(Some(result))
}

pub(crate) fn ignored_instruction_findings(
    session: &CurrentFindingSession,
    result: &antiburn_local::analysis::ignored_instructions::AssessmentResult,
) -> Option<Vec<Finding>> {
    ignored_instruction_findings_for_evidence(&session.evidence, result)
}

pub(crate) fn ignored_instruction_findings_for_evidence(
    evidence: &SessionEvidence,
    result: &antiburn_local::analysis::ignored_instructions::AssessmentResult,
) -> Option<Vec<Finding>> {
    let mut seen = BTreeSet::new();
    result
        .findings
        .iter()
        .map(|finding| {
            if !seen.insert(finding.id.as_str()) {
                return None;
            }
            Finding::ignored_instruction(evidence, &result.input_revision, finding)
        })
        .collect()
}

pub(super) struct IgnoredInstructionReportCounts {
    pub eligible: u64,
    pub assessed: u64,
    pub clean: u64,
    pub clean_agents: BTreeSet<String>,
    pub finding_agents: BTreeSet<String>,
    pub unavailable: u64,
    pub not_applicable: u64,
    pub finding_sessions: u64,
    pub examples: Vec<SessionExample>,
}

pub(super) fn apply_ignored_instruction_counts(
    report: &mut EfficiencyReport,
    ignored: IgnoredInstructionReportCounts,
) {
    let detector = DetectorId::IgnoredInstructions;
    let index = detector.index();
    let counts = &mut report.detectors[index];
    counts.eligible = ignored.eligible;
    counts.assessed = ignored.assessed;
    counts.finding = ignored.finding_sessions;
    counts.clean = ignored.clean;
    counts.unavailable = ignored.unavailable;
    counts.not_applicable = ignored.not_applicable;
    report.finding_agents[index] = ignored.finding_agents;
    report.clean_agents[index] = ignored.clean_agents;
    report.detector_statuses[index] = if ignored.finding_sessions > 0 {
        DetectorStatus::Findings(DetectorFindings {
            finding_sessions: ignored.finding_sessions,
            examples: ignored.examples,
        })
    } else if ignored.eligible > 0 && ignored.unavailable == 0 && ignored.clean == ignored.eligible
    {
        DetectorStatus::Clean
    } else {
        DetectorStatus::NotAssessed(if ignored.eligible == 0 {
            NotAssessedReason::CapabilityMissing
        } else {
            NotAssessedReason::IncompleteEvidence
        })
    };
    report.detector_estimated_token_burn_basis_points[index] = None;
}

pub(crate) fn ignored_result_has_scoped_no_issues(
    result: &antiburn_local::analysis::ignored_instructions::AssessmentResult,
    findings: &[Finding],
) -> bool {
    findings.is_empty()
        && result.coverage.unselected_pairs == 0
        && result.coverage.skipped_rules.is_empty()
        && result.coverage.skipped_actions.is_empty()
        && !result.coverage.processing_limit_reached
        && result.coverage.limitations.is_empty()
        && result.pending_rules.is_empty()
        && result.unassessed_comparisons.is_empty()
}
