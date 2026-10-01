//! Bounded construction of ignored-instruction assessment plans.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::assessment::{
    ASSESSMENT_CHUNKING_REVISION, ASSESSMENT_MODEL, ASSESSMENT_PROJECTION_REVISION,
    ASSESSMENT_QUESTION_REVISION, ASSESSMENT_REDUCER_REVISION, AssessmentCoverage, AssessmentInput,
    AssessmentPlan, CandidateComparison, CounterEvidence, INPUT_SELECTION,
    InstructionSourceCoverage, MAX_ASSESSMENT_CANDIDATES, RuleActionRef,
};
use super::evidence::{ContentAction, content_action_digest};
use super::instructions::{
    InstructionContentClass, InstructionRuleSection, InstructionSnapshot, sha256_hex,
};
use crate::analysis::jev::{JevError, JevSessionContext};

const MAX_CONTEXT_EVENTS: usize = 3;
pub(super) const MAX_COUNTER_EVIDENCE: usize = 4;
pub(super) const MAX_RULE_TEXT_BYTES: usize = 2 * 1024;
pub(super) const MAX_ACTION_TEXT_BYTES: usize = 1024;
const MAX_CONTEXT_TEXT_BYTES: usize = 192;
type RuleRange<'a> = (
    &'a InstructionSnapshot,
    &'a InstructionRuleSection,
    usize,
    usize,
);
type ActionRange<'a> = (&'a ContentAction, usize, usize);

/// Attach the bounded rule/action plan without duplicating its private content.
pub fn build_jev_context(input: &AssessmentInput) -> Result<JevSessionContext, JevError> {
    let plan = build_assessment_plan(input.clone());
    let input_revision = plan.input_revision.clone();
    let session_identity = plan.session_identity_digest.clone();
    let limitations = plan.coverage.limitations.clone();
    let check_context = serde_json::json!({"assessment_plan": plan, "incremental_identity": {
        "incarnation": input.incarnation,
        "source_generation": input.source_generation,
        "source_format": input.content.source_format,
        "activity_after_ms": input.activity_after_ms,
        "boundary_positions": input.boundary_positions,
    }});
    let evidence_store = super::evidence::selected_evidence_store(
        &input.content.actions,
        INPUT_SELECTION,
        input.content.publication_fence,
    )?;
    let reference_fields = serde_json::to_value(&input.content.instructions)
        .map_err(|_| JevError::InvalidCheckContext)?;
    let reference_identity = sha256_hex(
        &serde_json::to_vec(&(
            input
                .content
                .instructions
                .iter()
                .map(|snapshot| (&snapshot.id, &snapshot.digest))
                .collect::<Vec<_>>(),
            &input_revision,
        ))
        .map_err(|_| JevError::InvalidCheckContext)?,
    );
    Ok(JevSessionContext {
        input_revision: input_revision.clone(),
        session_identity,
        check_context,
        limitations,
        evidence_store,
        reference_snapshots: vec![crate::analysis::jev::JevReferenceSnapshot {
            kind: "instruction_snapshot".to_owned(),
            identity: reference_identity,
            revision: input_revision,
            fields: reference_fields,
        }],
    })
}

/// Add saved candidates to a continuation page and include earlier events from
/// that page. Keep the source identities local to the check context.
pub fn extend_jev_context_with_history(
    context: &mut JevSessionContext,
    carried_comparisons: &mut [CandidateComparison],
    page_actions: &[ContentAction],
    prior_history_complete: bool,
) -> Result<(), JevError> {
    if carried_comparisons.is_empty() {
        return Ok(());
    }
    let mut assessment: AssessmentPlan =
        serde_json::from_value(context.check_context["assessment_plan"].clone())
            .map_err(|_| JevError::InvalidCheckContext)?;
    if assessment.input_revision != context.input_revision {
        return Err(JevError::InvalidCheckContext);
    }
    let mut comparison_ids = assessment
        .comparisons
        .iter()
        .map(|comparison| comparison.id.clone())
        .collect::<BTreeSet<_>>();
    let mut revision_material = assessment.input_revision.clone();
    for carried in carried_comparisons {
        *carried = extend_comparison_with_history(carried, page_actions, prior_history_complete);
        revision_material.push('\0');
        revision_material.push_str(&carried.id);
        revision_material.push('\0');
        revision_material.push_str(
            &serde_json::to_string(&carried.counterevidence)
                .map_err(|_| JevError::InvalidCheckContext)?,
        );
        if comparison_ids.insert(carried.id.clone()) {
            assessment.current_action_digests.insert(
                carried.reference.action_id.clone(),
                carried.reference.action_digest.clone(),
            );
            assessment.current_rule_ids.insert((
                carried.reference.instruction_id.clone(),
                carried.reference.instruction_digest.clone(),
                carried.reference.rule_id.clone(),
            ));
            assessment.comparisons.push(carried.clone());
        }
    }
    assessment.input_revision = sha256_hex(revision_material.as_bytes());
    context
        .input_revision
        .clone_from(&assessment.input_revision);
    context.limitations = assessment.coverage.limitations.clone();
    context.check_context["assessment_plan"] =
        serde_json::to_value(assessment).map_err(|_| JevError::InvalidCheckContext)?;
    Ok(())
}

/// Prepare one immutable comparison per selected rule/action pair.
pub fn build_assessment_plan(input: AssessmentInput) -> AssessmentPlan {
    let content = &input.content;
    let mut limitations = content.limitations.clone();
    let skipped_rules = content
        .instructions
        .iter()
        .flat_map(|instruction| {
            instruction
                .sections
                .iter()
                .filter(|rule| {
                    rule.content_class == InstructionContentClass::RequirementCandidate
                        && !rule.evaluable
                })
                .map(move |rule| format!("{}:{}", instruction.id, rule.id))
        })
        .collect::<Vec<_>>();
    if !skipped_rules.is_empty() {
        limitations.push("instruction_rule_not_evaluable".to_owned());
    }
    let rule_groups: Vec<Vec<_>> =
        content
            .instructions
            .iter()
            .map(|instruction| {
                instruction
                    .sections
                    .iter()
                    .filter(move |rule| {
                        rule.content_class == InstructionContentClass::RequirementCandidate
                    })
                    .map(move |rule| (instruction, rule))
                    .filter(|(_, rule)| rule.evaluable)
                    .flat_map(|(instruction, rule)| {
                        rule_text_ranges(&rule.text).into_iter().map(
                            move |(text_start, text_end)| (instruction, rule, text_start, text_end),
                        )
                    })
                    .collect()
            })
            .collect();
    let mut rules = Vec::new();
    for index in 0..rule_groups.iter().map(Vec::len).max().unwrap_or_default() {
        for group in &rule_groups {
            if let Some(rule) = group.get(index) {
                rules.push(*rule);
            }
        }
    }
    let actions: Vec<_> = content
        .actions
        .iter()
        .filter(|action| {
            is_agent_action(action)
                && input
                    .activity_after_ms
                    .is_none_or(|watermark| match action.timestamp_ms {
                        Some(timestamp) => timestamp >= watermark,
                        None => input.boundary_positions.iter().any(|(source, position)| {
                            (source == "*"
                                || sha256_hex(source.as_bytes())
                                    == action.reference.source_key_digest)
                                && action.reference.turn_index > *position
                        }),
                    })
        })
        .flat_map(|action| {
            action_text_ranges(&action.text)
                .into_iter()
                .map(move |(text_start, text_end)| (action, text_start, text_end))
        })
        .collect();
    let mut action_digests = BTreeMap::new();
    let mut action_terms_by_id = BTreeMap::new();
    for action in &content.actions {
        action_terms_by_id
            .entry(action.reference.id.clone())
            .or_insert_with(|| action_meaningful_terms(action));
    }
    for (action, _, _) in &actions {
        action_digests
            .entry(action.reference.id.clone())
            .or_insert_with(|| content_action_digest(action));
    }
    let branch_order = branch_order_index(&content.actions);
    let rule_terms = rules
        .iter()
        .map(|(_, rule, start, end)| {
            meaningful_terms(rule.text.get(*start..*end).unwrap_or(&rule.text))
        })
        .collect::<Vec<_>>();
    let evaluable_rules = rules.as_slice();
    let candidate_pairs = evaluable_rules.len().saturating_mul(actions.len());
    let start = input
        .comparison_after
        .as_deref()
        .and_then(|cursor| cursor.strip_prefix("pair:"))
        .and_then(|offset| offset.parse::<usize>().ok())
        .filter(|offset| *offset <= candidate_pairs)
        .unwrap_or(0);
    let comparisons = select_comparisons(
        evaluable_rules,
        &actions,
        start,
        &ComparisonIndex {
            prior_history_complete: input.prior_history_complete,
            branch_order: &branch_order.actions_by_branch,
            branch_positions: &branch_order.positions_by_action,
            action_digests: &action_digests,
            rule_terms: &rule_terms,
            action_terms: &action_terms_by_id,
        },
    );
    let mut rules_by_source = BTreeMap::<String, BTreeSet<(String, String)>>::new();
    let mut ranges_by_source = BTreeMap::<String, usize>::new();
    for instruction in &content.instructions {
        rules_by_source
            .entry(instruction.source.clone())
            .or_default();
        ranges_by_source
            .entry(instruction.source.clone())
            .or_default();
    }
    for (instruction, rule, _, _) in evaluable_rules {
        rules_by_source
            .entry(instruction.source.clone())
            .or_default()
            .insert((instruction.id.clone(), rule.id.clone()));
        *ranges_by_source
            .entry(instruction.source.clone())
            .or_default() += 1;
    }
    let mut instruction_sources = ranges_by_source
        .into_iter()
        .map(|(source, rule_ranges)| InstructionSourceCoverage {
            eligible_rules: rules_by_source.get(&source).map_or(0, BTreeSet::len),
            candidate_pairs: rule_ranges.saturating_mul(actions.len()),
            selected_comparisons: 0,
            source,
        })
        .collect::<Vec<_>>();
    for comparison in &comparisons {
        if let Some(source) = instruction_sources
            .iter_mut()
            .find(|source| source.source == comparison.reference.source)
        {
            source.selected_comparisons = source.selected_comparisons.saturating_add(1);
        }
    }
    let current_action_digests = action_digests;
    let current_rule_ids = rules
        .iter()
        .map(|(instruction, rule, _, _)| {
            (
                instruction.id.clone(),
                instruction.digest.clone(),
                rule.id.clone(),
            )
        })
        .collect();
    let end = start.saturating_add(comparisons.len());
    let processing_limit_reached = end < candidate_pairs;
    if processing_limit_reached {
        limitations.push("assessment_candidate_limit".to_owned());
    }
    let unselected_pairs = candidate_pairs.saturating_sub(end);
    let next_comparison_cursor = (end < candidate_pairs).then(|| format!("pair:{end}"));

    let mut unique_rules = BTreeSet::new();
    for (instruction, rule, _, _) in rules {
        unique_rules.insert((instruction.id.as_str(), rule.id.as_str()));
    }
    let mut revision_hasher = Sha256::new();
    revision_hasher.update(content.selected_input_digest.as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(input.incarnation.to_string().as_bytes());
    revision_hasher.update(
        input
            .comparison_after
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    revision_hasher.update(b"\0");
    revision_hasher.update(input.source_generation.to_string().as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(content.publication_fence.to_string().as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(
        input
            .activity_after_ms
            .unwrap_or_default()
            .to_string()
            .as_bytes(),
    );
    revision_hasher.update(b"\0");
    revision_hasher.update(if input.prior_history_complete {
        "prior-history-complete"
    } else {
        "prior-history-incomplete"
    });
    for (source, position) in &input.boundary_positions {
        revision_hasher.update(source.as_bytes());
        revision_hasher.update(position.to_string().as_bytes());
    }
    revision_hasher.update(b"\0");
    revision_hasher.update(ASSESSMENT_MODEL.as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(ASSESSMENT_PROJECTION_REVISION.to_string().as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(ASSESSMENT_CHUNKING_REVISION.to_string().as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(ASSESSMENT_QUESTION_REVISION.to_string().as_bytes());
    revision_hasher.update(b"\0");
    revision_hasher.update(ASSESSMENT_REDUCER_REVISION.to_string().as_bytes());
    let input_revision = digest_to_hex(revision_hasher.finalize().as_slice());
    limitations.sort();
    limitations.dedup();
    AssessmentPlan {
        input_revision,
        observable_obligations: BTreeMap::new(),
        read_request_orders: super::assessment::exact_read_orders(
            &comparisons,
            content,
            input.prior_history_complete,
        ),
        earlier_read_only_actions: super::assessment::earlier_read_only_actions(
            &comparisons,
            content,
        ),
        session_identity_digest: content.session_identity_digest.clone(),
        source_generation: input.source_generation,
        source_fingerprint: input.source_fingerprint,
        publication_fence: content.publication_fence,
        activity_after_ms: input.activity_after_ms,
        model_version: ASSESSMENT_MODEL.to_owned(),
        projection_revision: ASSESSMENT_PROJECTION_REVISION,
        chunking_revision: ASSESSMENT_CHUNKING_REVISION,
        question_revision: ASSESSMENT_QUESTION_REVISION,
        reducer_revision: ASSESSMENT_REDUCER_REVISION,
        complete_input: content.complete,
        next_comparison_cursor,
        current_action_digests,
        current_rule_ids,
        coverage: AssessmentCoverage {
            eligible_rules: unique_rules.len(),
            candidate_pairs,
            selected_comparisons: end.saturating_sub(start),
            unselected_pairs,
            skipped_rules,
            skipped_actions: Vec::new(),
            processing_limit_reached,
            limitations,
            reassessed_comparison_ids: Vec::new(),
            reassessed_rule_ids: Vec::new(),
            reassessed_finding_ids: Vec::new(),
            instruction_sources,
        },
        comparisons,
    }
}

struct ComparisonIndex<'a> {
    prior_history_complete: bool,
    branch_order: &'a BTreeMap<(String, String), Vec<&'a ContentAction>>,
    branch_positions: &'a BTreeMap<(String, String, String), usize>,
    action_digests: &'a BTreeMap<String, String>,
    rule_terms: &'a [BTreeSet<String>],
    action_terms: &'a BTreeMap<String, BTreeSet<String>>,
}

fn select_comparisons<'a>(
    rules: &[RuleRange<'a>],
    actions: &[ActionRange<'a>],
    start: usize,
    index: &ComparisonIndex<'a>,
) -> Vec<CandidateComparison> {
    if rules.is_empty() || actions.is_empty() || start >= rules.len().saturating_mul(actions.len())
    {
        return Vec::new();
    }
    let starts = candidate_shell_starts(rules.len(), actions.len());
    let first_diagonal = starts
        .partition_point(|offset| *offset <= start)
        .saturating_sub(1);
    let first_shell_offset = start.saturating_sub(starts[first_diagonal]);
    let mut comparisons = Vec::with_capacity(MAX_ASSESSMENT_CANDIDATES);
    for diagonal in first_diagonal..rules.len().max(actions.len()) {
        let skip = if diagonal == first_diagonal {
            first_shell_offset
        } else {
            0
        };
        let shell_size = candidate_shell_size(rules.len(), actions.len(), diagonal);
        for shell_index in skip..shell_size {
            let rule_index = if diagonal < actions.len()
                && shell_index < diagonal.min(rules.len().saturating_sub(1)) + 1
            {
                shell_index.min(rules.len() - 1)
            } else {
                diagonal
            };
            let (instruction, rule, rule_start, rule_end) = rules[rule_index];
            let candidate = if diagonal < actions.len()
                && shell_index < diagonal.min(rules.len().saturating_sub(1)) + 1
            {
                let (action, action_start, action_end) = actions[diagonal];
                (
                    instruction,
                    rule,
                    rule_index,
                    rule_start,
                    rule_end,
                    action,
                    action_start,
                    action_end,
                )
            } else {
                let row_index = shell_index
                    - if diagonal < actions.len() {
                        diagonal.min(rules.len().saturating_sub(1)) + 1
                    } else {
                        0
                    };
                let (action, action_start, action_end) = actions[row_index];
                (
                    instruction,
                    rule,
                    rule_index,
                    rule_start,
                    rule_end,
                    action,
                    action_start,
                    action_end,
                )
            };
            let (
                instruction,
                rule,
                rule_index,
                rule_start,
                rule_end,
                action,
                action_start,
                action_end,
            ) = candidate;
            comparisons.push(make_comparison(
                CandidateCoordinate {
                    instruction,
                    rule,
                    rule_range: (rule_start, rule_end),
                    action,
                    action_range: (action_start, action_end),
                },
                index,
                &index.rule_terms[rule_index],
            ));
            if comparisons.len() == MAX_ASSESSMENT_CANDIDATES {
                return comparisons;
            }
        }
    }
    comparisons
}

pub(super) struct BranchOrderIndex<'a> {
    pub(super) actions_by_branch: BTreeMap<(String, String), Vec<&'a ContentAction>>,
    pub(super) positions_by_action: BTreeMap<(String, String, String), usize>,
}

pub(super) fn branch_order_index(actions: &[ContentAction]) -> BranchOrderIndex<'_> {
    let mut index = BranchOrderIndex {
        actions_by_branch: BTreeMap::new(),
        positions_by_action: BTreeMap::new(),
    };
    for action in actions {
        let branch_key = (
            action.reference.thread_digest.clone(),
            action.turn_scope.clone(),
        );
        let branch = index
            .actions_by_branch
            .entry(branch_key.clone())
            .or_default();
        index.positions_by_action.insert(
            (branch_key.0, branch_key.1, action.reference.id.clone()),
            branch.len(),
        );
        branch.push(action);
    }
    index
}

fn candidate_shell_starts(rule_count: usize, action_count: usize) -> Vec<usize> {
    let dimensions = rule_count.max(action_count);
    let mut starts = Vec::with_capacity(dimensions + 1);
    let mut offset = 0usize;
    for diagonal in 0..dimensions {
        starts.push(offset);
        offset = offset.saturating_add(candidate_shell_size(rule_count, action_count, diagonal));
    }
    starts.push(offset);
    starts
}

fn candidate_shell_size(rule_count: usize, action_count: usize, diagonal: usize) -> usize {
    let action_column = if action_count > 0 && diagonal < action_count && rule_count > 0 {
        diagonal.min(rule_count - 1) + 1
    } else {
        0
    };
    let rule_row = if diagonal < rule_count {
        diagonal.min(action_count)
    } else {
        0
    };
    action_column.saturating_add(rule_row)
}

/// Add earlier normalized events from an older content page to one saved
/// comparison. Source order decides which events are earlier; relevance only
/// chooses which bounded events to keep.
pub fn extend_comparison_with_history(
    comparison: &CandidateComparison,
    page_actions: &[ContentAction],
    prior_history_complete: bool,
) -> CandidateComparison {
    let context_ids = comparison
        .context
        .iter()
        .chain(&comparison.counterevidence)
        .map(|event| event.action_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut earlier = page_actions
        .iter()
        .filter(|action| {
            action.reference.thread_digest == comparison.source_thread_digest
                && action.turn_scope == comparison.source_turn_scope
                && action.reference.turn_index < comparison.source_turn_index
                && action.reference.id != comparison.reference.action_id
                && !context_ids.contains(action.reference.id.as_str())
        })
        .enumerate()
        .collect::<Vec<_>>();
    let rule_terms = meaningful_terms(rule_text_fragment(comparison));
    earlier.sort_by(|(left_index, left), (right_index, right)| {
        history_relevance(&rule_terms, right)
            .cmp(&history_relevance(&rule_terms, left))
            .then_with(|| right.reference.turn_index.cmp(&left.reference.turn_index))
            .then_with(|| right_index.cmp(left_index))
    });
    let omitted = earlier.len() > MAX_COUNTER_EVIDENCE;
    let mut comparison = comparison.clone();
    comparison.counterevidence.extend(
        earlier
            .into_iter()
            .take(MAX_COUNTER_EVIDENCE)
            .map(|(_, action)| counter_event(action, MAX_CONTEXT_TEXT_BYTES)),
    );
    comparison.counterevidence.sort_by(|left, right| {
        left.source_order
            .cmp(&right.source_order)
            .then_with(|| left.action_id.cmp(&right.action_id))
    });
    comparison
        .counterevidence
        .dedup_by(|left, right| left.action_id == right.action_id);
    if comparison.counterevidence.len() > MAX_COUNTER_EVIDENCE {
        comparison
            .counterevidence
            .drain(..comparison.counterevidence.len() - MAX_COUNTER_EVIDENCE);
        comparison.earlier_history_truncated = true;
    }
    comparison.earlier_history_truncated |= omitted
        || comparison
            .counterevidence
            .iter()
            .any(|event| event.truncated);
    comparison.prior_history_complete = prior_history_complete;
    comparison
}

pub(super) fn history_relevance(rule_terms: &BTreeSet<String>, action: &ContentAction) -> usize {
    let action_terms = meaningful_terms(&format!(
        "{} {} {}",
        action.text,
        action.tool_name.as_deref().unwrap_or_default(),
        action.tool_call_id.as_deref().unwrap_or_default()
    ));
    rule_terms
        .iter()
        .filter(|term| action_terms.contains(*term))
        .count()
}

pub(super) fn action_meaning(action: &CounterEvidence) -> &'static str {
    match action.kind.as_str() {
        "tool_input" => {
            "The assistant asked a tool to run this command or use these arguments. The text is the tool request, not the tool result."
        }
        _ => {
            "This is text the assistant wrote. A past-tense report of work done describes that completed action; a plan does not. It is not a tool result."
        }
    }
}

fn is_agent_action(action: &ContentAction) -> bool {
    !action.context_only
        && matches!(action.turn_role.as_str(), "assistant" | "tool")
        && matches!(
            action.kind.as_str(),
            "assistant" | "assistant_text" | "tool_input"
        )
}

fn action_meaningful_terms(action: &ContentAction) -> BTreeSet<String> {
    meaningful_terms(&format!(
        "{} {} {}",
        action.text,
        action.tool_name.as_deref().unwrap_or_default(),
        action.tool_call_id.as_deref().unwrap_or_default()
    ))
}

fn overlap_score(rule_terms: &BTreeSet<String>, action_terms: &BTreeSet<String>) -> usize {
    rule_terms
        .iter()
        .filter(|term| action_terms.contains(*term))
        .count()
}

pub(super) fn meaningful_terms(text: &str) -> BTreeSet<String> {
    text.split(|character: char| {
        !character.is_alphanumeric() && character != '_' && character != '/'
    })
    .filter(|term| term.len() >= 3)
    .map(|term| {
        let mut term = term.to_ascii_lowercase();
        for suffix in ["ing", "ed", "al", "es", "s"] {
            if term.len() > suffix.len() + 3 && term.ends_with(suffix) {
                term.truncate(term.len() - suffix.len());
                break;
            }
        }
        term
    })
    .filter(|term| {
        !matches!(
            term.as_str(),
            "the"
                | "and"
                | "for"
                | "with"
                | "from"
                | "this"
                | "that"
                | "must"
                | "not"
                | "before"
                | "after"
                | "when"
                | "then"
                | "only"
                | "any"
                | "all"
        )
    })
    .collect()
}

fn comparison_identity(
    instruction: &InstructionSnapshot,
    rule: &InstructionRuleSection,
    action: &ContentAction,
    rule_text_range: (usize, usize),
    action_text_range: (usize, usize),
) -> String {
    sha256_hex(
        format!(
            "{}\0{}\0{}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{}",
            instruction.id,
            instruction.digest,
            instruction.provenance.as_str(),
            instruction.scope,
            rule.id,
            action.reference.id,
            rule_text_range.0,
            rule_text_range.1,
            action_text_range.0,
            action_text_range.1
        )
        .as_bytes(),
    )
}

fn digest_to_hex(digest: &[u8]) -> String {
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

struct CandidateCoordinate<'a> {
    instruction: &'a InstructionSnapshot,
    rule: &'a InstructionRuleSection,
    rule_range: (usize, usize),
    action: &'a ContentAction,
    action_range: (usize, usize),
}

fn make_comparison(
    coordinate: CandidateCoordinate<'_>,
    index: &ComparisonIndex<'_>,
    rule_terms: &BTreeSet<String>,
) -> CandidateComparison {
    let CandidateCoordinate {
        instruction,
        rule,
        rule_range: rule_text_range,
        action,
        action_range: action_text_range,
    } = coordinate;
    let action_digest = index
        .action_digests
        .get(&action.reference.id)
        .map(String::as_str)
        .unwrap_or_default();
    let id = comparison_identity(
        instruction,
        rule,
        action,
        rule_text_range,
        action_text_range,
    );
    let (rule_text_start, rule_text_end) = rule_text_range;
    let (action_text_start, action_text_end) = action_text_range;
    let branch_order = index
        .branch_order
        .get(&(
            action.reference.thread_digest.clone(),
            action.turn_scope.clone(),
        ))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let candidate_position = index
        .branch_positions
        .get(&(
            action.reference.thread_digest.clone(),
            action.turn_scope.clone(),
            action.reference.id.clone(),
        ))
        .copied()
        .unwrap_or(0);
    let context_indices = context_indices(candidate_position, branch_order.len());
    let context: Vec<CounterEvidence> = context_indices
        .into_iter()
        .filter_map(|index| branch_order.get(index).copied())
        .take(MAX_CONTEXT_EVENTS)
        .map(|event| counter_event(event, MAX_CONTEXT_TEXT_BYTES))
        .collect();
    let context_truncated = branch_order.len() > context.len().saturating_add(1);
    let context_ids: BTreeSet<_> = context
        .iter()
        .map(|event| event.action_id.as_str())
        .collect();
    let mut earlier = branch_order
        .iter()
        .take(candidate_position)
        .enumerate()
        .filter(|(_, event)| {
            event.reference.id != action.reference.id
                && !context_ids.contains(event.reference.id.as_str())
        })
        .map(|(index, event)| (index, *event))
        .collect::<Vec<_>>();
    let relevance_order =
        |(left_index, left): &(usize, &ContentAction),
         (right_index, right): &(usize, &ContentAction)| {
            overlap_score(rule_terms, &index.action_terms[&left.reference.id])
                .cmp(&overlap_score(
                    rule_terms,
                    &index.action_terms[&right.reference.id],
                ))
                .reverse()
                .then_with(|| right_index.cmp(left_index))
        };
    let mut earlier_history_truncated = earlier.len() > MAX_COUNTER_EVIDENCE;
    if earlier_history_truncated {
        earlier.select_nth_unstable_by(MAX_COUNTER_EVIDENCE, relevance_order);
        earlier.truncate(MAX_COUNTER_EVIDENCE);
    }
    earlier.sort_by(relevance_order);
    let counterevidence = earlier
        .into_iter()
        .take(MAX_COUNTER_EVIDENCE)
        .map(|(_, event)| counter_event(event, MAX_CONTEXT_TEXT_BYTES))
        .collect::<Vec<_>>();
    earlier_history_truncated |= counterevidence.iter().any(|event| event.truncated);
    let reference = RuleActionRef {
        instruction_id: instruction.id.clone(),
        instruction_digest: instruction.digest.clone(),
        rule_id: rule.id.clone(),
        rule_heading: rule.heading.clone(),
        start_line: rule.start_line,
        end_line: rule.end_line,
        source: instruction.source.clone(),
        provenance: instruction.provenance,
        scope: instruction.scope,
        action_id: action.reference.id.clone(),
        action_digest: action_digest.to_owned(),
        action_timestamp_ms: action.timestamp_ms,
        action_stable: action.reference.stable,
    };
    CandidateComparison {
        id: id.clone(),
        reference,
        source_thread_digest: action.reference.thread_digest.clone(),
        source_turn_index: action.reference.turn_index,
        source_turn_scope: action.turn_scope.clone(),
        rule_text: rule.text.clone(),
        rule_text_start,
        rule_text_end,
        action: counter_event_with_range(
            action,
            MAX_ACTION_TEXT_BYTES,
            Some((action_text_start, action_text_end)),
        ),
        action_text_start,
        action_text_end,
        context,
        context_truncated,
        counterevidence,
        earlier_history_truncated,
        prior_history_complete: index.prior_history_complete,
    }
}

fn context_indices(candidate: usize, length: usize) -> Vec<usize> {
    let mut indices = Vec::with_capacity(MAX_CONTEXT_EVENTS);
    for distance in 1..=MAX_CONTEXT_EVENTS {
        if let Some(previous) = candidate.checked_sub(distance) {
            indices.push(previous);
        }
        let next = candidate.saturating_add(distance);
        if next < length {
            indices.push(next);
        }
    }
    indices.sort_unstable();
    indices.truncate(MAX_CONTEXT_EVENTS);
    indices
}

pub(super) fn counter_event(action: &ContentAction, max_text_bytes: usize) -> CounterEvidence {
    counter_event_with_range(action, max_text_bytes, None)
}

fn counter_event_with_range(
    action: &ContentAction,
    max_text_bytes: usize,
    range: Option<(usize, usize)>,
) -> CounterEvidence {
    let source_text = range
        .and_then(|(start, end)| action.text.get(start..end))
        .unwrap_or(&action.text);
    let (text, text_truncated) = bounded_text(source_text, max_text_bytes);
    CounterEvidence {
        action_id: action.reference.id.clone(),
        source_order: action.reference.turn_index,
        role: action.turn_role.clone(),
        kind: action.kind.clone(),
        timestamp_ms: action.timestamp_ms,
        tool_name: action.tool_name.clone(),
        text,
        truncated: action.truncated || text_truncated,
    }
}

pub(super) fn action_text_ranges(text: &str) -> Vec<(usize, usize)> {
    advancing_text_ranges(text, MAX_ACTION_TEXT_BYTES)
}

pub(super) fn bounded_text(text: &str, max_bytes: usize) -> (String, bool) {
    let end = text
        .char_indices()
        .take_while(|(index, character)| index.saturating_add(character.len_utf8()) <= max_bytes)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    (text[..end].to_owned(), end < text.len())
}

pub(super) fn rule_text_fragment(comparison: &CandidateComparison) -> &str {
    comparison
        .rule_text
        .get(comparison.rule_text_start..comparison.rule_text_end)
        .unwrap_or(&comparison.rule_text)
}

pub(super) fn rule_text_ranges(text: &str) -> Vec<(usize, usize)> {
    text_ranges(text, MAX_RULE_TEXT_BYTES)
}

pub(super) fn text_ranges(text: &str, window_bytes: usize) -> Vec<(usize, usize)> {
    advancing_text_ranges(text, window_bytes)
}

fn advancing_text_ranges(text: &str, window_bytes: usize) -> Vec<(usize, usize)> {
    crate::analysis::jev::text_ranges::text_ranges(text, window_bytes, MAX_CONTEXT_TEXT_BYTES)
}
