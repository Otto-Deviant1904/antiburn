//! Reusable TypeSafe request and check contracts.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const PINNED_MODEL: &str = "jev-1.13.0";
/// Bound the full serialized request before checking the returned token usage.
pub const MAX_REQUEST_BYTES: usize = 60 * 1024;
/// Use a conservative byte proxy for Jev's state-plus-question token limit.
pub const MAX_STATE_AND_LONGEST_QUESTION_BYTES: usize = 30 * 1024;
/// Jev rejects requests that exceed its current total input-token limit.
pub const MAX_REQUEST_TOKENS: u64 = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_QUESTIONS_PER_REQUEST: usize = 128;
pub const MAX_PARALLEL_REQUESTS: usize = 8;
const REQUEST_START_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Sanitized failures shared by request preparation, TypeSafe transport, and
/// answer validation. Variants never contain credentials, request bodies, or
/// provider response text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JevError {
    RequestSerialization,
    EmptyQuestions,
    QuestionLimitExceeded,
    UnsupportedModel,
    RequestTooLarge { bytes: usize, maximum: usize },
    ResponseModelMismatch,
    ResponseAnswerCountMismatch,
    ResponseAnswerMissing,
    ResponseAnswerTypeMismatch,
    InvalidChoiceDistribution,
    InvalidNoulProbability,
    InvalidScoreDistribution,
    InvalidProbabilitySum,
    WorkItemHasNoAnswers,
    AuthenticationRejected,
    InvalidRequestSchema,
    RateLimited { retry_after: Option<Duration> },
    ProviderOverloaded { retry_after: Option<Duration> },
    ProviderUnavailable,
    RequestOutcomeUnknown,
    ResponseTooLarge,
    ResponseDecode,
    ResponseUsageExceeded,
    ProgressStorageFailure,
    Cancelled,
    InvalidCheckContext,
    InvalidCheckPlan,
}

impl fmt::Display for JevError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestSerialization => {
                formatter.write_str("Jev request could not be serialized")
            }
            Self::EmptyQuestions => formatter.write_str("Jev request has no questions"),
            Self::QuestionLimitExceeded => {
                formatter.write_str("Jev request exceeds the question limit")
            }
            Self::UnsupportedModel => formatter.write_str("Jev request uses an unsupported model"),
            Self::RequestTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "Jev request is {bytes} bytes; the limit is {maximum} bytes"
                )
            }
            Self::ResponseModelMismatch => {
                formatter.write_str("Jev response model does not match the request")
            }
            Self::ResponseAnswerCountMismatch => {
                formatter.write_str("Jev response has an unexpected answer count")
            }
            Self::ResponseAnswerMissing => formatter.write_str("Jev response is missing an answer"),
            Self::ResponseAnswerTypeMismatch => {
                formatter.write_str("Jev response answer has the wrong type")
            }
            Self::InvalidChoiceDistribution => {
                formatter.write_str("Jev response has an invalid choice distribution")
            }
            Self::InvalidNoulProbability => {
                formatter.write_str("Jev response has an invalid Noul probability")
            }
            Self::InvalidScoreDistribution => {
                formatter.write_str("Jev response has an invalid score distribution")
            }
            Self::InvalidProbabilitySum => {
                formatter.write_str("Jev response probabilities do not sum to one")
            }
            Self::WorkItemHasNoAnswers => {
                formatter.write_str("Jev response has no answers for a work item")
            }
            Self::AuthenticationRejected => formatter.write_str("TypeSafe rejected the API key"),
            Self::InvalidRequestSchema => {
                formatter.write_str("TypeSafe rejected the request schema")
            }
            Self::RateLimited { .. } => formatter.write_str("TypeSafe rate-limited the request"),
            Self::ProviderOverloaded { .. } => {
                formatter.write_str("TypeSafe is temporarily overloaded")
            }
            Self::ProviderUnavailable => formatter.write_str("TypeSafe is unavailable"),
            Self::RequestOutcomeUnknown => {
                formatter.write_str("TypeSafe request outcome is unknown")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("TypeSafe response exceeds the size limit")
            }
            Self::ResponseDecode => formatter.write_str("TypeSafe response could not be decoded"),
            Self::ResponseUsageExceeded => {
                formatter.write_str("TypeSafe response exceeded the usage limit")
            }
            Self::ProgressStorageFailure => {
                formatter.write_str("Burn Check progress could not be saved")
            }
            Self::Cancelled => formatter.write_str("Jev assessment was cancelled"),
            Self::InvalidCheckContext => formatter.write_str("Jev check context is invalid"),
            Self::InvalidCheckPlan => formatter.write_str("Jev check plan is invalid"),
        }
    }
}

impl std::error::Error for JevError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevRequest {
    pub model: String,
    pub state: Value,
    pub questions: BTreeMap<String, JevQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum JevQuestion {
    Choice {
        instructions: Value,
        criteria: BTreeMap<String, Value>,
    },
    Noul {
        instructions: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        criteria: Option<Value>,
    },
    Score {
        instructions: Value,
        criteria: Vec<Value>,
    },
}

impl JevQuestion {
    fn with_context_path(self, path: &str) -> Self {
        match self {
            Self::Choice {
                instructions,
                criteria,
            } => Self::Choice {
                instructions: contextual_instructions(instructions, path),
                criteria,
            },
            Self::Noul {
                instructions,
                criteria,
            } => Self::Noul {
                instructions: contextual_instructions(instructions, path),
                criteria,
            },
            Self::Score {
                instructions,
                criteria,
            } => Self::Score {
                instructions: contextual_instructions(instructions, path),
                criteria,
            },
        }
    }
}

fn contextual_instructions(instructions: Value, path: &str) -> Value {
    json!({
        "question": instructions,
        "context_path": format!("Use the evidence at `{path}`."),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevResponse {
    pub model: String,
    pub answers: BTreeMap<String, JevAnswer>,
    pub usage: JevUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum JevAnswer {
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
    Noul {
        noul: f64,
    },
    Score {
        score: f64,
        legend: BTreeMap<String, String>,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JevUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevSessionContext {
    /// Revision of the normalized facts supplied to this check.
    pub input_revision: String,
    pub session_identity: String,
    /// Immutable, check-owned facts selected from normalized session data.
    pub check_context: Value,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JevCheckRevisions {
    pub projection: u32,
    pub chunking: u32,
    pub questions: u32,
    pub reducer: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JevEvidenceRole {
    Instruction,
    Candidate,
    SupportingContext,
}

/// Maps one request-local input path to a stable source identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JevEvidenceReference {
    pub part_id: String,
    pub source_id: String,
    pub content_kind: String,
    pub role: JevEvidenceRole,
}

/// One check-owned bounded input window. `fields` is the only evidence sent to
/// Jev; `evidence` stays local and binds its request paths to source identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevInputWindow {
    pub fields: Value,
    pub evidence: Vec<JevEvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevWorkItem {
    /// Stable local identity. The request uses a separate request-local label.
    pub id: String,
    pub window: JevInputWindow,
    pub questions: BTreeMap<String, JevQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevCheckPlan {
    pub check_id: String,
    pub input_revision: String,
    pub revisions: JevCheckRevisions,
    pub work_items: Vec<JevWorkItem>,
    pub skipped_item_ids: Vec<String>,
    pub coverage: JevCoverage,
    /// Check-owned reducer state, rebuilt from the immutable input on resume.
    pub check_data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct JevCoverage {
    pub selected_items: usize,
    pub skipped_items: usize,
    pub not_selected_items: usize,
    pub processing_limit_reached: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevWorkItemResult {
    pub request_id: String,
    pub work_item_id: String,
    pub answers: BTreeMap<String, JevAnswer>,
    pub evidence: Vec<JevEvidenceReference>,
    pub model: String,
    pub usage: JevUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevRequestBatch {
    /// Local progress identity. It is separate from the provider cache digest.
    pub id: String,
    pub request: JevRequest,
    pub work_item_ids: Vec<String>,
    /// Maps returned question IDs to their owning work item and local ID.
    pub answer_owners: BTreeMap<String, (String, String)>,
    /// Keeps source identities local while answers return to their work items.
    pub evidence_owners: BTreeMap<String, Vec<JevEvidenceReference>>,
    /// Digest of only the serialized Jev request.
    pub digest: String,
    pub serialized_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct JevPackingResult {
    pub batches: Vec<JevRequestBatch>,
    pub skipped_item_ids: Vec<String>,
}

/// A check owns its normalized-fact projection, input windows, typed questions,
/// evidence mapping, revisions, and deterministic reduction. Each work item is
/// one bounded window. Its local evidence references mark instruction,
/// candidate, and supporting-context parts without sending source IDs to Jev.
/// The shared runner owns request packing, transport, limits, caching, usage
/// reservations, retries, progress persistence, cancellation, and resume.
pub trait JevCheck {
    type Result: Serialize;

    fn id(&self) -> &'static str;

    fn revisions(&self) -> JevCheckRevisions;

    /// Select normalized facts, build bounded windows, and prepare questions.
    fn prepare(&self, context: &JevSessionContext) -> Result<JevCheckPlan, JevError>;

    /// Return a uniquely identified bounded follow-up window when an initial
    /// result needs cross-chunk context. The runner applies the same caps.
    fn reconcile(
        &self,
        _work_item: &JevWorkItem,
        _initial_result: &JevWorkItemResult,
        _context: &JevSessionContext,
    ) -> Result<Option<JevWorkItem>, JevError> {
        Ok(None)
    }

    fn reduce(
        &self,
        plan: &JevCheckPlan,
        results: &[JevWorkItemResult],
        complete: bool,
    ) -> Result<Self::Result, JevError>;
}

/// Pack check-owned work items into requests under the full serialized-byte
/// ceiling. Each question receives an explicit path to its item context.
pub fn pack_work_items(items: &[JevWorkItem]) -> JevPackingResult {
    pack_work_items_bounded(items, MAX_REQUEST_BYTES)
}

fn pack_work_items_bounded(items: &[JevWorkItem], maximum_bytes: usize) -> JevPackingResult {
    let mut result = JevPackingResult::default();
    let mut current: Vec<JevWorkItem> = Vec::new();
    for item in items {
        if item.questions.is_empty() {
            result.skipped_item_ids.push(item.id.clone());
            continue;
        }
        let mut candidate = current.clone();
        candidate.push(item.clone());
        if candidate.len() > MAX_QUESTIONS_PER_REQUEST
            || build_batch(&candidate, maximum_bytes).is_none()
        {
            if !current.is_empty() {
                if let Some(batch) = build_batch(&current, maximum_bytes) {
                    result.batches.push(batch);
                }
                current.clear();
            }
            if build_batch(std::slice::from_ref(item), maximum_bytes).is_some() {
                current.push(item.clone());
            } else {
                result.skipped_item_ids.push(item.id.clone());
            }
        } else {
            current = candidate;
        }
    }
    if !current.is_empty()
        && let Some(batch) = build_batch(&current, maximum_bytes)
    {
        result.batches.push(batch);
    }
    result
}

/// Map one validated batch response back to check-owned work items.
pub fn unpack_jev_response(
    batch: &JevRequestBatch,
    response: &JevResponse,
) -> Result<Vec<JevWorkItemResult>, JevError> {
    validate_jev_response(response, &batch.request)?;
    let mut results = Vec::with_capacity(batch.work_item_ids.len());
    for work_item_id in &batch.work_item_ids {
        let answers = batch
            .answer_owners
            .iter()
            .filter(|(_, (owner, _))| owner == work_item_id)
            .filter_map(|(remote_id, (_, local_id))| {
                response
                    .answers
                    .get(remote_id)
                    .map(|answer| (local_id.clone(), answer.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        if answers.is_empty() {
            return Err(JevError::WorkItemHasNoAnswers);
        }
        let evidence = batch
            .evidence_owners
            .get(work_item_id)
            .cloned()
            .ok_or(JevError::InvalidCheckPlan)?;
        results.push(JevWorkItemResult {
            request_id: batch.id.clone(),
            work_item_id: work_item_id.clone(),
            answers,
            evidence,
            model: response.model.clone(),
            usage: response.usage,
        });
    }
    Ok(results)
}

fn build_batch(items: &[JevWorkItem], maximum_bytes: usize) -> Option<JevRequestBatch> {
    let mut state_items = Vec::with_capacity(items.len());
    let mut questions = BTreeMap::new();
    let mut answer_owners = BTreeMap::new();
    let mut evidence_owners = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        if item.id.is_empty()
            || item.window.evidence.iter().any(|evidence| {
                evidence.part_id.is_empty()
                    || evidence.source_id.is_empty()
                    || evidence.content_kind.is_empty()
            })
        {
            return None;
        }
        let part_ids = item
            .window
            .evidence
            .iter()
            .map(|evidence| evidence.part_id.as_str())
            .collect::<BTreeSet<_>>();
        if part_ids.len() != item.window.evidence.len() {
            return None;
        }
        state_items.push(json!({"id": format!("w_{index}"), "context": item.window.fields}));
        evidence_owners.insert(item.id.clone(), item.window.evidence.clone());
        for (question_id, question) in &item.questions {
            let response_id = format!(
                "q_{}",
                digest_hex(format!("{index}\0{question_id}").as_bytes())
            );
            questions.insert(
                response_id.clone(),
                question
                    .clone()
                    .with_context_path(&format!("work_items[{index}].context")),
            );
            answer_owners.insert(response_id, (item.id.clone(), question_id.clone()));
        }
    }
    if questions.len() > MAX_QUESTIONS_PER_REQUEST {
        return None;
    }
    let request = JevRequest {
        model: PINNED_MODEL.to_owned(),
        state: json!({"work_items": state_items}),
        questions,
    };
    let serialized = serde_json::to_vec(&request).ok()?;
    if serialized.len() > maximum_bytes {
        return None;
    }
    let state_bytes = serde_json::to_vec(&request.state).ok()?.len();
    let longest_question_bytes = request
        .questions
        .values()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .into_iter()
        .map(|question| question.len())
        .max()
        .unwrap_or_default();
    if state_bytes.saturating_add(longest_question_bytes) > MAX_STATE_AND_LONGEST_QUESTION_BYTES {
        return None;
    }
    let digest = digest_hex(&serialized);
    let evidence_identity = serde_json::to_string(&evidence_owners).ok()?;
    let id = digest_hex(
        format!(
            "{}\0{}\0{}",
            digest,
            items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>()
                .join("\0"),
            evidence_identity,
        )
        .as_bytes(),
    );
    Some(JevRequestBatch {
        id,
        request,
        work_item_ids: items.iter().map(|item| item.id.clone()).collect(),
        answer_owners,
        evidence_owners,
        digest,
        serialized_bytes: serialized.len(),
    })
}

/// Validate the shared typed HTTP contract before storing a response.
pub fn validate_jev_response(response: &JevResponse, request: &JevRequest) -> Result<(), JevError> {
    if response.model != request.model {
        return Err(JevError::ResponseModelMismatch);
    }
    if response.answers.len() != request.questions.len() {
        return Err(JevError::ResponseAnswerCountMismatch);
    }
    for (id, question) in &request.questions {
        let answer = response
            .answers
            .get(id)
            .ok_or(JevError::ResponseAnswerMissing)?;
        match (question, answer) {
            (
                JevQuestion::Choice { criteria, .. },
                JevAnswer::Choice {
                    choice,
                    probabilities,
                    confidence,
                },
            ) => {
                if !criteria.contains_key(choice)
                    || probabilities.len() != criteria.len()
                    || probabilities.keys().any(|key| !criteria.contains_key(key))
                    || probabilities
                        .values()
                        .any(|value| !valid_probability(*value))
                    || !valid_probability(*confidence)
                {
                    return Err(JevError::InvalidChoiceDistribution);
                }
                validate_probability_sum(probabilities.values().copied())?;
            }
            (JevQuestion::Noul { .. }, JevAnswer::Noul { noul }) => {
                if !valid_probability(*noul) {
                    return Err(JevError::InvalidNoulProbability);
                }
            }
            (
                JevQuestion::Score { criteria, .. },
                JevAnswer::Score {
                    score,
                    legend,
                    probabilities,
                    confidence,
                },
            ) => {
                if !score.is_finite()
                    || !valid_probability(*confidence)
                    || legend.len() != criteria.len()
                    || probabilities.len() != criteria.len()
                    || probabilities
                        .values()
                        .any(|value| !valid_probability(*value))
                {
                    return Err(JevError::InvalidScoreDistribution);
                }
                validate_probability_sum(probabilities.values().copied())?;
            }
            _ => return Err(JevError::ResponseAnswerTypeMismatch),
        }
    }
    Ok(())
}

/// Use the distribution to select an option when the returned choice disagrees.
pub fn highest_probability_choice<'a>(
    choice: &'a str,
    probabilities: &'a BTreeMap<String, f64>,
) -> Option<&'a str> {
    let (highest, maximum) = probabilities
        .iter()
        .max_by(|left, right| left.1.total_cmp(right.1))?;
    if probabilities
        .get(choice)
        .is_some_and(|selected| *selected + 0.000_001 >= *maximum)
    {
        Some(choice)
    } else {
        Some(highest)
    }
}

pub fn validate_jev_request(request: &JevRequest) -> Result<usize, JevError> {
    if request.model != PINNED_MODEL {
        return Err(JevError::UnsupportedModel);
    }
    if request.questions.is_empty() {
        return Err(JevError::EmptyQuestions);
    }
    if request.questions.len() > MAX_QUESTIONS_PER_REQUEST {
        return Err(JevError::QuestionLimitExceeded);
    }
    let bytes = serde_json::to_vec(request).map_err(|_| JevError::RequestSerialization)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(JevError::RequestTooLarge {
            bytes: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    let state_bytes = serde_json::to_vec(&request.state)
        .map_err(|_| JevError::RequestSerialization)?
        .len();
    let longest_question_bytes = request
        .questions
        .values()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JevError::RequestSerialization)?
        .into_iter()
        .map(|question| question.len())
        .max()
        .unwrap_or_default();
    if state_bytes.saturating_add(longest_question_bytes) > MAX_STATE_AND_LONGEST_QUESTION_BYTES {
        return Err(JevError::RequestTooLarge {
            bytes: state_bytes.saturating_add(longest_question_bytes),
            maximum: MAX_STATE_AND_LONGEST_QUESTION_BYTES,
        });
    }
    Ok(bytes.len())
}

/// Durable typed answers and local source bindings for one check assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct JevRunProgress {
    pub input_revision: String,
    pub results: BTreeMap<String, JevWorkItemResult>,
    pub completed_batch_ids: BTreeSet<String>,
    pub failed_item_ids: BTreeSet<String>,
    pub request_count: usize,
}

/// One complete or partial reduction from the shared check runner.
#[derive(Debug, Clone, PartialEq)]
pub struct JevExecutionOutcome<R> {
    pub result: R,
    pub progress: JevRunProgress,
    pub complete: bool,
    pub failure: Option<JevError>,
}

/// Execute check-owned windows, reconciliation, and deterministic reduction.
/// The shared desktop runner supplies batch execution and progress storage.
pub async fn run_jev_check<C, E, Fut, S>(
    check: &C,
    context: &JevSessionContext,
    mut progress: JevRunProgress,
    execute: E,
    mut save_progress: S,
) -> Result<JevExecutionOutcome<C::Result>, JevError>
where
    C: JevCheck,
    E: Fn(JevRequestBatch) -> Fut + Sync,
    Fut: std::future::Future<Output = Result<JevResponse, JevError>> + Send,
    S: FnMut(&JevRunProgress) -> Result<(), JevError>,
{
    let mut plan = check.prepare(context)?;
    if plan.check_id != check.id()
        || plan.input_revision != context.input_revision
        || plan.revisions != check.revisions()
        || !valid_work_item_ids(&plan.work_items)
    {
        return Err(JevError::InvalidCheckPlan);
    }
    let progress_revision = progress_revision(check.id(), context, plan.revisions);
    if progress.input_revision != progress_revision {
        progress = JevRunProgress {
            input_revision: progress_revision,
            ..JevRunProgress::default()
        };
    }
    progress.failed_item_ids.clear();
    let mut failure = None;
    let mut complete = true;

    let initial = pack_work_items(&plan.work_items);
    if !initial.skipped_item_ids.is_empty() {
        complete = false;
        plan.coverage.skipped_items += initial.skipped_item_ids.len();
        plan.coverage
            .limitations
            .push("request_packing_limit".to_owned());
        progress
            .failed_item_ids
            .extend(initial.skipped_item_ids.iter().cloned());
    }
    let initial_batches = initial
        .batches
        .into_iter()
        .filter(|batch| !progress.completed_batch_ids.contains(&batch.id))
        .collect();
    for (batch, response) in execute_batches(&execute, initial_batches).await {
        match response {
            Ok(response) => {
                let results = unpack_jev_response(&batch, &response)?;
                for result in results {
                    progress.results.insert(result.work_item_id.clone(), result);
                }
                progress.completed_batch_ids.insert(batch.id);
                progress.request_count = progress.request_count.saturating_add(1);
                save_progress(&progress)?;
            }
            Err(error) => {
                complete = false;
                progress.failed_item_ids.extend(batch.work_item_ids);
                failure.get_or_insert(error);
            }
        }
    }
    if failure.is_some() {
        complete = false;
    }

    let mut reconciliation_items = Vec::new();
    if failure.is_none() {
        for work_item in &plan.work_items {
            let Some(initial_result) = progress.results.get(&work_item.id) else {
                complete = false;
                progress.failed_item_ids.insert(work_item.id.clone());
                continue;
            };
            if let Some(reconciliation) = check.reconcile(work_item, initial_result, context)? {
                reconciliation_items.push(reconciliation);
            }
        }
    } else {
        complete = false;
    }

    let reconciliation = pack_work_items(&reconciliation_items);
    if !reconciliation.skipped_item_ids.is_empty() {
        complete = false;
        plan.coverage.skipped_items += reconciliation.skipped_item_ids.len();
        plan.coverage
            .limitations
            .push("reconciliation_packing_limit".to_owned());
        progress
            .failed_item_ids
            .extend(reconciliation.skipped_item_ids.iter().cloned());
    }
    let mut all_work_items = plan.work_items.clone();
    all_work_items.extend(reconciliation_items.iter().cloned());
    if !valid_work_item_ids(&all_work_items) {
        return Err(JevError::InvalidCheckPlan);
    }
    let reconciliation_batches = reconciliation
        .batches
        .into_iter()
        .filter(|batch| !progress.completed_batch_ids.contains(&batch.id))
        .collect();
    for (batch, response) in execute_batches(&execute, reconciliation_batches).await {
        match response {
            Ok(response) => {
                let results = unpack_jev_response(&batch, &response)?;
                for result in results {
                    progress.results.insert(result.work_item_id.clone(), result);
                }
                progress.completed_batch_ids.insert(batch.id);
                progress.request_count = progress.request_count.saturating_add(1);
                save_progress(&progress)?;
            }
            Err(error) => {
                complete = false;
                progress.failed_item_ids.extend(batch.work_item_ids);
                failure.get_or_insert(error);
            }
        }
    }

    for item in &plan.work_items {
        if !progress.results.contains_key(&item.id) {
            progress.failed_item_ids.insert(item.id.clone());
        }
    }
    for item in &reconciliation_items {
        if !progress.results.contains_key(&item.id) {
            progress.failed_item_ids.insert(item.id.clone());
        }
    }
    if !progress.failed_item_ids.is_empty() || failure.is_some() {
        complete = false;
    }
    if !complete {
        plan.coverage
            .limitations
            .push("assessment_incomplete".to_owned());
        plan.coverage.limitations.sort();
        plan.coverage.limitations.dedup();
    }
    if !valid_result_evidence(&all_work_items, progress.results.values()) {
        return Err(JevError::InvalidCheckPlan);
    }
    let results = progress.results.values().cloned().collect::<Vec<_>>();
    let result = check.reduce(&plan, &results, complete)?;
    Ok(JevExecutionOutcome {
        result,
        progress,
        complete,
        failure,
    })
}

fn valid_work_item_ids(items: &[JevWorkItem]) -> bool {
    let mut ids = BTreeSet::new();
    items
        .iter()
        .all(|item| !item.id.is_empty() && ids.insert(item.id.as_str()))
}

fn valid_result_evidence<'a>(
    items: &[JevWorkItem],
    mut results: impl Iterator<Item = &'a JevWorkItemResult>,
) -> bool {
    let expected = items
        .iter()
        .map(|item| (item.id.as_str(), item.window.evidence.as_slice()))
        .collect::<BTreeMap<_, _>>();
    results.all(|result| {
        expected
            .get(result.work_item_id.as_str())
            .is_some_and(|evidence| *evidence == result.evidence.as_slice())
    })
}

fn progress_revision(
    check_id: &str,
    context: &JevSessionContext,
    revisions: JevCheckRevisions,
) -> String {
    digest_hex(
        format!(
            "{check_id}\0{}\0{}\0{}\0{}\0{}\0{}",
            context.session_identity,
            context.input_revision,
            revisions.projection,
            revisions.chunking,
            revisions.questions,
            revisions.reducer,
        )
        .as_bytes(),
    )
}

async fn execute_batches<E, Fut>(
    execute: &E,
    batches: Vec<JevRequestBatch>,
) -> Vec<(JevRequestBatch, Result<JevResponse, JevError>)>
where
    E: Fn(JevRequestBatch) -> Fut + Sync,
    Fut: std::future::Future<Output = Result<JevResponse, JevError>> + Send,
{
    type BatchFuture<'a> = Pin<
        Box<
            dyn Future<Output = (usize, JevRequestBatch, Result<JevResponse, JevError>)>
                + Send
                + 'a,
        >,
    >;

    let mut pending = batches.into_iter().enumerate().collect::<VecDeque<_>>();
    let mut tasks: Vec<Option<BatchFuture<'_>>> = std::iter::repeat_with(|| None)
        .take(MAX_PARALLEL_REQUESTS)
        .collect();
    let mut completed = std::iter::repeat_with(|| None)
        .take(pending.len())
        .collect::<Vec<Option<(JevRequestBatch, Result<JevResponse, JevError>)>>>();
    let mut next_start: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut failed = false;

    std::future::poll_fn(|context| {
        for task in &mut tasks {
            let ready = task
                .as_mut()
                .and_then(|task| match task.as_mut().poll(context) {
                    std::task::Poll::Ready(result) => Some(result),
                    std::task::Poll::Pending => None,
                });
            if let Some((index, batch, result)) = ready {
                failed |= result.is_err();
                completed[index] = Some((batch, result));
                *task = None;
            }
        }

        let start_ready = next_start
            .as_mut()
            .is_none_or(|sleep| sleep.as_mut().poll(context).is_ready());
        if !failed
            && !pending.is_empty()
            && start_ready
            && let Some(slot) = tasks.iter().position(Option::is_none)
            && let Some((index, batch)) = pending.pop_front()
        {
            let request = execute(batch.clone());
            tasks[slot] = Some(Box::pin(async move { (index, batch, request.await) }));
            next_start = Some(Box::pin(tokio::time::sleep(REQUEST_START_INTERVAL)));
            context.waker().wake_by_ref();
        }

        if tasks.iter().all(Option::is_none) && (failed || pending.is_empty()) {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;

    completed.into_iter().flatten().collect()
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn valid_probability(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn validate_probability_sum(values: impl Iterator<Item = f64>) -> Result<(), JevError> {
    let sum = values.sum::<f64>();
    if (sum - 1.0).abs() > 0.02 {
        Err(JevError::InvalidProbabilitySum)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn choice() -> JevQuestion {
        JevQuestion::Choice {
            instructions: json!("Which option applies?"),
            criteria: BTreeMap::from([
                ("yes".to_owned(), json!("Yes")),
                ("no".to_owned(), json!("No")),
            ]),
        }
    }

    fn item(id: &str, text: &str) -> JevWorkItem {
        JevWorkItem {
            id: id.to_owned(),
            window: JevInputWindow {
                fields: json!({"text": text}),
                evidence: vec![JevEvidenceReference {
                    part_id: "text".to_owned(),
                    source_id: id.to_owned(),
                    content_kind: "assistant_text".to_owned(),
                    role: JevEvidenceRole::Candidate,
                }],
            },
            questions: BTreeMap::from([("q".to_owned(), choice())]),
        }
    }

    #[test]
    fn request_packing_keeps_questions_with_their_context_and_stays_bounded() {
        let items = vec![item("one", "small evidence"), item("two", "other evidence")];
        let packed = pack_work_items(&items);
        assert!(packed.skipped_item_ids.is_empty());
        assert_eq!(packed.batches.len(), 1);
        let batch = &packed.batches[0];
        assert!(batch.serialized_bytes <= MAX_REQUEST_BYTES);
        assert_eq!(batch.work_item_ids, vec!["one", "two"]);
        assert_eq!(batch.answer_owners.len(), 2);
        assert_eq!(batch.evidence_owners["one"][0].source_id, "one");
        assert!(!batch.request.state.to_string().contains("source_id"));
        assert!(!batch.request.state.to_string().contains("\"one\""));
        let results = unpack_jev_response(batch, &response_for(&batch.request)).unwrap();
        assert_eq!(results[0].evidence, batch.evidence_owners["one"]);
        let instructions = &batch.request.questions.values().next().unwrap();
        assert!(
            matches!(instructions, JevQuestion::Choice { instructions, .. } if instructions.to_string().contains("work_items["))
        );
    }

    #[test]
    fn oversized_work_items_are_marked_skipped_instead_of_truncated() {
        let oversized = item("large", &"x".repeat(MAX_REQUEST_BYTES * 2));
        let packed = pack_work_items(&[oversized]);
        assert!(packed.batches.is_empty());
        assert_eq!(packed.skipped_item_ids, vec!["large"]);
    }

    #[test]
    fn state_and_question_budget_is_checked_separately_from_full_request_size() {
        let large_state = item("large-state", &"x".repeat(32 * 1024));
        let packed = pack_work_items(std::slice::from_ref(&large_state));
        assert!(packed.batches.is_empty());
        assert_eq!(packed.skipped_item_ids, vec!["large-state"]);

        let request = JevRequest {
            model: PINNED_MODEL.to_owned(),
            state: large_state.window.fields,
            questions: large_state.questions,
        };
        assert!(matches!(
            validate_jev_request(&request),
            Err(JevError::RequestTooLarge { .. })
        ));
    }

    #[test]
    fn response_validation_checks_answer_type_distribution_and_model() {
        let request = JevRequest {
            model: PINNED_MODEL.to_owned(),
            state: json!({"text": "sample"}),
            questions: BTreeMap::from([("q".to_owned(), choice())]),
        };
        let response = JevResponse {
            model: PINNED_MODEL.to_owned(),
            answers: BTreeMap::from([(
                "q".to_owned(),
                JevAnswer::Choice {
                    choice: "yes".to_owned(),
                    probabilities: BTreeMap::from([
                        ("yes".to_owned(), 0.9),
                        ("no".to_owned(), 0.1),
                    ]),
                    confidence: 0.8,
                },
            )]),
            usage: JevUsage {
                input_tokens: 10,
                output_tokens: 2,
            },
        };
        assert_eq!(validate_jev_response(&response, &request), Ok(()));
        let mut invalid = response;
        invalid.model = "jev-latest".to_owned();
        assert_eq!(
            validate_jev_response(&invalid, &request),
            Err(JevError::ResponseModelMismatch)
        );
    }

    #[test]
    fn valid_distribution_is_accepted_when_choice_disagrees() {
        let request = JevRequest {
            model: PINNED_MODEL.to_owned(),
            state: json!("sample"),
            questions: BTreeMap::from([("q".to_owned(), choice())]),
        };
        let response = JevResponse {
            model: PINNED_MODEL.to_owned(),
            answers: BTreeMap::from([(
                "q".to_owned(),
                JevAnswer::Choice {
                    choice: "yes".to_owned(),
                    probabilities: BTreeMap::from([
                        ("yes".to_owned(), 0.1),
                        ("no".to_owned(), 0.9),
                    ]),
                    confidence: 0.8,
                },
            )]),
            usage: JevUsage {
                input_tokens: 10,
                output_tokens: 2,
            },
        };
        assert_eq!(validate_jev_response(&response, &request), Ok(()));
        let JevAnswer::Choice {
            choice,
            probabilities,
            ..
        } = &response.answers["q"]
        else {
            panic!("test response uses Choice")
        };
        assert_eq!(
            highest_probability_choice(choice, probabilities),
            Some("no")
        );
        assert_eq!(
            highest_probability_choice(
                "yes",
                &BTreeMap::from([("yes".to_owned(), 0.5), ("no".to_owned(), 0.5)])
            ),
            Some("yes")
        );
        let mut invalid = response;
        if let JevAnswer::Choice { probabilities, .. } = invalid.answers.get_mut("q").unwrap() {
            probabilities.insert("no".to_owned(), 1.2);
        }
        assert_eq!(
            validate_jev_response(&invalid, &request),
            Err(JevError::InvalidChoiceDistribution)
        );
    }

    struct ResumeCheck {
        revisions: JevCheckRevisions,
    }

    impl JevCheck for ResumeCheck {
        type Result = Value;

        fn id(&self) -> &'static str {
            "resume_test"
        }

        fn revisions(&self) -> JevCheckRevisions {
            self.revisions
        }

        fn prepare(&self, context: &JevSessionContext) -> Result<JevCheckPlan, JevError> {
            let questions = BTreeMap::from([("decision".to_owned(), choice())]);
            let work_items = ["first", "second"]
                .into_iter()
                .map(|id| JevWorkItem {
                    id: id.to_owned(),
                    window: JevInputWindow {
                        fields: json!({"text": "x".repeat(20_000)}),
                        evidence: vec![JevEvidenceReference {
                            part_id: "text".to_owned(),
                            source_id: format!("event-{id}"),
                            content_kind: "assistant_text".to_owned(),
                            role: JevEvidenceRole::Candidate,
                        }],
                    },
                    questions: questions.clone(),
                })
                .collect::<Vec<_>>();
            Ok(JevCheckPlan {
                check_id: self.id().to_owned(),
                input_revision: context.input_revision.clone(),
                revisions: self.revisions(),
                work_items,
                skipped_item_ids: Vec::new(),
                coverage: JevCoverage {
                    selected_items: 2,
                    ..JevCoverage::default()
                },
                check_data: Value::Null,
            })
        }

        fn reduce(
            &self,
            plan: &JevCheckPlan,
            results: &[JevWorkItemResult],
            complete: bool,
        ) -> Result<Self::Result, JevError> {
            if plan.check_id != self.id() {
                return Err(JevError::InvalidCheckPlan);
            }
            Ok(json!({
                "completed": complete,
                "work_item_ids": results.iter().map(|result| result.work_item_id.as_str()).collect::<Vec<_>>(),
            }))
        }
    }

    struct ManyItemsCheck;

    impl JevCheck for ManyItemsCheck {
        type Result = usize;

        fn id(&self) -> &'static str {
            "many_items_test"
        }

        fn revisions(&self) -> JevCheckRevisions {
            JevCheckRevisions {
                projection: 1,
                chunking: 1,
                questions: 1,
                reducer: 1,
            }
        }

        fn prepare(&self, context: &JevSessionContext) -> Result<JevCheckPlan, JevError> {
            let questions = BTreeMap::from([("decision".to_owned(), choice())]);
            let work_items = (0..70)
                .map(|index| JevWorkItem {
                    id: format!("item-{index}"),
                    window: JevInputWindow {
                        fields: json!({"text": "synthetic evidence ".repeat(280)}),
                        evidence: vec![JevEvidenceReference {
                            part_id: "text".to_owned(),
                            source_id: format!("event-{index}"),
                            content_kind: "assistant_text".to_owned(),
                            role: JevEvidenceRole::Candidate,
                        }],
                    },
                    questions: questions.clone(),
                })
                .collect::<Vec<_>>();
            Ok(JevCheckPlan {
                check_id: self.id().to_owned(),
                input_revision: context.input_revision.clone(),
                revisions: self.revisions(),
                work_items,
                skipped_item_ids: Vec::new(),
                coverage: JevCoverage::default(),
                check_data: Value::Null,
            })
        }

        fn reduce(
            &self,
            _plan: &JevCheckPlan,
            results: &[JevWorkItemResult],
            complete: bool,
        ) -> Result<Self::Result, JevError> {
            if !complete {
                return Err(JevError::InvalidCheckPlan);
            }
            Ok(results.len())
        }
    }

    fn response_for(request: &JevRequest) -> JevResponse {
        let answers = request
            .questions
            .iter()
            .map(|(id, question)| {
                let JevQuestion::Choice { criteria, .. } = question else {
                    panic!("synthetic check uses Choice questions")
                };
                let choice = criteria.keys().next().unwrap().clone();
                let probabilities = criteria
                    .keys()
                    .map(|option| (option.clone(), if option == &choice { 1.0 } else { 0.0 }))
                    .collect();
                (
                    id.clone(),
                    JevAnswer::Choice {
                        choice,
                        probabilities,
                        confidence: 1.0,
                    },
                )
            })
            .collect();
        JevResponse {
            model: request.model.clone(),
            answers,
            usage: JevUsage {
                input_tokens: 10,
                output_tokens: 1,
            },
        }
    }

    #[tokio::test]
    async fn generic_runner_resumes_partial_progress_without_repeating_completed_batches() {
        let context = JevSessionContext {
            input_revision: "immutable-input".to_owned(),
            session_identity: "synthetic-session".to_owned(),
            check_context: Value::Null,
            limitations: Vec::new(),
        };
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut saved = Vec::new();
        let check = ResumeCheck {
            revisions: check_revisions(1, 1, 1, 1),
        };
        let first = run_jev_check(
            &check,
            &context,
            JevRunProgress::default(),
            |batch| {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if call == 2 {
                        Err(JevError::ProviderUnavailable)
                    } else {
                        Ok(response_for(&batch.request))
                    }
                }
            },
            |progress| {
                saved.push(progress.clone());
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(!first.complete);
        assert_eq!(first.failure, Some(JevError::ProviderUnavailable));
        assert_eq!(first.progress.results.len(), 1);
        assert_eq!(first.progress.completed_batch_ids.len(), 1);
        assert_eq!(saved.len(), 1);

        let resumed_calls = std::sync::atomic::AtomicUsize::new(0);
        let resumed = run_jev_check(
            &check,
            &context,
            first.progress,
            |batch| {
                resumed_calls.fetch_add(1, Ordering::SeqCst);
                async move { Ok(response_for(&batch.request)) }
            },
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(resumed.complete);
        assert_eq!(resumed_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resumed.progress.results.len(), 2);
        assert_eq!(resumed.progress.request_count, 2);
        assert_eq!(
            resumed.progress.results["first"].evidence[0].source_id,
            "event-first"
        );
        assert_eq!(resumed.result["completed"], true);
    }

    #[tokio::test]
    async fn check_contract_revisions_invalidate_saved_work() {
        let context = JevSessionContext {
            input_revision: "immutable-input".to_owned(),
            session_identity: "synthetic-session".to_owned(),
            check_context: Value::Null,
            limitations: Vec::new(),
        };
        let original_check = ResumeCheck {
            revisions: check_revisions(1, 1, 1, 1),
        };
        let original = run_jev_check(
            &original_check,
            &context,
            JevRunProgress::default(),
            |batch| async move { Ok(response_for(&batch.request)) },
            |_| Ok(()),
        )
        .await
        .unwrap();
        assert!(original.complete);
        assert_eq!(original.progress.results.len(), 2);
        assert_ne!(original.progress.input_revision, context.input_revision);

        for revisions in [
            check_revisions(2, 1, 1, 1),
            check_revisions(1, 2, 1, 1),
            check_revisions(1, 1, 2, 1),
            check_revisions(1, 1, 1, 2),
        ] {
            let changed_check = ResumeCheck { revisions };
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let changed = run_jev_check(
                &changed_check,
                &context,
                original.progress.clone(),
                |batch| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move { Ok(response_for(&batch.request)) }
                },
                |_| Ok(()),
            )
            .await
            .unwrap();
            assert!(changed.complete);
            assert_eq!(changed.progress.results.len(), 2);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn runner_rejects_saved_answers_with_changed_source_bindings() {
        let context = JevSessionContext {
            input_revision: "immutable-input".to_owned(),
            session_identity: "synthetic-session".to_owned(),
            check_context: Value::Null,
            limitations: Vec::new(),
        };
        let check = ResumeCheck {
            revisions: check_revisions(1, 1, 1, 1),
        };
        let original = run_jev_check(
            &check,
            &context,
            JevRunProgress::default(),
            |batch| async move { Ok(response_for(&batch.request)) },
            |_| Ok(()),
        )
        .await
        .unwrap();
        let mut stale = original.progress;
        stale.results.get_mut("first").unwrap().evidence[0].source_id = "other-source".to_owned();

        let resumed = run_jev_check(
            &check,
            &context,
            stale,
            |batch| async move { Ok(response_for(&batch.request)) },
            |_| Ok(()),
        )
        .await;
        assert_eq!(resumed, Err(JevError::InvalidCheckPlan));
    }

    #[tokio::test]
    async fn generic_runner_packs_many_items_into_bounded_parallel_requests() {
        let context = JevSessionContext {
            input_revision: "many-items-input".to_owned(),
            session_identity: "synthetic-session".to_owned(),
            check_context: Value::Null,
            limitations: Vec::new(),
        };
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let maximum_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let outcome = run_jev_check(
            &ManyItemsCheck,
            &context,
            JevRunProgress::default(),
            |batch| {
                calls.fetch_add(1, Ordering::SeqCst);
                let in_flight = std::sync::Arc::clone(&in_flight);
                let maximum_in_flight = std::sync::Arc::clone(&maximum_in_flight);
                async move {
                    let active = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_in_flight.fetch_max(active, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(response_for(&batch.request))
                }
            },
            |_| Ok(()),
        )
        .await
        .unwrap();

        assert!(outcome.complete);
        let call_count = calls.load(Ordering::SeqCst);
        assert!(call_count > 1);
        assert!(call_count < 64, "larger requests reduce provider calls");
        assert!(maximum_in_flight.load(Ordering::SeqCst) > 1);
        assert!(maximum_in_flight.load(Ordering::SeqCst) <= MAX_PARALLEL_REQUESTS);
        assert_eq!(outcome.progress.request_count, call_count);
        assert_eq!(outcome.result, 70);
    }

    fn check_revisions(
        projection: u32,
        chunking: u32,
        questions: u32,
        reducer: u32,
    ) -> JevCheckRevisions {
        JevCheckRevisions {
            projection,
            chunking,
            questions,
            reducer,
        }
    }
}
