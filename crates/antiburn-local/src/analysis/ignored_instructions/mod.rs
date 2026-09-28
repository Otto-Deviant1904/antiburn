//! Source evidence and instruction snapshots for the Ignored Instructions check.
//!
//! This module only prepares bounded local evidence. It does not perform
//! inference, schedule work, or interpret vendor transcript formats itself.

mod assessment;
mod evidence;
mod input;
mod sources;

pub const CHECK_ID: &str = "ignored_instructions";

pub use evidence::{
    ContentAction, ContentEventReference, ContentReferenceResolution, SessionContentEvidence,
    content_action_digest, prepare_session_content, resolve_content_reference, source_supported,
};

pub use crate::analysis::jev::{
    JevAnswer, JevError, JevQuestion, JevRequest, JevResponse, JevUsage,
};
pub use assessment::{
    ASSESSMENT_CHUNKING_REVISION, ASSESSMENT_MODEL, ASSESSMENT_PROJECTION_REVISION,
    ASSESSMENT_QUESTION_REVISION, ASSESSMENT_REDUCER_REVISION, AssessmentCoverage,
    AssessmentFinding, AssessmentInput, AssessmentPlan, AssessmentResult, CandidateComparison,
    ComparisonJudgment, CompletionCoverage, CounterEvidence, FindingCertainty,
    IgnoredInstructionsCheck, InstructionSourceCoverage, MAX_ASSESSMENT_CANDIDATES, PendingRule,
    RuleActionRef, RuleStatus, build_assessment_plan, build_jev_context, evaluator_revision,
    extend_comparison_with_history, extend_jev_context_with_history, reduce_assessment,
};
pub use input::{
    InstructionContentClass, InstructionProvenance, InstructionRuleSection, InstructionScope,
    InstructionSnapshot, MAX_INSTRUCTION_BYTES, MAX_RULE_SECTION_BYTES, MarkdownLimit,
    segment_markdown, sha256_hex, snapshot_from_text,
};
pub use sources::{
    InstructionAdapter, InstructionDiscovery, MAX_INSTRUCTION_FILES, MAX_INSTRUCTION_TOTAL_BYTES,
    discover_current_instructions,
};
