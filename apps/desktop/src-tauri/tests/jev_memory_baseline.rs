use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use antiburn_local::analysis::SourceFormat;
use antiburn_local::analysis::ignored_instructions::{
    AssessmentInput, ContentAction, ContentEventReference, IgnoredInstructionsCheck,
    InstructionProvenance, InstructionScope, SessionContentEvidence, build_jev_context,
    select_session_content, snapshot_from_text,
};
use antiburn_local::analysis::jev::{JevCheck, pack_work_items};

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            if new_size >= layout.size() {
                let growth = new_size - layout.size();
                let live = LIVE_BYTES.fetch_add(growth, Ordering::Relaxed) + growth;
                PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
            ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
            ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Measurement {
    elapsed_us: u128,
    allocated_bytes: usize,
    allocation_count: usize,
    peak_live_bytes: usize,
    retained_bytes_after_assessment: usize,
    actions: usize,
    input_bytes: usize,
    work_items: usize,
    requests: usize,
    questions: usize,
    request_bytes: usize,
}

fn measure(input: &AssessmentInput) -> Measurement {
    let live_before = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(live_before, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    ALLOCATION_COUNT.store(0, Ordering::Relaxed);
    let started = Instant::now();
    let context = build_jev_context(input).unwrap();
    let work_items = IgnoredInstructionsCheck
        .prepare(&context)
        .unwrap()
        .work_items;
    let packed = pack_work_items(&work_items);
    let elapsed_us = started.elapsed().as_micros();
    let work_item_count = work_items.len();
    let requests = packed.batches.len();
    let questions = packed
        .batches
        .iter()
        .map(|batch| batch.request.questions.len())
        .sum();
    let request_bytes = packed
        .batches
        .iter()
        .map(|batch| batch.serialized_bytes)
        .sum();
    drop(packed);
    drop(work_items);
    drop(context);
    let retained_bytes_after_assessment = LIVE_BYTES
        .load(Ordering::Relaxed)
        .saturating_sub(live_before);
    Measurement {
        elapsed_us,
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        allocation_count: ALLOCATION_COUNT.load(Ordering::Relaxed),
        peak_live_bytes: PEAK_BYTES
            .load(Ordering::Relaxed)
            .saturating_sub(live_before),
        retained_bytes_after_assessment,
        actions: input.content.actions.len(),
        input_bytes: input
            .content
            .actions
            .iter()
            .map(|action| action.text.len())
            .sum(),
        work_items: work_item_count,
        requests,
        questions,
        request_bytes,
    }
}

fn synthetic_input() -> AssessmentInput {
    let rules = (0..12)
        .map(|index| format!("- Do not use the forbidden pattern number {index}."))
        .collect::<Vec<_>>()
        .join("\n");
    let instruction = snapshot_from_text(
        "AGENTS.md",
        rules,
        InstructionProvenance::RecordedInjection,
        InstructionScope::Project,
    )
    .unwrap();
    let mut actions = (0..32)
        .map(|index| ContentAction {
            reference: ContentEventReference {
                id: format!("action-{index}"),
                source_key_digest: "synthetic-source".to_owned(),
                thread_digest: "synthetic-thread".to_owned(),
                turn_index: index,
                native_record_id: Some(format!("record-{index}")),
                part_index: 0,
                stable: true,
            },
            timestamp_ms: Some(index as i64),
            turn_role: "assistant".to_owned(),
            turn_scope: "main".to_owned(),
            authority: "assistant".to_owned(),
            kind: "assistant".to_owned(),
            text: format!(
                "I completed synthetic action {index} and reviewed the forbidden pattern. {}",
                "Synthetic context text. ".repeat(16)
            ),
            tool_name: None,
            tool_call_id: None,
            normalized_fields: None,
            metadata: Default::default(),
            truncated: false,
            context_only: false,
        })
        .collect::<Vec<_>>();
    actions.extend((0..8).map(|index| {
        ContentAction {
            reference: ContentEventReference {
                id: format!("edit-{index}"),
                source_key_digest: "synthetic-source".to_owned(),
                thread_digest: "synthetic-thread".to_owned(),
                turn_index: 32 + index,
                native_record_id: Some(format!("edit-record-{index}")),
                part_index: 0,
                stable: true,
            },
            timestamp_ms: Some((32 + index) as i64),
            turn_role: "assistant".to_owned(),
            turn_scope: "main".to_owned(),
            authority: "assistant".to_owned(),
            kind: "tool_input".to_owned(),
            text: serde_json::json!({
                "file_path": format!("src/generated-{index}.rs"),
                "old_string": "forbidden old source ".repeat(512),
                "new_string": "safe replacement source ".repeat(512),
            })
            .to_string(),
            tool_name: Some("Edit".to_owned()),
            tool_call_id: Some(format!("edit-call-{index}")),
            normalized_fields: None,
            metadata: Default::default(),
            truncated: false,
            context_only: false,
        }
    }));
    AssessmentInput {
        content: SessionContentEvidence {
            session_identity_digest: "synthetic-session".to_owned(),
            source_format: SourceFormat::ClaudeJsonl,
            publication_fence: 1,
            selected_input_digest: "synthetic-input".to_owned(),
            actions,
            instructions: vec![instruction],
            complete: true,
            limitations: Vec::new(),
            excluded_thinking_parts: 0,
            field_availability: Vec::new(),
        },
        prior_history_complete: true,
        activity_after_ms: None,
        boundary_positions: Default::default(),
        source_generation: 1,
        source_fingerprint: None,
        incarnation: 1,
        comparison_after: None,
    }
}

#[test]
#[ignore = "diagnostic only; use the release probes for memory acceptance"]
fn reports_jev_memory_and_allocation_diagnostics() {
    let baseline_a = synthetic_input();
    let baseline_b = AssessmentInput {
        content: select_session_content(
            &baseline_a.content,
            IgnoredInstructionsCheck.input_selection(),
        ),
        ..baseline_a.clone()
    };
    let a = measure(&baseline_a);
    let b = measure(&baseline_b);
    for (name, result) in [("A", a), ("B", b)] {
        eprintln!(
            "jev_memory_baseline baseline={name} actions={} input_bytes={} work_items={} requests={} questions={} request_bytes={} elapsed_us={} allocated_bytes={} allocation_count={} peak_live_bytes={} retained_bytes_after_assessment={}",
            result.actions,
            result.input_bytes,
            result.work_items,
            result.requests,
            result.questions,
            result.request_bytes,
            result.elapsed_us,
            result.allocated_bytes,
            result.allocation_count,
            result.peak_live_bytes,
            result.retained_bytes_after_assessment,
        );
        assert!(result.actions > 0);
        assert!(result.work_items > 0);
        assert!(result.requests > 0);
    }
}
