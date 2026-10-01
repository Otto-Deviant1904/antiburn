# Smart Burn Checks

Smart Burn Checks are like deterministic Burn Checks: both look for signs of
known issues in coding sessions. Smart Burn Checks send small, selected parts
of a session to Jev for an assessment. Antiburn then combines those assessments
with its local rules. The result describes evidence of an issue; it does not
judge a person's intent.

Smart Burn Checks means all Jev-powered Burn Checks. Each check declares its
own evidence selection, questions, and result policy. Ignored Instructions is
the first implementation, not the definition of the shared framework.

Ignored Instructions needs a TypeSafe API
key. Jev requests can use paid API credits. Antiburn shows local usage totals in
Settings.

## Ignored Instructions

The following product flow describes Ignored Instructions. Its instruction
rules, six selected fields, analysis passes, and confidence gates are specific
to this check.

### What the check reads

The session reader turns each supported agent's records into the same event
format. This lets the check handle different agents in the same way.

The check selects:

- Instruction text from supported files in their current state. This is a
  current-file comparison, not proof of the text or activation the agent saw
  during the session. Historical text is available only from a supported,
  authoritative session record; a read path alone does not provide it.
- Assistant text that describes work.
- Bash command input, which can include inline scripts, heredocs, and patches
  recorded inside the command.
- File-edit paths, read-file paths, and search queries with their scope filters.
- Inputs for other tools that are not recognized as Bash, edit, read, or search
  tools.

The check excludes user messages, command and search results, read output, edit
content, other tool output, and private thinking. Dedicated edit-tool content
stays excluded even though inline Bash content is selected. Selected file paths
can appear in TypeSafe requests. Event IDs, line numbers, and citation links
stay on the computer. Jev gets temporary labels; Antiburn uses a private map to
connect its answers to the original session events. Missing historical evidence
stays unavailable and cannot support a clean result. A recorded command request
does not establish that the command ran or succeeded.

The selected query filters content kinds and tool categories before loading
text and applies page limits to selected fields. Source-wide truncation flags
can still keep a result unassessed when they cannot identify the omitted field.

### How instructions are split

The Markdown reader uses headings and main list items to find rules. It keeps a
rule's nested bullets, conditions, exceptions, and examples with that rule. It
also saves the YAML header with the instruction file. A change to the file then
creates a new saved version.

Background and example sections do not become rule targets. The check does not
classify a rule by searching for words such as “must” or “never.” Jev judges the
meaning from the supplied text.

Long text cannot fit in one request. The check cuts long rules, assistant
messages, and tool inputs into small, overlapping text ranges. Each range
repeats a little text from the range before it. This keeps words near a cut
connected. Antiburn can check every range without making one oversized request.

Instruction source also matters. The worker currently discovers supported
instruction files from the session's worktree and home and labels those snapshots
as current-file comparisons. A matching path does not prove historical content
or activation. Recorded historical injection is a distinct provenance, but the
worker does not recover it from session fields. The reducer preserves
provenance, and current-file-only evidence cannot support a clean result.

### How sessions are split

The check starts at the saved enablement boundary, or at the selected history
window for a history run. It includes supported content after that boundary.
Assistant text and tool input can be actions to check. A candidate action means
one such event that may match an instruction. Tool-result text is not sent.

Antiburn reads a large session in pages. Each page holds a fixed amount of
content. The first page can have newer events than the second page. The reader
keeps the original order of events and keeps separate conversation branches
apart.

Within a page, the check moves through actions and rules in a stable order. It
makes an **event window** from one action and up to two rules to compare with
it. This sends the action once for those rules instead of copying it into a
separate window each time. One rule/action comparison is a **target**. Long
actions or rules can need several windows, with a small overlap so no text is
skipped.

For example, the instructions might say “Run tests before publishing” and “Get
approval before publishing.” If the session says “Published the release,” the
window has one action and two targets. Jev makes a separate decision for each
target.

An older page may contain a selected earlier step for a newer action. The worker
keeps only comparisons whose prior history is incomplete, up to the candidate
limit. It adds matching earlier events in source order and checks each candidate
again. Completed comparisons do not carry forward. The carried comparison state
is separate from the content cursor and page result. Missing history never proves
that a prerequisite did not happen. User approval text is excluded and cannot
resolve a permission-dependent conclusion. If the needed interval remains
missing or cut short, the result stays unassessed.

### What Jev receives and returns

Each event window contains the selected rule text, the action, and a few
nearby events. The check uses two analysis passes. The first pass asks one
applicability question for each target:

1. Does this instruction apply to the action?

The check asks independent relationship and evidence questions after each valid
applicability answer, including “not applicable” and uncertain answers:

1. Does the action conflict with or follow the instruction after conditions and
   exceptions are considered?
2. Could missing or truncated evidence change that conclusion?
3. Does the instruction have a completion-bound obligation whose completion
   boundary is not shown?

A “not applicable” answer does not prove the action is clean. The independent
answers must confirm that the candidate is unrelated and that the selected
evidence is sufficient, each with at least 0.85 probability. Contradictory, weak,
or incomplete answers stay unassessed. Confident rule classification can settle
an action or prerequisite obligation without another completion question.

The shared request code combines windows until the request reaches its size or
question limit. Jev returns a choice and probability for each answer. The
temporary labels let the shared worker connect answers to their windows, while
the private map connects those windows back to the original rule and event.
The independent follow-up also checks excluded-field limits and keeps context
violations separate from the candidate's local citation. The first pass still
evaluates every selected target.

### How results become findings

Jev does not decide the session result by itself. Antiburn checks the answers
available for each target, then combines those decisions from all windows and
pages into one session result.

The local decision rules apply confidence limits. A possible finding needs at
least 0.85 probability that the rule applies and the action conflicts. A likely
finding needs 0.90 plus stronger evidence about the instruction source and the
action.
When evidence is incomplete, Jev must also judge that the supplied evidence is
enough to prove the result. A direct conflict can still qualify when omitted
history cannot change it. A conclusion that depends on missing history stays
unassessed.

Antiburn links each finding to the exact local rule and action. It combines
duplicate results for the same rule and action into one finding. A typed
completion answer can keep a rule pending until the session shows the task's
completion point. A clean result requires all eligible targets and pages to be
covered, with no pending or unassessed work. Partial pages cannot produce a
clean result.

The shared worker saves progress after each request. If Antiburn stops, it can
resume without sending completed requests again. The worker also handles the
TypeSafe connection, cached answers, usage reservations, retries, response
checks, and cancellation. Check text and answers do not go to product analytics.

## Reusable Jev check contract

The shared engine contract is `JevCheck` in
`crates/antiburn-local/src/analysis/jev.rs`. A check implements it to define:

- Its stable check ID and input, chunking, question, and reducer revisions.
- Its typed session-field selection. The default selection is empty.
- How to project normalized facts into bounded `JevInputWindow` values.
- Which local evidence IDs are candidates, instructions, or supporting context.
- Its typed questions and deterministic reducer.
- Its typed prepared state, without a JSON round trip through the runner.
- Any check-owned reference snapshots, separate from transcript evidence.

`run_jev_check` packs those windows, validates Jev's answers, maps each answer
back to its local window, saves generic progress, resumes unfinished requests,
and calls the check's reducer. Its mechanics do not depend on Ignored
Instructions.

The desktop `JevCheckWorker` trait connects a check to product work. It supplies
the check ID and processes one stored session candidate. The shared
`jev_worker` scheduler finds candidates, and `execute_jev_batch` handles
transport, cache, reservations, retries, cancellation, and safe error reporting.
The scheduler does not inspect instruction rules or define findings.

Ignored Instructions implements `JevCheck` in
`crates/antiburn-local/src/checks/ignored_instructions/assessment.rs`. Its
desktop adapter is `apps/desktop/src-tauri/src/ignored_instructions_worker.rs`.
That adapter owns instruction discovery, source paging, its saved cursor, and
how its page results combine.
The check's instruction discovery, planning, questions, matching, windows, and
reduction live beside its assessment under `checks/ignored_instructions/`.
`analysis::ignored_instructions` remains a compatibility export.

### Inputs and evidence

Each check declares a `JevInputSelection` and matching
`JevEvidenceRequirements`. The default selection is empty. The source boundary
applies selection before a check receives evidence. Its page query filters by
content kind and tool category before loading text. The page contains only
fields permitted by the selection.

`JevFieldAvailability` reports `excluded`, `unsupported`, `not_observed`, or
`observed` for each field, plus source capability and observed, empty, malformed,
and truncated part counts. A conditional field can be supported by the source
contract but absent from one page. Unsupported source formats remain unavailable.
Malformed known tools do not become other-tool input. Unsupported, malformed,
truncated, or capped selected evidence blocks a clean result. An unobserved
conditional field stays distinct from an unsupported field.

`JevEvidenceStore` indexes selected values by local source ID and field. It caps
the page at 288 source IDs and 1.125 MiB of selected text. The store is tied to the
published content fence and is rebuilt for each page or continuation. IDs stay
local. A check can request an allowed value through `retrieve_evidence`; the
method rejects fields outside the check's declared selection. It cannot read an
unselected field or another publication.

`JevInputWindow` contains only the bounded state sent to Jev. Its evidence
references bind request-local context to local source IDs. Packing sends the
context and questions, not those IDs. Unpacking restores the local bindings and
the runner verifies them before reduction.

### Reference sources

Reference data is separate from transcript evidence. A worker or check-owned
source adapter loads the policy data it can prove, then supplies a typed
`JevReferenceSnapshot` with a kind, identity, revision, and fields. For Ignored
Instructions this source is the instruction snapshot. Current-file comparisons
remain labeled as current-file evidence; they do not become historical proof.

The check lists required reference kinds in `JevEvidenceRequirements`. The
runner rejects a context that lacks a required snapshot. Reference identity and
revision are included in the check input revision and progress identity.

### Prepared state and revisions

`JevCheckPlan<Prepared>` carries the check's typed preparation and reducer
state. A check defines `Prepared`; the generic runner does not serialize it to
JSON or interpret its fields. The desktop adapter can still persist generic
answers, source bindings, and progress. It rebuilds the prepared state from the
immutable input when it resumes.

The four `JevCheckRevisions` cover projection, chunking, questions, and
reduction. Progress identity also includes the input selection and required
reference kinds. Increase the relevant revision when these semantics change.
The source input revision binds the selected evidence, source generation, and
publication fence. A changed input or revision invalidates prior answers.

### Check and desktop boundaries

Checks own projection, windows, questions, follow-up policy, deterministic
reduction, and clean-result eligibility. Checks do not decode native source
formats, call TypeSafe, reserve usage, or access the desktop Store.

`JevCheckWorker` is a thin desktop adapter. It enrolls and pages product
candidates, obtains source-fenced check input and reference snapshots, restores
check progress, calls `run_jev_check`, and publishes results. A new check reuses
the shared scheduler, executor, cache, and usage reservation.

### Test-only second check

`OutputEnabledCheck` in the `analysis::jev` tests selects Bash output and
retrieves it by its local evidence binding. It runs through the same packing,
response validation, progress, resume, and reduction code as Ignored
Instructions. This test proves the shared preparation contract does not force
checks to exclude output fields. Production output support still depends on the
source field matrix and the check's product enrollment.

### Adding another Jev-powered check

1. Define a stable check ID, field selection, evidence/reference requirements,
   and four revisions. Increase a revision when its
   projection, chunking, questions, or reducer changes.
2. Implement `JevCheck`. Select only the normalized facts the check needs,
   group them into bounded windows, bind local evidence IDs, write typed
   questions, and reduce the answers deterministically.
3. Implement `JevCheckWorker` for candidate selection, source preparation,
   check-specific paging, resume state, and result combination. Load only
   supported source evidence and check-owned references. Preserve availability
   and source-fence limits.
4. Register the worker and its check ID with Settings and candidate enrollment.
   Reuse the shared scheduler and `execute_jev_batch`; do not add another HTTP,
   cache, or usage-reservation path.
5. Add offline tests for field selection, excluded-field isolation, allowed
   follow-up retrieval, window boundaries, request bounds, local citations,
   reference and revision invalidation, partial progress and history, and
   clean-result eligibility.
   Keep billable live tests bounded and based on synthetic data.

The main rule is simple: the check owns what its evidence means. Shared Jev code
owns how requests run and how progress resumes.

## Evaluation scope

The synthetic Ignored Instructions evaluation inputs and Rust harness are under
`apps/desktop/src-tauri/eval/ignored_instructions/`. The development and
regression case data, exact binding sidecars, and gate definitions are under its
`data/` directory. Offline characterization and harness tests check bounded
behavior; they do not establish live Jev accuracy. Complete development and
fresh independent confirmation at a frozen implementation are still required
before claiming the planned live acceptance gates passed.
The first-version gates require 80% joint outcome-and-exact-binding accuracy,
80% observable binding recall, 80% published binding precision, and complete
scheduled results with exact labels. That is at least 128/159 joint passes for
the development schedule and 39/48 for independent confirmation. The latest
complete development run (`questions37`) reported 133/159 joint passes, 43/52
observable bindings recalled, and 43/46 published bindings correct. These
development counts meet the numeric gates; they are not independent acceptance.

## Ignored Instructions selected-input coverage

Audit date: 2026-09-30.

This matrix records the twelve normalized session fields and their current
availability to Ignored Instructions. Other Smart Burn Checks can select a
different subset. It complements the exact native-source inventory in
[`session-coverage.md`](session-coverage.md) and the reachable finding contract
in [`check-coverage.md`](check-coverage.md).

`S` means the accepted adapter can supply the field. `C` means the field is
conditional on the native record. `U` means this check does not accept the
source format. `N` means the field is excluded by the current check selection;
it does not mean the source format cannot contain it. Page availability is
reported separately as excluded, unsupported, not observed, or observed, with
observed, empty, malformed, and truncated counts.

The six accepted formats below have native fixture-to-store-to-selected-query
coverage. Claims remain limited to the characterized source shapes and producer
pins in the session coverage document. All other formats are unavailable to
this check, even if another local parser reads them. In particular, the
OpenCode JSONL export, Antigravity Cascade/SQLite, and other Cursor formats have
no accepted Ignored Instructions characterization.

| `SourceFormat`                 | UserMessage | AssistantMessage | BashCommandInput | BashCommandOutput | FileEditPath | FileEditContent | ReadFilePath | ReadFileOutput | SearchFilesQuery | SearchFilesOutput | OtherToolInput | OtherToolOutput |
| ------------------------------ | ----------- | ---------------- | ---------------- | ----------------- | ------------ | --------------- | ------------ | -------------- | ---------------- | ----------------- | -------------- | --------------- |
| `ClaudeJsonl`                  | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `CodexRolloutJsonl`            | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `PiV3Jsonl`                    | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `OpenCodeSqliteV2`             | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `CursorCliAgentJsonl`          | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `AntigravityBrainJsonl`        | N           | S                | C                | N                 | S            | N               | S            | N              | C                | N                 | C              | N               |
| `OpenCodeJsonl`                | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `OmpV3Jsonl`                   | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CursorJsonl`                  | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CursorCliStoreDb`             | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CursorChatStoreDb`            | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CursorIdeComposer`            | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CursorLegacyChatJson`         | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AntigravityJson`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AntigravityCascadeJson`       | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AntigravityWorkspaceChatJson` | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AntigravitySqlite`            | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CopilotCliJsonl`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `CopilotIdeChatJson`           | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `ClineSessionJson`             | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `ClineMessagesContractV1`      | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `KiroSessionJson`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `KiroChat`                     | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `KiroCliV2Bundle`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `KiroCliV3Bundle`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `KiroChatSaveExport`           | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AmpThreadJson`                | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `AmpFileChanges`               | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `WindsurfWorkspaceJson`        | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `WindsurfMirrorJson`           | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `WindsurfCascadeProtobuf`      | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `DevinLocalSqlite`             | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |
| `Uncharacterized`              | U           | U                | U                | U                 | U            | U               | U            | U              | U                | U                 | U              | U               |

The query filters content kinds and tool categories before it reads text. It
applies part and byte limits to selected fields. SQLite extracts only selected
normalized fields. Each tool request is normalized once when its source adapter
writes the fenced content row. Raw request content remains local; selected
paths, commands, queries, or enabled edit content form the assessment input.
Schema migration 63 adds normalized fields. Parser revision 45 refreshes older
rows for operation metadata, native field bindings, recorded path context, and
truncated-request isolation and exact result joins. Metadata uses the existing
private normalized JSON column.

## Shared normalization contract

Normalization is a reusable source-boundary abstraction. Each Smart Burn Check
selects from its normalized fields; Ignored Instructions does not define which
fields another check can select. `analysis::jev_evidence` owns normalization,
projection, availability, and local citation bindings. The existing Ignored
Instructions evidence exports remain available through that shared module.

The shared normalizer accepts object arguments, JSON-encoded arguments, and up
to four `arguments`/`args`/`params`/`input` wrappers. It bounds each input at
256 KiB, each object or array at 256 entries, the decoded structure at 16 levels
and 4,096 values, and each normalized request at 256 KiB. Unknown tools retain
only bounded recorded input. A malformed known tool does not become other-tool
input. These decoding rules do not prove that a producer emits every wrapper.

Bash input keeps the recorded command, including inline scripts, heredocs, and
patches. When present, its envelope also keeps scalar `cwd`, `workdir`, `shell`,
`login`, `timeout`, and `timeout_ms` execution context. It excludes descriptions,
output-size controls, polling intervals, and output. Command arrays must contain
strings. This is recorded request evidence, not proof of successful execution.

Search input keeps string or string-array query, pattern, glob, include/exclude,
path, and CWD fields, plus recorded boolean constraints. It excludes matches and
arbitrary nested objects. Read paths and edit paths are separate from outputs
and edit bodies. Patch paths include both `Update File` and `Move to` paths;
content-only selection removes those path headers and retains line prefixes.
Multi-file edits retain every accepted path. Paths remain literal transcript
evidence. The normalizer does not resolve relative paths, platform syntax, or
globs against files on disk.

Dedicated edit content accepts recorded string bodies and arrays of edits with
recorded string bodies. Numbers, nested result objects, and unrecognized edit
items do not become edit text. An explicit empty string body is observed and
counted as empty. It is distinct from a missing or malformed body. Message and
tool-result strings use the same presence distinction in the shared content
decoder; non-text blocks remain outside selectable text.

Projection retains only selected normalized values. Excluded bodies cannot
survive in its normalized-field map. Changes to excluded bodies do not change
the selected digest at the same publication fence. A changed source fence still
invalidates that digest. Unsupported formats supply no projected actions.

### Recorded operation and path facts

`JevOperationMetadata` retains a typed native lifecycle state and selected
`JevNativeFieldRange` bindings. OpenCode native `state.status` maps pending,
running, completed, and error exactly. Missing or unknown labels remain unknown.
Other adapters do not infer lifecycle state from request presence, result text,
adjacency, or assistant reports. Completed is a recorded lifecycle label; it
does not establish a passing command or a resulting file state.

Field bindings identify a typed native container, JSON pointer, and UTF-8 offsets within its
decoded string. They are not byte offsets into a transcript file, SQLite cell,
or escaped JSON representation. Bindings cover retained direct string fields
of characterized native request objects. The pointer base is the native
OpenCode part, Claude/Pi record, Codex rollout record, Cursor tool block, or
Antigravity step. Raw Bash strings bind only when retained verbatim. Encoded
JSON strings, nested wrappers, arrays, unknown-tool envelopes, patch-derived paths, and synthesized
store/composer calls have no native field-range claim. No range is fabricated
for a field the producer does not record. Edit keys retain old/new/body
ownership through their native pointers; this does not add a native hunk-range
claim. Native IDs and bindings stay local.

Storage preserves lifecycle state and truncation. SQL filters bindings by the
check's field mask before materialization; projection applies the same mask.
Excluded edit-body bindings cannot affect path-only evidence or its digest.
A truncated known request retains category, malformed state, lifecycle state,
and truncation, but supplies no normalized request text or native range. It
cannot become raw Bash or other-tool input. This fail-closed limit also applies
to oversized raw known-tool input. Unknown tools retain their bounded partial
input under their own selector.

Antigravity's characterized `truncated_fields: ["content"]` marker survives
storage and selection on message/result text. It does not mark tool arguments
as truncated. Other marker-to-field mappings remain uncharacterized. Pi's
subagent filtering preserves original block indexes for native field bindings.

`JevRecordedPathFacts` reads only selected request envelopes. Read/edit paths
retain recorded string CWD/workdir context. Facts bound each path, CWD, and glob
at 4,096 bytes and path/glob lists at 256 entries, and report truncation. Glob
facts distinguish pattern, include, and exclude constraints. Conflicting CWD
aliases stay unknown. Session-header CWD is not propagated into requests in
this contract. Platform must come from a characterized recorded source; no
adapter in this batch records it, and the host platform is never substituted.

The shared lexical resolver requires an explicit recorded POSIX platform and,
for relative paths, an absolute recorded CWD. It collapses `.` and repeated
separators without filesystem access. Parent traversal, shell expansions,
Windows paths, symlink identity, and missing context remain unknown. The typed
POSIX segment-glob helper supports `*` and `?` with case-sensitive matching;
wildcards cannot cross `/`. `**`, brackets, braces, and escapes remain unknown.
Callers must establish this glob dialect separately. These helpers do not claim
that an accepted producer records platform or glob-dialect evidence.

### Characterization and limits

`turn_content_privacy::equivalent_native_requests_have_the_same_selected_meaning_for_all_six_formats`
runs synthetic equivalent assistant, command, edit, read, search, and unknown
tool records through each admitted adapter, the sink, storage, and selection.
It asserts exact selected text and observed field counts. The tool names in
this test exercise recorded call envelopes; they do not establish a producer's
built-in tool inventory. Producer pins and version limits remain in session
coverage.

`turn_content_privacy::native_field_sentinels_remain_isolated_in_fenced_queries_and_projection`
uses the synthetic Claude `selection_isolation.jsonl` fixture. Each of the twelve
single-field queries retains its own sentinel and excludes the other eleven and
private thinking. The empty-field perturbation separately checks empty messages,
edit bodies, and results, and rejects an image block with a misleading text key.
These are adapter/store/projection tests, not model-quality evaluations.
The Pi non-text-result test also rejects image blocks with a text key through
its native tool-result message envelope.

Claude's exact `tool_use_id` joins use a source-local, branch-scoped identity map.
It retains at most 4,096 calls and accepts identity strings up to 512 bytes.
The map survives a validated resume. Reused IDs with conflicting names remain
ambiguous; missing IDs, missing branch links, and calls beyond the cap cannot
gain a name from adjacency or another branch. A joined result records tool
ownership, not successful execution or an authoritative completion boundary.

OpenCode's native SQLite lifecycle fixture covers pending, running, completed,
and error requests. Only completed output and error text supply result bodies
in that fixture. The typed lifecycle label survives selected storage, but the
current Ignored Instructions selection excludes result text. A completed label
does not prove command success or a resulting file state. Exact recorded call
IDs remain local. Native patch parts remain separate metric evidence and do not
supply a second selected edit action.

Historical instruction snapshots, missing call identities, ambiguous output
joins, relative-path resolution, and producer completion boundaries are not
fabricated. Cursor store/composer synthesis and Antigravity Cascade/SQLite
remain outside the Ignored Instructions six-format admission gate. Unsupported
fields on those surfaces stay unsupported; these tests do not establish a new
native schema or release range.

## Shared execution and storage limits

All registered Jev checks use the same desktop transport, request admission,
provider backoff, response cache, and usage settlement. The scheduler takes one
candidate from each check per round. Within a check, history and recent work
alternate. Least recently attempted candidates lead each lane, so continuing
history pages do not always take the next slot.

The runner saves each completed response before waiting for other requests in
the wave. It saves failure state too. Results reduce in stable work-item order;
the reported provider error uses stable batch-ID order. A checkpoint failure
stops further dispatch. Source and credential fences still control admission,
checkpoint writes, and final publication.

Request packing counts JSON bytes and hashes through writers. It measures each
item independently and builds the final request once per batch. The final
request must pass both the 60 KiB request limit and the 30 KiB state-plus-longest-
question limit. These are byte proxies, not measured provider token counts.

The desktop shares eight HTTP slots and a 512 KiB in-flight byte allowance.
Each call reserves twice its request and local-binding bytes plus the 64 KiB
response maximum.
The runner also caps a request wave at a 16 MiB queued-byte allowance shared
across runners. These limits account for serialized payloads and response
buffers; they are not a bound on every allocator or check-owned preparation
object. Provider starts are at least 100 ms apart across checks. Retry-After
and bounded exponential backoff delay the shared start time. A rolling one-
second allowance admits at most 98,304 reserved input tokens. Each dispatched
call starts with a 65,536-token reservation. Confirmed input-token usage replaces
that reservation within the window; known rejection releases it. Unknown
outcomes keep the reservation until the window expires. This is shared across
checks. No live throughput claim follows from these local limits.

Production HTTP uses a cancellable async request. Cancellation cannot undo a
request that the provider already accepted. A timeout, cancellation after
dispatch, or unusable response can leave the billing outcome unknown. The
store keeps hashed work-item identities and a reservation ID for that outcome
and blocks another dispatch of the same semantic work for that session
incarnation and check, including after append or repacking. It does not automatically retry an unknown
outcome. At 1,024 unresolved identities it stops new dispatch rather than evict
an identity and risk repeat billing. Clear Local Data removes this state.

At startup, recovery records any dispatched reservation without a final usage
settlement as one unknown outcome. It preserves unresolved identities and their
reservations, so a restart does not authorize another attempt. A later confirmed
usage result can settle the reservation and remove its unknown count. An expired
reservation is removed only when no unresolved request identity refers to it.
Deleting one session removes its session-scoped check state, but does not erase
usage totals already incurred. Clear Local Data removes local sessions, check
state, unresolved identities, reservations, and usage totals. These rules do not
show whether TypeSafe billed a request whose outcome is unknown.

Migration 64 moves cached responses into indexed SQLite rows and preserves the
older bounded cache. Cache writes, confirmed usage settlement, and unresolved-
identity removal share one transaction. Exact lookup reads one response rather
than decoding every cached response. Cache retention is seven days, at most
128 rows and 512 KiB of payload and identity bytes. The rolling usage ledger
retains at most 4,096 reservations; reaching that limit stops new reservations
until entries expire. Usage summaries remain bounded aggregates.

Migration 65 adds source-order and recent-order content indexes. Production
selected-content reads use bounded keyset pages. A cursor stores a revision, a
hash of the session identity and query inputs, and the last source key, turn
index, row ID, and part index. The query inputs include the published fence
scope, source generation, activity cutoff, source positions, parser and evidence
schema revisions, and selected fields. A change to any of them rejects the
cursor before content is read. The Store checks that the publication still
matches the session generation, fingerprint, parser revision, evidence schema,
and ready status in the same transaction as the page query.

Pages use stable source/turn/row/part order, with a separate reverse order for
recent activity. The full position distinguishes duplicate source coordinates
and multi-part rows. Pages seek after the saved position; they do not use
ordinal offsets. After a validated resume, the cursor may continue through rows
that remain in the same immutable publication. Newly published or changed input
requires a new cursor. For recent-history checks, each page also loads bounded
context before the activity cutoff and through the current page boundary; that
context does not advance the cursor. Page state and carried comparison state are
saved separately.

The selected-page query caps output at 288 source IDs and 1.125 MiB of selected
text. These bounds apply to selected content, not every allocation in the
application. Cursor serialization stays local and is not sent to TypeSafe.
Selected normalized-field limits count UTF-8 bytes, including JSON envelope
bytes. SQLite character counts do not define the selected-page byte allowance.

Compact checkpoints save each answer's original request binding, so a later
packing layout does not require a paid request for completed work. Checkpoint
serialization borrows cursor data and caches follow-up descriptions within one
immutable assessment. A check can opt into append reuse only when its shared
reuse scope and exact work-item content, questions, and local bindings match.
Changed reference text, selection, model, or evaluator revisions invalidate it.
