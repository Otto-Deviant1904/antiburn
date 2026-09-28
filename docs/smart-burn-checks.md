# How Smart Burn Checks work

Smart Burn Checks are like deterministic Burn Checks: both look for signs of
known issues in coding sessions. Smart Burn Checks send small, selected parts
of a session to Jev for an assessment. Antiburn then combines those assessments
with its local rules. The result describes evidence of an issue; it does not
judge a person's intent.

Ignored Instructions is the first check that uses Jev. It needs a TypeSafe API
key. Jev requests can use paid API credits. Antiburn shows local usage totals in
Settings.

## What the check reads

The session reader turns each supported agent's records into the same event
format. This lets the check handle different agents in the same way.

The check selects:

- Instruction text found in the session or in supported instruction files.
- Assistant text that describes work.
- Complete normalized tool inputs, such as shell commands and structured edit
  arguments.

The check removes tool-result text and private thinking before sending a
request. Paths, event IDs, line numbers, and citation links stay on the
computer. Jev gets temporary labels; Antiburn uses a private map to connect its
answers to the original session events.

## How instructions are split

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

Instruction source also matters. A rule saved as part of the session is
stronger evidence of what the agent saw than a file read from the current
worktree. A current file may have changed since the session. The reducer keeps
that difference when it decides whether to publish a finding or a clean result.

## How sessions are split

The check starts at the saved enablement boundary, or at the selected history
window for a history run. It includes supported content after that boundary.
Assistant text and tool input can be actions to check. A candidate action means
one such event that may match an instruction. Tool-result text is not sent.

Antiburn reads a large session in pages. Each page holds a fixed amount of
content. The first page can have newer events than the second page. The reader
keeps the original order of events and keeps separate conversation branches
apart.

Within a page, the check moves through actions and rules in a stable order. It
makes an **event window** from one action and up to four rules to compare with
it. This sends the action once for those rules instead of copying it into a
separate window each time. One rule/action comparison is a **target**. Long
actions or rules can need several windows, with a small overlap so no text is
skipped.

For example, the instructions might say “Run tests before publishing” and “Get
approval before publishing.” If the session says “Published the release,” the
window has one action and two targets. Jev makes a separate decision for each
target.

An older page may contain an approval or other earlier step for a newer action.
The worker saves that candidate while it reads the next page. It adds matching
earlier events in source order and checks the candidate again. A missing page
does not prove that an approval or prerequisite never happened. If the needed
interval remains missing or cut short, the result stays unassessed.

## What Jev receives and returns

Each event window contains the selected rule text, the action, and a few
nearby events. The check uses two analysis passes. The first pass asks one
applicability question for each target:

1. Does this instruction apply to the action?

The check asks the remaining questions only when Jev selects “applies” and its
probability is at least 0.85:

1. Does the action conflict with or follow the instruction after conditions and
   exceptions are considered?
2. Could missing or truncated evidence change that conclusion?
3. Does the instruction have a completion-bound obligation whose completion
   boundary is not shown?

An answer below that gate does not prove the action is clean. Weak, uncertain,
or incomplete evidence stays unassessed when it cannot support a reliable result.

The shared request code combines windows until the request reaches its size or
question limit. It runs the follow-up pass only for targets that pass the
applicability gate. Jev returns a choice and probability for each answer. The
temporary labels let the shared worker connect answers to their windows, while
the private map connects those windows back to the original rule and event.
This can reduce follow-up questions and token use when few actions match the
selected instructions. The first pass still evaluates every selected target.

## How results become findings

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

## How Jev-powered checks share code

The shared engine contract is `JevCheck` in
`crates/antiburn-local/src/analysis/jev.rs`. A check implements it to define:

- Its stable check ID and input, chunking, question, and reducer revisions.
- How to project normalized facts into bounded `JevInputWindow` values.
- Which local evidence IDs are candidates, instructions, or supporting context.
- Its typed questions and deterministic reducer.

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
`crates/antiburn-local/src/analysis/ignored_instructions/assessment.rs`. Its
desktop adapter is `apps/desktop/src-tauri/src/ignored_instructions_worker.rs`.
That adapter owns instruction discovery, source paging, its saved cursor, and
how its page results combine.

## Adding another Jev-powered check

1. Define a stable check ID and four revisions. Increase a revision when its
   projection, chunking, questions, or reducer changes.
2. Implement `JevCheck`. Select only the normalized facts the check needs,
   group them into bounded windows, bind local evidence IDs, write typed
   questions, and reduce the answers deterministically.
3. Implement `JevCheckWorker` for candidate selection, source preparation,
   check-specific paging, resume state, and result combination.
4. Register the worker and its check ID with Settings and candidate enrollment.
   Reuse the shared scheduler and `execute_jev_batch`; do not add another HTTP,
   cache, or usage-reservation path.
5. Add offline tests for field selection, window boundaries, local citations,
   revision invalidation, partial history, and clean-result eligibility.
   Keep billable live tests bounded and based on synthetic data.

The main rule is simple: the check owns what its evidence means. Shared Jev code
owns how requests run and how progress resumes.
