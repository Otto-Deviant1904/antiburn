# Ignored Instructions evaluations

This directory owns the desktop crate's synthetic evaluation runner, support code,
and active development and regression JSON data. The independent confirmation
wrapper is part of the same Cargo target. Its sealed fixture stays at its existing
path and is not part of the development or regression inputs.

Every case has one semantic outcome label. `bindings.json` keeps exact production
rule/action IDs separate from semantic source references. A finding with
`resolution: "pending"` is not ready for live execution. Empty bindings are
explicit and valid only for a reviewed non-finding, pending, or unassessed label.

The 192-case development inventory has 51 finding cases and 52 resolved
rule/action pairs. The separate focused cohort has 13 resolved positive cases.
The historical heldout cohort has 48 regression cases.

The first-version live acceptance gates in `data/gates.json` require at least
80% joint outcome-and-exact-binding accuracy, 80% observable binding recall,
80% published binding precision, and complete scheduled results with exact
binding labels. The joint thresholds are 128/159 development cases and 39/48
independent confirmation cases. Counts use scheduled cases, observable expected
bindings, and published bindings as their respective denominators; a missing
result is a non-pass, and a zero-denominator metric is unavailable. Publication
confidence thresholds remain 0.85 for possible and 0.90 for likely findings.
Development evidence alone does not establish independent acceptance.

The latest complete development run (`questions37`) reported 133/159 joint
passes, 43/52 observable bindings recalled, and 43/46 published bindings
correct. These counts clear the first-version numeric thresholds on that run;
fresh independent confirmation at a frozen implementation is still required.

Run offline harness checks with:

```sh
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --test ignored_instructions
```

Live tests remain ignored by default. They require explicit authorization and
write unique captures under `.agent-artifacts/reviews/`.
