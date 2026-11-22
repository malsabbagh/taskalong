# Ordered CLI fixture tasks

M10 runs 1–8 required steps with one fixed existing synthetic Codex fixture,
one Workflow, Store, lease and owned workspace. A step completion means a
validated worker result and stopped workspace checkpoint. Independent checks and
released ReviewSensei fixture review accept only the complete final candidate.
This recipe makes no provider request and cannot publish a branch or PR.

Use the matching source archive and installed wheel with the review extra as in
the [installed walkthrough](fixture-walkthrough.md). The fixture executable is
original test data in that archive, not a product executable shipped in the wheel.
From the source archive, choose a new absolute, private scratch directory:

```sh
python tools/ordered_fixture.py --directory /absolute/new-ordered-example \
  --review-executable /absolute/venv/bin/review-sensei
```

Use that same installed Python/CLI environment throughout. The setup creates a
disposable Git repository, original fixture/check launcher, sealed two-step
`task.json`, and state outside the repository. It explicitly upgrades through each
numbered format with a complete backup and quarantined restore at every step.
Omitting the reviewer permits the core-only demonstration; the final result then
blocks with `required_review_missing`, and cannot be accepted.

Run these CLI commands, substituting the observed run ID and revisions. Each
mutation requires a unique key, except when deliberately replaying the identical
operation and arguments. `status` and `result` never launch or reconcile work.
For this generated fixture only, keep the same process-local Git configuration
selection as the setup; these environment values do not edit Git configuration.

```sh
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
taskalong --state-dir /absolute/new-ordered-example/state validate \
  --spec /absolute/new-ordered-example/task.json --json
taskalong --state-dir /absolute/new-ordered-example/state submit \
  --spec /absolute/new-ordered-example/task.json --key submit-example --json
# Use the returned run_id, spec_digest and revision.
taskalong --state-dir /absolute/new-ordered-example/state authorize RUN_ID \
  --decision-digest SPEC_DIGEST --scope execute verify commit_candidate --json
taskalong --state-dir /absolute/new-ordered-example/state start RUN_ID \
  --key start-example --expected-revision REVISION --json
taskalong --state-dir /absolute/new-ordered-example/state status RUN_ID --json
taskalong --state-dir /absolute/new-ordered-example/state result RUN_ID --json
```

After A stops, `steps` shows A `completed` and B `pending`, `state` is `ready`,
`next_actions` is `["advance"]`, and no final check, review or acceptance exists.
Copy A's `receipt_digest` and the current `revision` from status. Advance once:

```sh
taskalong --state-dir /absolute/new-ordered-example/state advance RUN_ID \
  --step-id B --predecessor-digest A_RECEIPT_DIGEST \
  --key advance-example --expected-revision CURRENT_REVISION --json
taskalong --state-dir /absolute/new-ordered-example/state result RUN_ID --json
```

B edits only its own file in the retained workspace. After B completes, the
existing independent final checks and review run against the exact candidate.
`result` reports both step results, attempt IDs, conserved reservations, observed
usage, execution-chain digest, acceptance digest and stop reason. Success requires
`state: accepted`, `outcome: accepted` and `independently_accepted: true` together.
A failed final check remains a failure; completing every worker alone is not
acceptance. No branch push or PR transport is available for this task family.

A settled failed step reports `next_actions: ["retry"]`. Use `retry RUN_ID
--step-id B --key NEW_KEY --expected-revision CURRENT_REVISION`. It retains A,
failed-attempt history and every reservation. A retry requires remaining allowance,
confirmed cessation, clear effects and an unchanged scope-valid checkpoint.
Cancellation uses the existing `cancel` and explicit `reconcile` commands;
cancelling between steps or during a worker prevents subsequent workers and new
final checks. A missing PID, client disconnection or timeout never proves cessation.
An uncertain worker remains quarantined, with `reconcile` as the next action.

The complete task is validated before launch: unique IDs and required fields,
fixed synthetic configuration, scope containment, existing input path/SHA-256
pairs, and enough declared attempts/time/output for every required step plus
final verification. Each dispatch rechecks current authority, executable and input
bytes. Empty inputs are valid; prior-output selectors, per-step configuration,
live providers, hard token/cost guarantees and unknown versions refuse.

Each worker reserves its full `attempt_seconds` and `attempt_output_bytes` before
launch; each final pass reserves its declared time and output. Reservations never
refund. `reservation_totals` records those allowances separately from
`observed_usage`, which reports measured worker duration and captured output.
An unfinished worker or uncertain capture leaves the relevant observed total
unknown. Legacy `budget_consumed.active_seconds` remains the conservative worker
time reservation; legacy output consumption can also retain a conservative bound
after an uncertain capture. Token/cost usage remains unknown where unsupported.
The final time declaration must cover every declared
check timeout plus the existing two 15-second reviewer probes and 60-second review.
Replaying an operation returns the original receipt without another charge/launch.

Schema family 2.7 requires explicit store format 10 / SQL010 on current main.
The accepted Muse format 9 / SQL009 and ADR0011–0012 retain their meanings;
[ADR0013](adr/0013-ordered-cli-tasks.md) records the allocation reconciliation.
Existing format-8 E1 history migrates only through backed-up 8 → 9 → 10; older
clients refuse the new format. Never edit version markers or restore over a live
store. Preserve unknown processes, private captures and complete backups.
