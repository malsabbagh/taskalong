# Bounded ordered CLI tasks

Status: proposed with M10, issue #10.

Use the allocated explicit 2.7 family for task-spec, task-run, step-receipt and
result-view. Current accepted main `63f54a04d7ca95b440a8717474d8d1f4a0facf13`
already assigns Muse format 9 / SQL009 and ADR0011–0012. Astra's October 26 decision
reconciles the older issue allocation: M10 uses format 10 / SQL010 and ADR0013,
preserving all inherited resources, including the 65-resource historical minimum
and subsequent Muse additions. Follow explicit backed-up 8 → 9 → 10 maintenance;
the actual format-9 reader must refuse 10 before journal changes, with additional
format-8 refusal and E1/Muse history preservation coverage.

Choose one fixed existing synthetic v1 Codex executor for the complete plan.
Reuse its wire contract through an explicit closed 2.7 mapping; do not relabel
the full task as v1. The wire packet digest and its ordered-step extension bind
the full task, step, attempt, predecessor and reservation. Alternatives were a
per-step adapter projection framework or nested independent runs. Both add scope
and split ownership unnecessarily. M11 output declarations/selectors and other
providers are excluded.

Keep one Workflow, Store, lease, dispatch guard and existing owned supervisor.
Submit validates the entire sealed plan. Start reserves the first attempt;
explicit advance atomically prepares only the next pending step, and explicit
retry prepares only a stopped failed current step. Every dispatch retains current
authority, executable, cancellation, lease and input checks. Compare each attempt's
actual delta with its immediate pre-attempt checkpoint and step scope, and compare
cumulative changes with the original task scope. A failed illegal partial edit
cannot become a retry checkpoint.

A successful finish atomically records the immutable result/checkpoint receipt
and step state with the original effect settlement. Intermediate `ready` means
completed worker plus pending required steps; it does not launch final checks.
Receipt validation rereads blobs, exact attempts, process cessation, packets,
reservations and predecessor links. Late callbacks cannot finish a newer attempt.
The existing proven no-dispatch preparation recovery and unknown-process
quarantine remain. Client loss supplies no new process ownership.

Reserve attempts, full execution time and bounded captured output before launch,
with no refunds. A final verification pass reserves its own declared allowance;
observed capture bytes remain separate. Unknown token/cost usage does not become
zero or a hard guarantee. Identical operation replay reuses the original receipt;
changed targets conflict. Failed steps stop the sequence, and cancellation stops
further worker/final-check launch.

Only a completely revalidated chain may enter the existing candidate, check,
ReviewSensei and independent acceptance path. The acceptance extension binds the
actual receipt-chain digest; normal evidence binds exact candidate/task/packet.
Revalidate the chain/candidate at verifier dispatch and final commit. Ordered
runtime publication is explicitly unavailable. Old single-step documents and
sealed resource bytes retain their meanings; their prior readers remain intact.
Rollback means a verified pre-upgrade backup in a new quarantined location, not a
version downgrade or restoring over later effects.

Qualification uses public CLI subprocesses and the existing original fixture,
with independent audit cases for ordering/replay, failure/retry, reservations,
cancellation, scope/input/checkpoint/result tampering, interruptions, migration
and source/installed-wheel/rebuilt-sdist/core-only distribution boundaries.
