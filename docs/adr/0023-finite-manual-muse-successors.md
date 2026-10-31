# Finite manual successors of a local Muse timeout

Status: proposed.

A short local deadline can expire before a coding response exists. A larger
deadline must not erase the consumed request, repeat a successful or ambiguous
execution, or become an automatic provider retry loop.

The OS operator explicitly configures and invokes a successor in the original
state store. Task/response JSON cannot request one. The first successor has a
360-second local deadline; a final successor has 720 seconds and requires the
first to end in a qualifying local timeout without a response. Both retain the
same bundle, binary, account roots, model/effort, context pins and capture/proposal
limits. The ordinary default remains 20 seconds. New config format `/3` supports
the finite 1–720 range and makes older clients refuse rather than ignore it.

Local timeout eligibility requires retained root exit and group termination,
clean tracking/cleanup, no cancellation/overflow/protocol error, unchanged
process/invocation/prompt/captures and append-only event identity, and the native
session's cancelled-during-model-step terminal. Completed, failed or conflicting
stdout terminals, complete JSON output, staged responses and partial staging all
stop the ladder. Final admission revalidates the original first-plan artifact
hashes as well as the immediate predecessor. Unknown remote usage and complete
descendant cessation remain unknown: a native cancellation observation is not
remote cancellation acknowledgement or settlement.

Alternative: changing the task nonce or creating a fresh state would abandon the
old claim and liability. Alternative: trusting only SQLite permits an older backup
to reopen a slot. Instead, append exclusive reservation indexes in the same store
and retain a separate private control directory beside the original output, named
`.taskalong-muse-successors-<root-run-id>`. Its immutable enrollment and two slot
files bind the original root, original state scope and exact successor descriptors.
Original run/bundle/native journal bytes are never modified by the successor.

An exclusive slot file precedes the database reservation commit and every native
preflight. Crashes, failed commits, denials and other setup failures retain the
slot; absence of a result never refunds it. A repeated key only observes the
existing successor, including an incomplete reservation. Competing keys cannot
create another child. Copied/restored databases conflict with the retained
control directory. Partial directory creation is not automatically repaired.
This is a cooperative local fence, not an external coordinator or protection
against an OS operator deliberately deleting/forging history.

The plan is a model-free measurement, not a transferable grant. Execution
recomputes it from owned state and artifacts, compares its digest, reserves one
slot, revalidates after native preflight, and checks again before process gate
release. The API schedules nothing: each successor needs a separate explicit
owner invocation. Only the existing bounded process owner performs cancellation.
No saved-PID signalling, new credential, security setting or provider fallback is
introduced. No exposure/production ledger or old charge is rewritten.

At most two new controller submissions are possible in this ladder, with 1,080
seconds of selected local Meta deadlines plus separate preflights and cleanup.
Those are reservations/upper bounds, not measured remote inference or spending.
A proposal stops the ladder for manual review/application and independent tests.
Any non-timeout failure or uncertain local cleanup stops it as well.

Rollback retains all claims and the separate control directory. Older clients
refuse `/3`; they cannot erase these reservations. No new SQL migration is needed.
Tests cover complete public API/CLI journeys, conditional final admission, strict
deadlines, competing reservations, crashes, restored/copied databases, root-byte
preservation, artifact/config drift, output isolation and ambiguous results.
