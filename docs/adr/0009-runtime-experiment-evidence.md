# Bounded model-free runtime experiments

Status: proposed for review in M9.

Add a standalone version-1 experiment plan, private proof manifest and offline
replay report. Preserve every shipped schema/SQL byte, schema-name enumeration,
TaskSpec/DriverConfig version and store format. Use the existing owned process
boundary; add no launcher, persisted-PID kill path, registration or migration.

The closed `owned-host-canaries-v1` profile runs original generated, non-forking
helpers. It measures permitted reads/writes, original bounded captures,
pre-dispatch refusal, completion, cancellation at the owned gate and cancellation
after a nonce-bound ready event. Verdict and capability differ: a correct refusal
passes its negative oracle while the requested capability remains unsupported.
Production dispatch, vendor inference and network isolation are not established.

Pure validation receives bounded immutable bytes. It reconciles the exact plan,
subjects, required case inventory, original protocol/effect/capture identities,
process receipts, cleanup and terminal ordering. Empty streams are valid;
missing bytes, forged success, changed subjects, unknown cleanup, truncation or
write failure cannot pass. Failed observations stay failed. Unknown counts stay
unknown; the first cleanup uncertainty survives a secondary persistence error.
Original captures remain private under new owner-only directories and files.
Path identity checks detect cooperative substitution; they are not hostile
same-user containment or atomic filesystem sandboxing.

An installed model-free campaign creates fresh evidence for its actual current
host, logical interpreter, package, artifact, copied helper and runner. Freeze
expected payloads independently from the audited wheel and dependency lock;
verify actual site-package bytes and refuse source fallback. Retain the installed
wheel identity separately from its originating sdist. A declared file catalog is
not a complete native/runtime closure; unmeasured components remain explicit.

Installed replay is a separate offline operation with zero child launches. It
checks an existing immutable proof through the installed reader and emits a
separate report binding the original manifest/evidence set and verifier inventory.
Keep original subjects, origins, times and outcomes. A valid failed source proof
remains failed/source-origin; a successful replay never becomes fresh execution
or producer authentication. Reuse and input/output overlap refuse. Required fresh
installed host experiments cannot be replaced by replay.

Live responder, actual-provider and native-resume stages refuse before credential
resolution, listeners, package discovery or helper dispatch. Future enablement
needs a separately reviewed exact-mode context/closure, current external consent,
observed routing and enforceable lifetime/budgets. No implicit fallback or live
qualification follows from a stage name, executable, digest or producer ID.

Alternatives rejected: treating the helper's success prose or exit zero as proof;
relabeling source evidence as installed; making the runner trust its own receipt;
changing M2 evidence limits; interpreting signal/PID disappearance as cessation;
and using model-free completion to register a live adapter. The M2 evaluator and
current trusted approval/revocation gates remain authoritative. This milestone
emits no M2 receipt and grants no execution authority.
