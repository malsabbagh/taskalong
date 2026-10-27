# Explicit experimental Darwin foreground observations

Status: proposed for review. Related design: issue #30.

## Problem and decision

Native CLIs may fork even in model-free operation. The existing Darwin process
owner observes `NOTE_FORK`, but XNU does not supply descendant identities through
its supported kqueue boundary. Root exit and an empty process group do not prove
that a descendant which changed its session or group stopped. The existing
production result must continue to refuse complete cessation after a fork.

Add `taskalong.experimental_process.run_foreground_experiment`, requiring the
literal `darwin-foreground-experiment/1` mode in trusted caller code. Reuse
`process.run_bounded` for its gated launch, bounded streams, deadlines, callbacks,
cancellation and existing live-handle group signalling. A private observation
sink adds fork and tracker-error facts without altering `ProcessResult` or its
serialized fields. No RunService/driver registration, handoff, schema, Store
migration, persisted-PID signalling or automatic retry is added.

Return a distinct experimental result: root exit/code, process-group cessation,
fork observation, tracker errors, timeout/cancel/output-limit facts and redacted
bounded output. Preserve process-boundary failure codes and `not_sent` versus
`uncertain` effects. A pre-release tracking refusal still blocks target launch.
The experimental result always reports descendant cessation `unknown`,
`termination_confirmed=false`, and no production dispatch, workspace reuse or
acceptance permission, even for a non-forking observation.

The caller may inspect an observed candidate and run independent tests under an
explicitly authorized experiment, recording the unknown-writer caveat. Neither
that inspection nor passing tests establishes a stable snapshot, quiescence,
production handoff or accepted work. Do not replay, resume or reuse an uncertain
workspace automatically. The operator retains responsibility for any separately
authorized follow-up; this API provides no reconciliation authority.

## Limits and alternatives

Retain the existing signal ownership rule: only the still-live owned Popen root
can authorize group signalling. If it exits first, report the actual group state;
do not signal a saved PID/PGID or claim cleanup occurred. Escaped descendants may
outlive the foreground invocation. Local cancellation also does not establish
remote request settlement or stopped subscription consumption.

Widening the production result or adding a permissive flag to its acceptance
logic was rejected: existing callers could mistake weaker observations for full
cessation. A second launcher was rejected because it would duplicate the gate,
stream and signal implementation. Process-list reconstruction, a new daemon,
launchd group cleanup and unsupported kqueue child tracking do not provide a
qualified unprivileged full-tree guarantee and are outside this change.

The mode grants no model/data/network, credential, billing or tool authority.
The actual host pilot requires its separate existing-account scope and explicit
acceptance of the weaker guarantee. Protective CLI/OS settings remain in effect.
No vendor command, authentication or inference runs in this change's tests.

## Validation and rollback

Real finite Python helpers cover fork-and-wait, rapid parent exit, double-fork
session escape, timeout, cancellation and output exhaustion. An escaped fixture
closes inherited pipes, completes within a short deterministic lifetime and
signals only its own completion marker; no persisted identity is used for
cleanup. Fault injection separates registration/poll errors from fork events.
Default process tests preserve their existing strict result and serialization.

Remove the separate API and observation sink to roll back; there is no persisted
state or compatibility migration. The optional future Docker/remote backend and
session sharing in issue #30 remain separate work.
