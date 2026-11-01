# Shared owner for configured experimental providers

Status: proposed.

The later explicit large-task option uses `configured-provider-profile/2` for a
finite deadline through 1440 seconds. Version `/1` keeps its 720-second ceiling;
defaults remain 720. Muse uses a distinct `local-muse-provider/5` `large-task`
configuration, with separately retained raw/proposal/record limits. No historical
claim, deadline or recovery cohort is extended by these new configuration formats.

## Context

Configured Codex, Antigravity, and Claude Code need one usable local task path
without copying process admission, capture, claims, cancellation, or recovery into
each adapter. Claude's Anthropic and Ollama backends share a native CLI protocol,
while their runtime closure and route declarations differ. Existing production
qualification and refusal rules remain separate. Configuration enables the
experimental route without an additional permanent activation gate; it does not
qualify a release, installed native tools, or remote inference behavior.

## Decision

Use `local_provider_runtime` as the shared owner for `codex`, `antigravity`, and
`claude-code`. Passive adapters validate a closed
`configured-provider-profile/1`, project fixed argv/stdin/environment changes, and
decode native observations. Only the owner checks actual source and runtime
fingerprints, reserves a logical submission, releases its owned child, captures
streams, and stages an independently validated manual proposal. Codex retains its
existing `CodexCLI.run` handoff rather than adding another Codex process driver.

Keep the public sequence configure → prepare/budget → run → status/result →
cancel/reconcile. Source API names are `configure_provider`,
`prepare_provider_task`, `provider_budget`, `run_provider`, `inspect`, `result`,
`cancel`, and `reconcile`. The generic request explicitly supplies repository,
exact base commit, task, read-only paths, writable paths, and artifact format.
Preparation observes selected tracked text and truly absent new outputs; a new
output has a null preimage. Read-only context cannot become write authority.
Integrity validation of a serialized plan alone is not source authentication.
The owner rechecks the actual caller-selected repository before release, and a
human must verify it again before manual application.

Support `file-replacements/1` for all three providers. Support `unified-diff/1` for
Codex and Antigravity to avoid requiring whole-file output for a small large-file
edit; refuse that representation for Claude before claiming a submission.
Validate exact paths, counts, positions, context, hashes, presence, and modes;
reject partial output, aliases, renames, binary forms, and arbitrary mode changes.
The resulting artifact grants no execution, automatic application, retry,
independent acceptance, or production authority.

Preserve existing native context through the normal `include` policy. Full
`exclude` fails explicitly. Where native options offer `native-only`, document it
as partial reduction, with remaining managed/native policy and unqualified
isolation. Native sandbox, permission, tool, structured-output, model, and effort
flags are intent and protocol evidence, not proof of OS containment or effective
backend behavior.

Bind declared runtime closures. A Codex Node entrypoint includes fingerprints for
Node, the entrypoint, and the declared native binary. Ollama binds the existing
launcher and Claude executable, the launcher PATH, and the effective
`$HOME/.ollama/config.json` bytes and exact saved-model pointer. Recheck HOME,
PATH-resolved Claude identity, and saved selection before release. Do not add
`--yes` or silently change saved model preferences. A loopback Ollama daemon may
use local or cloud inference; preserve the explicit route distinction without
claiming authenticated local-only execution. Native Anthropic live qualification
is not established by the offline protocol or configuration tests.

Use finite shared limits: a default of 720 seconds and that same ceiling for
profile `/1`; profile `/2` permits an explicit deadline through 1440 seconds.
Both versions retain 4 MiB combined captured output,
8,192 protocol records, 1 MiB per protocol record, 64 KiB canonical proposal, and
one reserved controller submission. The owner uses an absolute deadline;
bounded cleanup and evidence finalization may extend briefly beyond it. Keep
raw streaming capture and immutable checkpoints, distinguish retained from
observed bytes, and reject overflow or incomplete evidence as success. A local
reservation is not a remote request count or settlement guarantee. Native retries,
remote usage, remote cancellation, and complete descendant cessation can remain
unknown. Preserve those obligations rather than refunding a consumed claim.

Cancellation durably records an identity/revision-bound intent for the current
owner. It never derives signal authority from a persisted PID. Reconcile reads
retained evidence without redispatch, automatic marker replay, or mutation of the
owner's attempt history. Interrupted publication remains unknown. Controller
budget or artifact-format changes cannot create fresh submission authority.

Keep Muse's legacy request/bundle and macOS execution route intact while using
durable streaming capture and the shared cancel/reconcile controls. Its fixed
implementation capture profile and existing explicitly authorized finite
successor mechanism retain their own identities; ordinary run does not retry.
Do not weaken any production refusal or claim that the experimental paths are
production qualified.

## Alternatives and consequences

Per-adapter lifecycle owners would duplicate effect boundaries and could disagree
about retries, capture closure, or cancellation. Reusing production qualification
as a permanent experimental activation requirement would prevent the configured
local path without adding evidence about the installed runtime. Treating native
terminal records, flags, or one subprocess as complete cessation and billing
proof would erase material unknowns. These alternatives are rejected.

The shared owner supplies a consistent experimental path while preserving native
protocol differences. Strict context and artifact support may refuse a requested
combination; the caller must select an implemented combination explicitly.
Synthetic tests and process canaries validate the implemented local contracts,
not full release qualification or native backend guarantees. Runtime behavior and
unknown remote obligations must remain visible in retained evidence.

Rollback can refuse new configured profiles and shared runs while retaining
configuration identities, claims, captures, control intents, and receipts.
Rollback must not delete evidence or turn a prior consumed/uncertain claim into
permission to rerun it.

See [configured providers](../configured-providers.md) for current schemas,
synthetic examples, limits, source references, and operating flow. Earlier
proposed decisions [ADR0022](0022-configured-experimental-provider.md),
[ADR0023](0023-finite-manual-muse-successors.md), and
[ADR0024](0024-bounded-implementation-capture.md) describe the legacy Muse path and
its bounded successors.

### Explicit larger response profiles

Configured-provider profile `/4` and Muse `/6` add an opt-in one-MiB canonical
proposal contract without reinterpreting earlier configurations or granting a
new submission to a consumed task. The expanded ceilings are 64 MiB combined
raw capture, 131072 protocol records, 16 MiB per frame, 4 MiB response-wire JSON,
4 MiB generated review patch and the existing 1440-second deadline option.
Authority JSON keeps its one-MiB ceiling. Large responses are separate immutable
files referenced by small, verified hashes in run events and observations.

The existing process owner can omit full transcript buffers only when a trusted
live capture sink is present. Bounded per-frame decoders and held-file iteration
consume the raw evidence, with independent raw and immutable-checkpoint fences
at iterator exhaustion. Muse's postrun identity observation uses a separate
64-MiB streamed journal reader, retaining only small identity fields and an
observed request count. Startup context and earlier journal readers stay at their
previous bounds. Neither reader authenticates vendor data cryptographically.

These controls bound retained controller data rather than impose an OS quota or
prove a peak RSS, provider cost, remote cancellation or descendant cessation.
The expanded limits support representative framing and escaping, not every
possible repetition pattern. Overflow and incomplete evidence remain failures;
there is no adaptive cap growth, replay, automatic application or acceptance.

### Expanded capture-recovery decisions

A separate versioned plan/reservation/enrollment `/3` may link an original failed
Muse `/5` large-task capture to one `/6` attempt. Scope and deadline stay fixed;
the explicitly selected capture/proposal envelope changes. Earlier timeout and
capture identities retain their original rules. Planning reads evidence only;
reservation precedes any native preflight and consumes the single final slot.

This path distinguishes a hash-closed limited prefix from a complete protocol.
Complete JSON in nonterminal fragments is unsealed inspection metadata, never an
accepted result. A completed-terminal prefix, a conflicting terminal, a staged
result, ambiguous journal evidence or missing cleanup proof blocks dispatch.
In particular, truncation inside a native completed-terminal text is not
cancellation evidence. Full bound native completion evidence must be reconciled
before considering another attempt; verified result recovery is not implemented
by the successor path. Old failure status, claims and unknown exposure survive.

### Sealed complete-result observations

Complete-result recovery is a separate model-free local operation, not a
successor attempt. It requires stable full native completion evidence and checks
the committed response against the original scope and bounds. A new immutable
observation and staged proposal reference the failed run without rewriting its
status, submission claim, captures, history or unknown remote exposure. A shared
exclusive anchor prevents recovery from racing a successor or being repeated
through copied or restored State. Reservation precedes local staging; uncertain
local outcomes are observed instead of restaged. Recovered snapshots retain the
original submission marker and cannot become a fresh inference route. Captured
fragments alone never authorize this operation.
