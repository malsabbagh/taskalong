# Local operations

Use the installed console script or `python -m taskalong`. The CLI's `--help` is
the authoritative command syntax for this experimental foundation. Start with version
and model-free doctor output; missing credentials, authorization, compatible
profile, containment or reviewer remain typed blockers. Doctor never logs in,
installs a runtime, edits personal configuration or launches inference.
Production start/resume currently fail preflight with
`runtime_policy_unsupported` for every production profile. Full effective exec
configuration/instruction/tool discovery and owned `--no-daemon` worker lifetime
remain unqualified; a passing no-model command probe or operator-supplied receipt
ID does not remove this gate. Synthetic test profiles exercise the implemented
core without enabling live source transmission.

State belongs outside repositories and site-packages. Linux defaults to
`$XDG_STATE_HOME/taskalong` (absolute paths only) or `~/.local/state/taskalong`;
macOS defaults to `~/Library/Application Support/TaskAlong`. An explicit operator
state directory must be private, owned by the current OS user and have no
symlinked control paths. On macOS, resolve an operating-system temporary-root
alias before selecting a scratch state directory. Never chmod an existing shared
directory to make it pass. Local filesystems and one trusted OS operator are the
supported model; multi-user stores and network shares are unsupported.

New stores carry the `application=taskalong` metadata tag. Untagged or foreign
application stores are rejected with `unsupported_store_application`; do not
relabel them to bypass this check. This candidate does not import or migrate
another installation's stores, worktrees or sessions. Preserve those records
and use their owning application. TaskAlong uses its own state/control paths.

The state store uses SQLite WAL, foreign keys, full synchronous transactions and
bounded busy waits. A transaction advances one run revision and appends its
ordered events together. Content-addressed blobs are durable before references
commit. Missing or tampered referenced blobs block recovery/acceptance; orphaned
blobs remain preserved. Never reset a corrupt store, discard its event history,
or relabel a future format to run older code. Use SQLite's backup API rather than
copying only a live database file without its WAL.

Repository registration binds its canonical Git common directory to one state
store. A common-directory OS lock serializes admission and a lease fences mutable
work. Keep the primary checkout clean and unchanged. TaskAlong retains owned marked
worktrees and branches after completion and never stashes, resets, adopts foreign
work or performs automatic cleanup. Do not remove its live lock file. Dirty or
foreign workspaces and unknown processes require operator reconciliation.

After a cancelled, failed, accepted or draft-published run is quiescent, the
operator can release repository exclusivity explicitly:

```sh
taskalong --state-dir /absolute/private/state retire-workspace RUN_ID \
  --expected-revision REVISION --key unique-retirement-key --json
```

`RunService.retire_workspace` provides the same operation. Retirement requires
all operation guards, no active attempt or unresolved effect, confirmed cessation
for every recorded invocation, and the matching workspace fence. An accepted run
also requires its exact candidate. It records `workspace.retired` and revokes the
old fence while preserving the worktree, branch, marker, evidence and history.
A later task receives a fresh workspace and a greater repository generation.
The retired run cannot resume, verify or publish; this operation does not delete
data or release an uncertain process. Repeating the same key returns its original
retirement receipt.

Worker tools and verifier commands need the qualified named command sandbox.
The Codex parent may use already authorized runtime authentication; child tools
must not read private control state or credential paths, change Git metadata,
write outside the exact workspace, or access network. A missing sandbox capability
blocks execution. Inference source disclosure remains a separate operator grant
from disabling tool network access. Runtime session retention is owned by Codex;
TaskAlong does not delete or migrate those sessions.

Submit creates immutable task state without launching work. Start requires
separately admitted local-effect/inference authority. Status is read-only. Cancel
records a request; only owned-process cessation can confirm local cancellation.
An outer CLI interruption does not stop a detached supervisor. A stale heartbeat
or numeric PID alone never authorizes killing or reusing a process/workspace.
Reconcile is an explicit mutation and can remain uncertain. On Darwin, the
kernel exit/fork observer only confirms non-forking lifetimes: any observed fork
quarantines the invocation. Linux uses a separate non-dumpable child subreaper
and target-inaccessible status pipe; root exit plus kernel child reaping is its
cessation boundary. Linux support is pending exact-head CI and installed
qualification. Missing or lost lifetime receipts remain uncertain on either
platform. Native resume requires
the observed thread, compatible task/profile/content, fresh attempt/fence and
remaining persisted budget; restart is separately explicit. Provider cost and
remote billing cessation can remain unknown after local process death.

The standard foreground `verify` CLI defers Ctrl-C while it collects the owned
process cleanup receipt and persists the capture outcome, then returns exit 130
with `verification_interrupted`. Confirmed cleanup leaves a blocked run that can
be inspected and verified with a fresh key, accounting for actual captured bytes.
Unconfirmed descendants keep the effect unknown and the workspace reserved. This
does not repair an older interrupted effect with no durable receipt, and a process
crash/SIGKILL can still require quarantine. Custom caller signal handlers retain
their own semantics. Interrupting a client of a detached worker still does not
cancel that worker; use the explicit cancellation operation.

The [installed fixture walkthrough](fixture-walkthrough.md) is also available as
`taskalong guide`. Synthetic command launchers require explicit `configure-sandbox`
admission and make no containment claim. Reviewer setup should select both the
reviewer executable and its Python interpreter from the intended installed venv.
A missing executable returns `review_executable_missing` with an actionable
prerequisite rather than a local-store failure.

Independent verification rechecks exact content before and after each check and
released ReviewSensei invocation. Worker command claims cannot satisfy criteria.
Only full current released review coverage plus all required checks can accept.
A synthetic fixture result is labeled synthetic through acceptance and can never
authorize production publication. A missing optional ReviewSensei installation
blocks required review rather than weakening the acceptance policy.

Use `RunService` or its CLI for start/status/cancel/resume/reconcile. Direct
`CodexCLI.start` and `.resume` return `supervisor_required`; the actual bounded
`.run` driver belongs beneath the durable per-run supervisor. Registration,
profile/configuration and `authorize` commands are privileged OS control-plane
operations. They record the current OS principal and
`human_decision_observed=false`; they do not authenticate a person from a supplied
name or worker claim. Synthetic sandbox/transport settings cannot enable a
production TaskSpec.

Publish-intent displays exact candidate, evidence, repository/base, branch, title,
body and draft payload. An explicit publish invocation with that intent digest
admits the exact effect from the trusted OS operator. It does not authenticate a
self-declared human name. Git branch creation uses an expected-absent lease;
existing foreign refs block. PR discovery searches all states with a stable run
marker. Unknown responses are reconciled by read-only lookup, never blind POST
retries. Publisher Git transport checks process-group exit plus protocol and
remote read-back. That narrower transport observation cannot establish
worker/check quiescence, authorize a pending worker effect, or release a
quarantined lease. Rollback/cancellation does not delete or close a branch or PR.

Default export is redacted metadata. Raw prompts, source, reviews, runtime handles,
private paths and logs are private artifacts and are not automatically included.
Input screening/redaction is a secondary defense with documented limits, not a
claim to detect arbitrary secrets. No telemetry, automatic retention deletion,
legacy store discovery, credential setup or package registry upload occurs.

Rollback means stop/reconcile owned processes, disable new starts if a profile
fails, preserve unknown processes/worktrees/state, and reinstall the last reviewed
qualified wheel using a separate scratch state directory if needed. Reverting
source does not undo external effects. Licensing, per-file extraction rights,
public notices, live qualification and public release remain separate owner gates.
Application code/resources/fixtures are original; the source import allowlist
remains empty. The [MIT License](../LICENSE) includes the owner-approved copyright notice.
The runtime dependency floor is `jsonschema>=4.26,<5`, reflecting the exercised
version; use the exact hashed qualification lock when replaying evidence.
See [contracts](contracts.md), [provenance](provenance.json) and
[qualification](qualification.md) for exact boundaries and evidence.
