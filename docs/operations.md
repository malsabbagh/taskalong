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

The offline Muse fixture route requires an explicitly upgraded format 9 Store.
The trusted Python API `RunService.configure_muse_capture(document)` registers
its exact original executable, independent check profile, checks/review digests
and command sandbox; task-spec 2.9 then uses normal submit/start/status/cancel
and verification. Configuration grants no execution authority. The closed route
allows at most 60 seconds and 1 MiB per attempt, and no hard token/cost claim.
Unknown cessation or incomplete capture persistence quarantines the attempt;
repeated start cannot rerun it. No vendor login, model call or live qualification
follows from fixture success. See [the contract](adr/0012-muse-supervisor-handoff.md).

Cancelling a completed Muse fixture run reports a pending result until explicit
reconciliation confirms cancellation. The existing completed handoff, captures
and consumed budgets remain intact; missing evidence or unresolved effects still
refuse reconciliation. Cancellation prevents new handoff creation or completion.
After workspace retirement, `inspect` retains the run history; the Muse current-lease
result view refuses with `lease_retired`, and start and verification remain
forbidden. Retirement does not add a historical result API or restore execution
authority.

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

Denied owned-process signals remain typed `process_signal_failed` errors, even
when later independent observations prove cessation. Cleanup failures retain
the primary failure and bounded stage/errno diagnostics without raw OS messages.
A live process that cannot be signalled returns within the existing escalation,
drain and final-wait allowances with unconfirmed cessation. Later operator or
test cleanup cannot change that returned receipt or release its unresolved effect.
Target non-dispatch and owned wrapper cessation are separate facts. A refused
verifier gate with missing or unconfirmed cleanup retains an unknown capture,
its conservative output reservation and the workspace lease; cancellation cannot
be acknowledged from target non-dispatch alone. This also applies to independent
review schema and version probes.

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

## Quiescent store maintenance

Database format 2 adds immutable installation/provider/binding/decision history.
It is independent of document schema versions. New stores still use format 1;
ordinary opening never silently upgrades an existing store. Original v1 records
and the original legacy profiles remain unchanged.

Close all Store/RunService clients and allow owned invocations to stop and their
effects to reconcile before maintenance. Current clients hold a lifetime shared
gate; maintenance requires its exclusive gate and actual SQLite exclusive
ownership in rollback-journal mode. An open predecessor WAL client prevents that
transition. `maintenance_busy`, `maintenance_exclusivity_unproven` or
`maintenance_not_quiescent` is a refusal, not permission to ignore a lock or kill
an unverified PID. Unknown effect kinds, inconsistent records and uncertain
cessation remain blocked. Only local filesystems and a trusted OS operator are
supported. A new advisory file alone cannot fence older clients.

Qualification checks exact predecessor opening before/after maintenance and
refusal of maintenance while that predecessor is active. Separate real SQLite
subprocesses, with only their own retry handlers disabled, must return numeric
BUSY for protected reads and write reservations while maintenance retains its
kernel lock. Unlocked controls and an advisory-only counterexample must succeed
at those operations. These checks preserve logical state and require observed
child completion/reaping. The ten-second probe bound is test containment, not a
product refusal SLA; timeout remains failure. The historical default-handler
constructor timeout is unresolved and its latency is not qualified by this proof.

The trusted Python operator API performs the complete sequence:

```python
from taskalong.store import Store

# All paths are operator-selected private local locations. Backup and restore
# must be new, separate directories outside the original control directory.
with Store.maintenance(state_path) as maintenance:
    receipt = maintenance.upgrade(
        operation_key="history-upgrade-1",
        backup_dir=backup_path,
        restore_dir=restore_verification_path,
    )
```

The durable intent binds the operation key to store identity, target version and
both target paths. A complete control backup and verified fresh restore precede
DDL. OS aliases and case variations cannot make an existing control directory
count as a separate backup or restore destination. Original application-table
rows/digests, blob references, retained captures,
instruction files and required control metadata are included privately. SQLite's
backup captures committed WAL data; copying only state.sqlite3 is insufficient.
SQLite WAL/SHM/rollback journals and empty coordination lock files are omitted
explicitly because the snapshot replaces the journals and OS locks cannot be
restored from bytes. External worktrees/repositories, executables, remote effects
and referenced files outside the control directory require separate preservation
and reconciliation. This is a complete control-state backup, not an environment
or project backup.

Files/directories retain their private modes. Symlinks, hard links, special files,
insecure existing paths, missing/tampered registered or core-evidence blobs and
inconsistent manifests refuse the operation. Existing permissions are never
silently repaired. New attempt containers are created privately; an older store
with shared-mode nested control paths needs explicit operator reconciliation.
Inventories are bounded to 10,000 entries, 64 directory levels, 512 MiB total
payload and the existing bounded JSON manifest size. Exceeding a bound refuses
without deleting partial artifacts.

Migration SQL 002 adds immutable history and atomically commits both schema
markers and its receipt. Matching retries return the committed receipt or verify
and reuse complete pre-migration artifacts. Changed paths/inputs under the same
key conflict. ENOSPC, interrupted copying or incomplete artifacts keep the prior
format and retained failure data; inspect and reconcile rather than overwriting
their destinations. A later source change makes the old backup stale.

For a complete backup without upgrading, use `maintenance.backup(new_path,
complete=True)` inside the same maintenance context. The original
`Store.backup(new_sqlite_path)` API remains a SQLite-only snapshot and is not a
complete control backup or redacted export.

`taskalong.maintenance.verify_backup(path, expected_digest=trusted_digest)` checks
the complete manifest and payload. `restore_backup(path, new_directory,
expected_digest=trusted_digest)` restores only to a fresh directory. The expected
digest must come from the trusted operator's retained receipt, not a worker claim.
Hashes establish identity, not authenticity. Restores are deliberately tagged
`taskalong.restore-quarantine`; current and predecessor clients both refuse them.
The restore is built and verified in a private sibling staging directory with a
canonical quarantine database committed before any payload is copied. Atomic
no-replace directory publication exposes only the complete quarantine at the
selected destination. Unsupported platform/filesystem primitives refuse this
step; a racing existing directory is never replaced, even when empty. Failures
retain private stages for inspection. There is no automatic promotion, in-place
rollback or restore over later effects.
Preserve the original store and reconcile external state before any future
forward-repair procedure. Backups contain private unredacted data: do not put them
in source control, public issues or distribution artifacts.

After upgrade, `Store.record_document(typed_document, operation_key=...)` appends
validated immutable RuntimeProfile, HarnessInstallation, ProviderProfile,
ExecutionBinding or QualificationDecision bytes. `Store.document_history(kind,
identity)` returns frozen records and refuses histories larger than 1,000 entries
instead of returning a partial result. Provider/installation identity uses its
declared ID, bindings use their digest, and decisions use `binding_digest:mode`.
No implicit latest/current selection is provided. Storing or reading a decision
does not grant execution, publication or current qualification authority.

## V2 execution store boundary

Executable 2.2 tasks require store format 3, which deliberately excludes older
clients that cannot enforce v2 restrictions. Ordinary opening, inspection and v1
operation never upgrade a store. After closing all clients and proving quiescence,
use the same complete-backup and quarantined-restore boundary for each numbered
migration. From a format-2 store:

```python
from taskalong.store import Store

with Store.maintenance(state_dir) as store:
    receipt = store.upgrade(
        operation_key="explicit-format3-upgrade",
        backup_dir=new_private_backup_directory,
        restore_dir=new_quarantined_restore_directory,
        target_version=3,
    )
```

A format-1 store must first explicitly complete its existing format-2 migration
with separate backup/restore paths and operation key. SQL001/002, their receipts
and legacy canonical state remain intact. SQL003 adds immutable execution
projection registrations and advances both format markers in one transaction.
Same-key/same-input replay returns its retained receipt; changed inputs conflict.
Failures preserve the source, prior state and private backup/restore evidence.
No downgrade, rollback over later effects or restore promotion is implemented.

After upgrade, trusted local execution configuration stores exact policy history
and an immutable fixture projection. Explicit trust/receipt updates remain
operator settings and are re-evaluated before dispatch; historical decisions never
become current authority. Registering a portable document, opening a store or
reading a result cannot select a model, start inference or enable production.
The [contracts guide](contracts.md#single-step-execution-v22) describes the current
synthetic-only subset and refusal boundaries.

## Claude fixture store boundary

Executable 2.3 tasks and DriverConfig history require format 4. Under the same
exclusive, quiescent maintenance procedure, upgrade an already format-3 store
with `store.upgrade(operation_key=..., backup_dir=..., restore_dir=...,
target_version=4)`. Use distinct private backup and fresh restore directories.
Skipping a numbered version refuses before backup/mutation. The pinned format-3
client refuses format 4; use a verified prior backup in a fresh directory for
rollback rather than editing markers. Existing runs/history remain intact.

Select `claude-print-fixture/1` explicitly through `configure_execution` with a
2.3 DriverConfig and exact 2.0 installation/provider/binding plus policies and
trusted synthetic evidence. This is a developer fixture, not a vendor launcher
setup guide. Schema validity or installed Claude help cannot admit real execution.
Production, native continuation, Ollama and hard cost/token enforcement refuse.
Explicit restart has a new session and consumes the existing run budget. Unknown
cessation/effects require inspection and reconciliation, never automatic retry.

## Ollama fixture store boundary

The distinct `claude-ollama-fixture/1` projection requires 2.4 task/config
documents and installation `synthetic-claude-ollama-1`. Under the same exclusive,
quiescent maintenance procedure, an already format-4 store can explicitly use
`target_version=5`, with distinct private backup and fresh restore directories.
SQL005 changes no existing tables; both format markers and its numbered receipt
advance together after complete backup and restore verification. A byte-pinned
format-4 client refuses format 5. Preserve verified prior backups for recovery;
never edit markers or restore over current data.

This is an offline developer fixture through the same Claude driver. Select the
exact local or direct-cloud ProviderProfile and approved start **and** lookup
evidence. Capability inspection reflects both gates and creates no authority.
The responder sends no server request. No Ollama install, login, model pull,
shared-server lifecycle, real credentials or live provider execution is enabled.
See the [2.4 contract](contracts.md#ollama-fixture-contracts-v24).

## Cursor fixture store and capture boundary

The 2.5 `cursor-print-fixture/1` tuple requires explicit format5-to-6 maintenance
through the same quiescent full-backup/restore API. Preserve SQL001–005 and
immutable history. The pinned format5 predecessor must refuse format6 before
journal mutation. Never advance markers manually or restore over current data.

Configure only the original operator-registered Cursor fixture, exact immutable
installation/provider/policies and current approved start evidence. Its account
reference is synthetic and never dereferenced. Fresh sessions are observed after
start, not chosen from task input; native resume/latest/create-chat refuse.
Stopped restart allocates a new attempt/session under the persisted budget.

Exact stdout/stderr are private unredacted blobs. Completion requires core
re-decode and association validation against the frozen packet and actual owned
process accounting; missing/corrupt bytes refuse result/verification and dependent
recovery/publication. Private complete backups contain these captures. Public
result, events and exports omit raw capture/session/model content. A crash before
durable finish leaves uncertainty and quarantine, even if a valid stream exists.
Do not retry by looking up a vendor chat. See the [Cursor contract](contracts.md#cursor-fixture-contracts-v25).

## Antigravity fixture store and conversation boundary

The 2.6 `antigravity-headless-fixture/1` tuple requires sequential format6-to-7
maintenance under the same exclusive, quiescent complete-backup/restore API.
Use `target_version=7` only from format6, with separate private backup and fresh
restore directories. SQL007 adds no table; prior schemas, receipts, rows and
blobs stay intact. The byte-pinned format6 predecessor refuses format7 before
journal mutation. Never edit markers or restore over current state.

Register only the explicit original fixture and exact current identities/policies
and synthetic start evidence. Its account reference is never resolved. One framed
user input plus EOF is supplied to the owned runner; the canonical packet remains
unchanged. A fresh conversation is observed, not preselected. Private captures
include intended stdin and actual stdout/stderr. A stopped completed handoff is
redecoded before dependent reads or recovery; a closed gate does not prove stdin
was delivered. Restart uses a new conversation and the same persisted budget.
Native continuation, provider lookup, remote cessation, live execution and hard
caps refuse. See the [Antigravity contract](contracts.md#antigravity-fixture-contracts-v26).

## Private host experiment evidence

Run the [model-free qualifier](qualification.md#model-free-host-experiments-and-offline-replay)
only with the explicit closed profile and a new owner-only directory outside the
checkout. It does not open a Store or modify registered profiles. Preserve raw
blobs, `manifest.json`, failed receipts and any quarantined state. Files use 0600
and directories 0700; do not publish original captures, environment/host paths or
canary content. A separately reviewed public report should contain allowlisted
commands, hashes, counts, scope and unsupported capabilities only.

Offline installed replay reserves a separate new output directory and leaves
its original input unchanged. `replay-report.json` refers to that immutable
original and to a distinct verifier inventory; retain both. Integrity-valid
replay of failed/unknown execution remains unsuccessful. Neither replay nor a
complete host-canary campaign supplies trusted approvals, clears quarantine,
changes revocations or enables production. No automatic replay/recovery or
cleanup using saved process IDs is performed. Evidence-write or close failure
returns a safe non-durable result; the first cleanup uncertainty remains recorded
when a secondary write also fails.

Keep controller UID observations in the private inventory only. Do not copy UID
values, usernames or raw host metadata into public summaries. The experiment
inherits its caller identity and performs no elevation or identity switch.
Neither zero nor nonzero classification establishes a privileged execution or
confinement capability. A changed controller identity stops subsequent owned
launches/completion; it does not rewrite earlier process or cleanup evidence.
# Offline E1 preparation and format 8

The explicit format 8 / SQL008 migration uses the same quiescent maintenance,
complete private backup and quarantined restore process described below. Apply
every preceding numbered migration first and pass `target_version=8` explicitly.
Opening a store never upgrades it. The retained format 7 client rejects the new
format before journal mutation. Preserve the complete backup for recovery;
lowering metadata/version integers is unsupported.

`RunService.register_trial_document(document, operation_key=...)` records one
exact immutable 2.8 document as historical data on format 8. It cannot install
a launcher, issue an authorization or make an activation-shaped record current
authority. Worker-result lacks a document-history digest and is retained through
the existing attempt/blob seam when an independently qualified route exists.
All current 2.8 operational submissions and stored-run operations return
`trial_runtime_unqualified`. No real worker or reviewer is launched.

The existing synthetic service already exposes the completed worker handoff
through `inspect()`/`result()` before `verify()`. The recovery regression stops
the actual controller at that pre-verification boundary, observes cessation,
and uses a fresh controller's first explicit `verify()` call. It preserves
workspace ownership, worker result/captures, completed attempt/effect identities
and consumed budget; new verification output remains charged. It does not
resume an interrupted verification claim or repeat the worker. Pending effects,
unknown worker cessation or changed subjects still refuse. No new stop/restart
API, scheduler or native-session continuation is introduced.

## Production Muse intent (v2.11, execution blocked)

The additive v2.11 profile, task and driver-configuration contracts describe a
future production Muse route. They do not install or qualify a driver. V1 Codex
and v2.9 synthetic Muse retain their existing contracts. SOL can orchestrate the
public commands below; Muse coding remains unavailable in this slice.

Use `register-profile --profile profile.json` with a v2.11 `runtime_profile`:
start from the v1 profile fields, set `schema_version` to `2.11`, `adapter` to
`muse`, `qualification` to `production`, `runtime_version` to
`1.4.10-R6427.1`, `model` to `wonder-full`, `reasoning_effort` to `high`, and
`qualification_receipt_ids` to `[]`. Bind a direct, absolute executable path and
its SHA-256. Symlink paths, missing/nonexecutable files and changed bytes refuse.
No help command, updater, login or provider is executed during registration.
The build/model/effort remain requested identity, not runtime observation.

`permission_policy` has exactly `permission_profile` (the intended named Muse
profile), `policy_sha256`, `instructions_sha256` and `tools_sha256`. The last
three are SHA-256 identities for reviewed local policy/instruction/tool inputs;
registration does not discover or load skills, plugins or tools, expose source,
or establish effective containment. Set `permission_policy_digest` to the
canonical JSON digest of that object. Other v1 profile fields remain required.
Use `taskalong.validation.seal_versioned(..., version="2.11")` to normalize and
seal documents; use the installed schemas for the complete required vocabulary.

Register a `driver_config` with `configure-muse --config configuration.json`.
Its fields are `kind`, `schema_version`, `digest`, `profile_id`, `profile_digest`,
`permission_policy_path` (absolute direct regular file) and
`permission_policy_sha256`. It binds the exact registered profile and local
policy bytes. Configuration documents are content addressed. A changed profile
needs a new profile ID; changed configuration needs its newly sealed digest.
Never put credentials in these documents.

```sh
taskalong --state-dir "$STATE" --json register-profile --profile profile.json
taskalong --state-dir "$STATE" --json configure-muse --config configuration.json
taskalong --state-dir "$STATE" --json muse-readiness --profile-id muse-wonder-high --configuration-digest "$CONFIG_DIGEST"
taskalong --state-dir "$STATE" --json validate --spec task.json
taskalong --state-dir "$STATE" --json submit --spec task.json --key muse-intent-1
```

A v2.11 task retains the v1 goal, scope, criteria, independent checks, registered
repository/base, review and permission fields. Its execution adapter is `muse`
and adds `configuration_digest` alongside `profile_id` and `profile_digest`.
Qualification is production, publication is null, and effects are limited to
execute/verify/commit_candidate. Budgets allow one attempt, at most 60 active
seconds and 1 MiB output, with `max_model_steps: 1`. Hard cost/token requests are
intent only and cannot be enforced by this slice. No run is created.

`muse-readiness` exits zero when the registered identities match, with
`production_dispatch_allowed: false` and `acceptance_allowed: false`. This is a
successful observation of blocked readiness. `validate` exits zero for a valid,
bound intent and embeds that readiness report. `submit` exits 3 with
`muse_runtime_unqualified`, `not_sent`, before allocating a run, worktree,
authority, lease or attempt. Unknown/malformed documents exit 2. Stale executable
or policy identities exit 3. No run ID exists for start/status/recovery commands.

The proposed closed argv projection fixes `wonder-full`, `--reasoning-effort
high`, one model step, untrusted approval, proxy-only network and disabled
request-user-input. It is pure data, not a launcher. Model steps do not bound
judge, observer or subagent inference. Hash matching does not qualify executable
closure, account/model routing, effective policy or process lifetime.

Production intent is stored under separate immutable `muse-production-*`
settings. The database remains format 11; no migration or new legacy history
rows are required. Existing store migration tests remain applicable. Older
readers ignore the new settings and reject v2.11 rather than treat it as v1 or a
synthetic execution. No production registration enters the legacy profiles table.

Remaining gates are effective instruction/tool/source isolation, actual runtime
model/effort evidence, bounded inference, owned process/descendant cessation,
durable worker output and interrupted-run recovery, and real independent review.
On macOS the existing native-fork limitation and experimental foreground unknown
cessation remain blockers. Local control tests are not Muse qualification. A
separately authorized TaskAlong-owned real canary must precede the protected
RED-to-GREEN defect journey. Track these under existing issues 12 and 30.


## Production Muse preparation

After registering the v2.11 intent above, select reviewed local instruction and
tool files and any declared dependencies in a bounded JSON input document:

```json
{
  "instructions_path": "/reviewed/inputs/instructions.txt",
  "tools_path": "/reviewed/inputs/tools.json",
  "dependency_paths": []
}
```

The paths must be canonical absolute direct files. The instruction/tool hashes
must match the profile; preparation never discovers effective Muse inputs.
Do not put credentials or credential paths in this document.

```sh
taskalong --state-dir "$STATE" --json prepare-muse --spec task.json --inputs inputs.json
taskalong --state-dir "$STATE" --json muse-preparation "$PREPARATION_DIGEST"
```

The first command returns `preparation_digest`; use that exact digest for the
second command. Both exit zero only for matching measured inputs and return
`production_dispatch_allowed: false` and `acceptance_allowed: false`. No Muse,
updater, account or provider command runs. Read-only local Git inspection does
run to bind the clean registered repository and full immutable base tree.
The argv template uses symbolic prospective workspace/prompt bindings; no prompt
or executable attempt exists. The declared file list is not complete runtime
closure, and requested budgets are not enforcement of total inference usage.

A stale retained assessment exits 3 with `muse_preparation_stale`; changed bound
executable/policy/instruction/tool bytes have their specific changed-identity
codes. Unsafe/missing/oversized inputs, corrupt records and unknown digests also
refuse before dispatch. No retained record is silently rewritten. Preserve the
original, review changed inputs and prepare a distinct subject. A clean move of
HEAD alone does not change a preparation pinned to an earlier existing base.
The [contract](contracts.md#production-muse-preparation) lists measurement bounds.
These preparation commands create no executable attempt. The separate
[production lifecycle](#production-muse-lifecycle-configuration) implements
packet, capture, completion and recovery contracts behind a closed runtime gate.


## Production Muse lifecycle configuration

`RunService.configure_muse_driver(document)` and
`configure-muse-driver --config FILE` register a 2.12 production configuration only
after explicit backed-up format 12 maintenance. It binds the existing 2.11 profile
and intent configuration, direct measured instruction/tool/dependency inputs,
check/sandbox/review identities and an explicit non-fixture `review_provider`.
Registration returns its immutable digest; no runtime authority is created.
Use the installed2.12 driver/task schemas for the exact closed vocabulary.

`validate --spec FILE` returns the exact runtime subject identity and current false
readiness. `submit` refuses `muse_runtime_unqualified`/`not_sent` before creating a
run/attempt/effect/workspace. Even an imported run rechecks the gate at start and
inside the closed owned spawn boundary. No setting or caller-supplied receipt can
open it. Native resume and automatic retries are unsupported.

The blockers are concrete: the pinned 1.4.10 contract lacks a supported aggregate
observer/judge/subagent bound; the Darwin owner cannot prove complete native-fork
cessation; requested CLI flags and local hashes do not establish OS containment
or authenticated account/allowance and independent-checker facts. Select a runtime
host/build that supports those boundaries before qualification. No new credentials,
access, terms, security settings or broader live canary are implied by these APIs.

## Muse local shutdown and retained exposure

Store13 adds a backed-up append-only local exposure ledger for production2.12.
The read-only `muse-exposure` command separates local cessation from unknown
remote usage and cannot authorize dispatch or settlement. A possible release
holds later Muse attempts across destination aliases within that Store. This is
not an account-wide spending cap. No absolute vendor cessation promise is
required; actual whole-process containment and account/checker observations are
still missing here. See the [execution plan](muse-shutdown.md) for exact controls,
qualification limits and the Linux host/security action awaiting approval.
