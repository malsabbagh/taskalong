# Experimental alpha contracts

The original provisional contracts use schema version `1.0`; the package/API version is
`0.1.0a1`/`1.0`. Implemented contracts do not establish supported live execution;
see [qualification](qualification.md).

## Claude fixture contracts v2.3

The explicit 2.3 family contains `driver-config`, `task-spec`, `worker-packet`,
`packet-projection` and `worker-result`. Earlier schema resources and readers
retain their exact bytes and meanings. `read_task_spec` selects the declared
version; no version or adapter is inferred. A 2.3 task names
`execution.binding_digest` and `execution.driver_config_digest`; it never puts a
DriverConfig digest in a legacy RuntimeProfile field. The separately retained
2.0 ProviderProfile supplies the exact simulated model/provider/auth identities.
The five schemas are available with `schema(name, version="2.3")`.

The trusted `configure_execution` API accepts `driver_config=...` instead of
`runtime_profile_digest` for the explicit `claude-print-fixture/1` projection.
It requires a format-4 store and the same exact installation, binding, policies,
trusted receipts, evidence and context as 2.2 admission. The effective-context
digest binds `{policies: <documents sorted by digest>, driver_config_digest: ...}`.
It admits only installation `synthetic-claude-1`, empty additional instructions,
semantic tool `claude.edit`, the synthetic worker/check backends and no hard
cost/token cap. Provider metadata describes a simulation, never actual routing.
Configuration registration does not authorize a task or enable production.

The owned supervisor emits one canonical 2.3 packet, the identical stdin wire
packet and a mapping binding configuration/provider/admission/session identities.
The session UUID equals the new attempt UUID. Decoder results bind all those
identities; terminal reports are untrusted. Complete owned cessation precedes
candidate freezing and independent verification with a separate genuine v1
check profile. Existing 2.2 result/capabilities envelopes also describe 2.3 tasks
without exposing private paths, policy bodies or credential data.

Native resume refuses. Explicit restart creates a new attempt/session, keeps
worktree fencing and consumes the persisted budget; reported token/cost counters
remain unknown totals. No fallback, public registry release or real vendor
execution is enabled. See the [driver ADR](adr/0005-claude-fixture-driver.md) and
[wire component](claude-protocol.md) for exact limits.

## Single-step execution v2.2

Explicit version `2.2` adds TaskSpecV2, WorkerPacketV2, ExecutionEvidence,
InstructionBundle, ToolPolicy, SandboxPolicy and CheckBinding through
`taskalong.execution`. It also adds closed packet-projection, result-view and
capabilities-view schemas. Use `schema(name, version="2.2")`,
`seal_versioned(name, data, version="2.2")` and `read_task_spec(data)` explicitly.
The v1 reader remains unchanged; reading a saved v1 task preserves its canonical
bytes/digest. The exact 2.0 and 2.1 resource sets and semantics remain unchanged.

A v2 TaskSpec selects `execution.binding_digest`. Its worker and verifier policies
are separate exact immutable references. PolicyResolver accepts only a bounded
operator-selected tuple of typed documents and resolves exact digest plus type.
It does no filesystem/network discovery and grants no authority. Instruction
content and configured runtime paths stay private. A valid schema or self-hash
does not establish effective enforcement, trusted qualification or a launch route.

`RunService.configure_execution(...)` is a trusted operating-system control-plane
API, separate from task submission. It requires explicit installation, provider,
binding, policy, exact runtime-profile digest, context, receipts, approved trust
and evidence bytes. Its 2.2 projection is `codex-v1-fixture/1`: an
explicitly registered synthetic executable and independent fixture verifier
launcher. Empty additional instructions, exactly `fixture.edit`, denied discovery
and the `synthetic-fixture` sandbox backend are its closed policy subset. Legacy
permission objects and extra toolchain roots must be empty; additional constraints
cannot be silently discarded by this projection. These
are simulation inputs, with no claim of actual Codex or OS policy enforcement.
The effective-context digest is SHA-256 of the canonical array of policy documents
sorted by their content digests. Other context identities remain explicit inputs
to the fixture measurement, never proof of this release's runtime qualification.
Requested provider/model/auth identities remain recorded as simulated route
inputs; actual transport is the registered local fixture. Arbitrary policies,
unknown drivers, unresolved documents, non-null cost/token limits and unsupported
native resume are typed refusals. Nothing selects a fallback transport or model.

V2 executable state requires an explicit format-3 store upgrade. Admission
re-evaluates current trusted approvals, expiry/revocation, exact required mode,
profile identity and budgets. A start receipt cannot satisfy a binding requiring
native resume. Preparation atomically retains authority/policy/binding/decision
snapshots, lease, reservation, event and intent. Dispatch and the owned pre-exec
gate revalidate current mutable facts. An interruption after dispatch can leave
unknown effects; the workspace stays quarantined until explicitly reconciled.

The canonical packet binds the 2.2 task and admission. The explicitly projected
v1 wire packet and final mapping bind both packet identities to one attempt.
Legacy worker output must match those exact wire inputs. Independent check
records retain the existing acceptance interpreter and immutable 2.2 evidence
projections. Worker completion does not grant independent acceptance.

`RunService.capabilities(run_id, mode="start")` and `result(run_id)` return 2.2
dictionary envelopes without preparing work, reconciling state or issuing
authority. V1 `inspect`, other dictionary returns, CLI verbs and exit meanings
remain available. V2 start/restart returns its original prepared operation receipt
on both first call and replay; call `inspect` for the latest run revision.
Capabilities reports scoped fixture satisfaction separately from production
dispatch, which is always false. Result distinguishes pending, unknown, completed
worker and independent acceptance, and exposes immutable artifact identities
without policy bodies, configured paths, authority records or raw output. These
views do not authorize execution or publication.

See the [admission ADR](adr/0004-single-step-execution-admission.md) and
[maintenance operations](operations.md#v2-execution-store-boundary).

Persistent stores belong to the `taskalong` application namespace. New stores
record that marker; existing untagged or foreign stores fail before journal-mode
configuration. No automatic cross-application migration is provided.

The importable facade is `taskalong.api.RunService`. Orchestrators call this facade
rather than importing the runtime adapter or interpreting provider output. The
CLI calls that same boundary. `python -m taskalong` and the console script have the
same semantics. Help and version require no state, repository or network access.
Read-only status and events never launch or reconcile a run implicitly.
Repository/profile registration, `configure_review`, `configure_command_sandbox`,
`configure_publication`, and `authorize` are additional trusted control-plane
methods. Their CLI counterparts operate as the current OS user. Task documents
and worker output cannot invoke them or admit their own authority. Authority
records identify that OS principal and retain `human_decision_observed=false`;
no human approval is inferred from an identity string.

Version `1.0` contains exactly these twelve offline Draft 2020-12 schemas:
`task-spec`, `task-run`, `run-event`, `worker-packet`, `worker-result`,
`execution-observation`, `evidence`, `acceptance`, `authority`, `effect-intent`,
`command-result`, and `runtime-profile`. Their IDs are
`urn:taskalong:schema:v1:<name>`. Unknown root/nested contract fields and unsupported
versions fail. Explicit metadata mappings (`extensions`, event payloads, private
profile policy, summary records) are bounded and grant no authority. Extensions
use namespaced keys. There is no remote schema resolution.

The JSON boundary rejects duplicate keys, invalid UTF-8, floats/non-finite
numbers, excessive nesting and inputs over 1 MiB. Integers stay within the
interoperable 53-bit JSON range. Schema integer fields reject booleans. Goals and
non-goals together are limited to 16 KiB. Literal POSIX scope rejects traversal,
absolute paths, globs, symlinks, Git/control/agent configuration and credentials.
The core separately checks actual file bytes, mode and scope before acceptance.
Required checks use argv and expected exit zero; shell strings are unsupported.

Canonical bytes are validated normalized UTF-8 JSON with sorted object keys,
compact separators, `ensure_ascii=False`, no implicit Unicode normalization and
no floating point. SHA-256 excludes only the root's own `digest` field. Set-like
scope, effect, criterion and evidence lists are sorted/deduplicated at admission;
semantic arrays such as argv retain order. A changed semantic input changes the
digest. IDs and human-readable names grant no authority.

Frozen document types in `taskalong.contracts` store canonical bytes. `from_dict`
validates; `to_dict` returns an independent copy. Runtime protocol records live
in `taskalong.executors.base`; they carry no acceptance or publishing capability.
The protocol names provider-neutral start/status/cancel/resume operations, while
this first adapter requires `RunService` to own their durable lifecycle.
`CodexCLI.start` and `.resume` return the unsupported `supervisor_required`
observation. Its internal `.run` primitive is called only by the owned per-run
supervisor after attempt/effect preparation. Direct adapter method presence is
not standalone execution support; callers use `RunService` for execution,
reconciliation, lookup and cancellation.
Worker output is untrusted, including fields claiming commands passed or a person
approved them. Only an actual independent owned invocation can produce trusted
command/review evidence. A missing reviewer, partial coverage or stale subject
blocks acceptance.

Mutations accept operation keys and expected run revisions. A repeated key with
the same semantic request returns its prior receipt before checking optimistic
revision. A repeated key with different semantics conflicts. State changes and
consecutive events commit atomically; sequence establishes ordering. Read-only
portable summaries omit private runtime thread IDs and absolute control paths.
Exports omit raw prompts, source, results, credentials and logs by default.

The lifecycle is `created → ready → running → verifying → accepted → publishing
→ draft_published`, with typed blocked/failure/cancellation states. A worker
completion starts verification. Only exact current independent evidence can
produce acceptance; publication needs additional exact intent authority.
Terminal cancellation/failure cannot be silently resumed. Unknown spawn,
cancellation or remote effects require reconciliation rather than duplicate
execution. Native resume names an observed session and never means latest-session
or restart. Unsupported native resume cannot silently fall back to another mode.

Cancellation confirmation is selected from the state observed inside the
completion transaction, including a request made after the worker returns.
Stale blockers cannot reopen terminal cancellation. A cancellation before any
dispatch can be reconciled without launching a worker; unresolved invocation
effects still prevent confirmation. Native resume rejects a different returned
session identity. Reported input/output token usage accumulates across attempts;
an unknown component or integer overflow leaves the corresponding total unknown.
Provider cost remains unknown.

Explicit `retire-workspace` / `RunService.retire_workspace` releases a quiescent
terminal or accepted run's repository reservation after cessation and effect
checks. It preserves retained data, records `workspace.retired` and revokes the
old fence. A new task receives a distinct workspace and increasing generation;
retired runs cannot regain mutation authority. See [operations](operations.md).

Candidate effect intents journal bounded file metadata rather than base64 source
bytes. Existing inline-content intents remain readable and content-checked;
current source limits remain one MiB per file and eight MiB per candidate.

Production profiles always fail preflight with `runtime_policy_unsupported`.
The missing qualification covers effective exec config/instruction/tool discovery
and the complete no-daemon worker lifetime. Profile qualification receipt IDs
are not proof and cannot turn this gate on. Synthetic fixtures remain explicitly
synthetic throughout the lifecycle; no live executor support is claimed.

For worker/check cessation, Darwin's `darwin-kqueue-no-fork` backend treats every
observed fork as unaccounted descendants and blocks advancement. Linux's
`linux-child-subreaper` backend uses an isolated non-dumpable wrapper and private
status pipe to report root termination and kernel child reaping. Linux generic
process-backend qualification awaits actual matching CI and installed tests.
Even passing those tests does not qualify a real CLI: production also requires
separate effective instruction/tool and complete owned-runtime proof. An expired
heartbeat, process-list snapshot, closed pipe or delivered signal cannot replace
that receipt. Git publication transport may use verified process-group exit
plus exact remote read-back; this does not grant worker/check quiescence.

The implementation is original; no source from unrelated projects is imported.
The source import allowlist is empty. The tested dependency floor is
`jsonschema>=4.26,<5`, with exact qualification versions/hashes in the lockfile;
Python/platform support still requires recorded environment-specific evidence.

JSON CLI results have one `command_result` envelope; events JSONL is the explicit
exception. `ok` describes the command, not task acceptance. Exit codes are:

| Exit | Meaning |
| --- | --- |
| 0 | Command fulfilled; task may still be blocked in a read-only observation. |
| 1 | Known execution or verification failure. |
| 2 | CLI, schema or input validation error. |
| 3 | Blocked prerequisite, missing authority/review, unsupported capability. |
| 4 | Revision, key or lease conflict. |
| 5 | Unknown effect; reconciliation required. |
| 6 | Pending after bounded wait. |
| 70 | Internal/store integrity error; preserve state. |
| 130 | Foreground client interrupted; does not imply worker cancellation. |

No live task-to-verified-draft-PR, exactly-once remote effect, hard provider cost
cap, arbitrary-runtime compatibility, public license or release claim follows
from these contracts.

## Offline semantic documents v2

`taskalong.bindings.HarnessInstallation`, `ProviderProfile` and `ExecutionBinding`
are frozen canonical documents using schema version `2.0`. Their three schemas
have IDs `urn:taskalong:schema:v2:<name>`. They are descriptive data only: no
registration, trusted resolution, DB migration, task v2, driver selection or
production admission is implemented here. Existing v1 APIs, canonical bytes,
digests and schema resources keep their original behavior.

```python
from importlib import resources
from taskalong.bindings import HarnessInstallation
from taskalong.validation import schema, schema_names, validate_versioned

assert len(schema_names()) == 12  # Existing default remains v1.
assert len(schema_names(version="2.0")) == 3
resource = resources.files("taskalong.resources").joinpath(
    "examples", "v2", "harness-installation.json")
installation = HarnessInstallation(resource.read_bytes())
document = validate_versioned("harness-installation", installation.to_dict(),
                              expected_version="2.0")
assert schema("harness-installation", version="2.0")["additionalProperties"] is False
```

The installed `examples/v2/` directory also contains `provider-profile.json` and
`execution-binding.json`. Each example is complete, sealed and synthetic. The
binding links the other two example digests. Its policy/check references and
runtime/model digests are synthetic declarations, not existing approved objects
or evidence. They cannot admit a launch. The provider example names loopback but
does not connect to it or claim any server/model is installed.

`seal_versioned(name, data, version="2.0")` supplies kind/version and seals strict
JSON. `validate_versioned(..., expected_version=...)` requires the caller's
selected format; it never guesses from input. Version `1.0` uses the existing
validator/sealer unchanged. Schema enumeration and registries are explicitly
version-scoped, installed and offline. Frozen `from_dict` and byte constructors
validate, `to_dict` returns an independent copy, and `to_bytes` returns canonical
bytes. Unknown fields/versions, malformed digests, duplicate keys, non-integer
numbers, overflow and recognizable credentials are rejected. Sensitive-input
screening is a secondary check, not arbitrary secret detection.

Installation identity includes harness, adapter/driver and CLI versions, exact
platform/backend, executable digest and a separate dependency-closure digest.
Paths and arbitrary argv/imports are absent. Unknown adapter IDs can be stored as
design data but are unavailable to the unchanged closed registry. A declared
closure hash does not prove that the complete executable closure was captured.

Provider profiles have closed harness/provider/auth variants for Codex account,
Claude account/API, separate Claude/Ollama local and cloud destinations, Cursor
account and Antigravity account. Model requested identity and resolved digest,
endpoint, credential reference, effort/tier and auxiliary profile references are
explicit semantic inputs. Account/API references are nonsecret identifiers, never
secret values or credential file paths. Local Ollama requires an HTTP(S) literal
loopback endpoint and local-no-secret auth; other variants require HTTPS and an
explicit credential/account reference. Userinfo, query/fragment, invalid ports
and control characters are refused. Endpoint validation performs no DNS lookup.
Loopback does not prove local computation, effective egress or routing. A model
digest is a declaration requiring later trusted evidence, not alias resolution.
Unlisted auxiliary routes and fallback are forbidden. Supported data variants
and option names make no claim that a corresponding installed CLI accepts them.

Bindings reference installation/provider, instruction/tool policy, worker sandbox
and independent check-binding digests. Complete policy records and trusted
resolvers belong to a later milestone. No qualification receipt field exists;
receipt rotation therefore cannot change binding identity. Capabilities form a
nonempty unique set sorted before hashing. Auxiliary routes retain declared
order. Budgets use integer seconds/tokens/micro-USD; null is unspecified, not zero
usage or spending authority. A required hard cap needs a numeric limit and its
required capability; declaring it still proves no enforcement.

Native resume is null unless explicitly required. Its protocol version,
`exact_stored_session` scope and compatibility digest bind every semantic binding
input (including policies, independent check binding, required capabilities and
budgets). `native_resume_compatibility_digest` computes this identity excluding
only the two digest fields themselves. Use the complete kind/version-bearing
document as input. Altering any compatibility subject requires a new digest.
No session is transferred or resumed by these records; later admission must also
verify the exact stored session, evidence and fresh authority.

Future milestones must preserve these shipped v2 bytes/meanings or introduce an
explicit new schema version/discriminant. Neither v1 nor v2 authority may be
silently reinterpreted. Production refusal remains in force.

## Offline qualification v2.1

`taskalong.qualification` adds frozen `QualificationReceipt`,
`QualificationDecision` and `CapabilityReport` records. Read them with explicit
version `2.1`; its schema IDs use `urn:taskalong:schema:v2.1:<name>`. Existing
v1 defaults and M1's exact v2.0 enumeration, schemas and canonical examples remain
unchanged. Shared subject, observation, evidence-reference and trust-policy
shapes are embedded in the receipt schema and resolve only in the offline 2.1
registry. These records do not register profiles or change runtime admission.

`evaluate` takes M1 binding/installation/provider records, explicit context and
operation mode, receipts, a `TrustPolicy`, an immutable `EvidenceStore`, explicit
UTC evaluation time and a minimum evidence level. The default minimum is
`actual_provider`; fixture and controlled-responder evidence cannot satisfy it.
No callback resolver, filesystem search, network connection, clock lookup,
credential discovery, process, persistence or launch is performed. Installed
schema resources are read-only package constants. Evidence snapshots are bounded
to 128 blobs, one MiB each and 16 MiB total; receipts are bounded to 64 per call.
Strict JSON and output size limits still apply; excessive output fails closed.

Trusted policy is an external control-plane input. Its constructor validates
shape and digests, not origin or authorization. Applications must supply it from
authenticated operator-approved evidence; never construct approvals from worker,
profile, task or receipt claims. Producer-name matching alone is insufficient:
an exact receipt digest needs a current, unrevoked trusted approval. That approval
is sealed after the receipt exists, so receipts do not refer back to approvals.
Producer evidence-level restrictions and current receipt/approval/evidence
revocations are separately checked. The caller must supply trusted current time
and a current policy snapshot. This module implements no signer, key store or
approval acquisition.

Each receipt binds exact semantic binding/installation/provider, artifact,
runtime closure, host/backend, model, instruction/tool/worker/check policy,
effective context and test inputs. Native resume additionally binds exact session,
prior invocation and M1 compatibility identity. Mode is separate: start evidence
never implicitly grants observe, cancellation, result, resume, provider lookup or
remote cancellation. The decision requires every binding-required capability plus
the operation's mandatory capability, all under that exact mode. Native-resume
observations are eligible only in native-resume mode, where both session and
prior-invocation identities are mandatory. Requiring resume in a binding cannot
turn start-mode evidence into resume support. Missing evidence
stays unknown; explicit negative facts stay unsupported. Conflicting trusted
negative/unknown results cannot be overwritten by positive results. Untrusted or
invalid extra records are rejected and recorded without supplying votes.

Evidence references bind SHA-256, size, media type and public/private
classification. Approved typed observation manifests bind their producer,
subject/mode/level/capability, expected support and observed boolean/null facts.
They must link available, matching raw captures. False is unsupported; null is
unknown. A root exit without complete descendant proof cannot report local
cessation. Local proof does not imply provider acknowledgment, remote work stop
or final accounting. Hard token/cost guarantees need complete facts for every
route, enforcement before dispatch, overrun prevention and the exact declared
limit; cost additionally needs a known billing bound. Insufficient hard-cap proof
returns unsupported. These are checks of approved evidence declarations and
capture identity, not independent proof that a producer's claims are truthful.
Trusted capture/approval provenance and real runtime campaigns remain necessary.

The decision records the trusted policy digest, verified receipt digests,
rejected input indices/reason codes and scoped outcomes. A report links that
decision, retains receipt limitations and individual nullable usage, and never
invents aggregate token/cost totals. No raw capture bytes are copied into outputs.
Rotation creates a new decision while preserving binding identity and old bytes.
Both returned records always carry `production_dispatch_allowed=false`, including
a satisfied actual-provider-level input decision. Existing production preflight
is unchanged and cannot be enabled by any of these records.

The installed `examples/v2.1/` bundle is a complete generated offline example:
three sealed records, a narrow M1 binding fixture, an observation/capture and an
explicit fixture-only trust policy. Its synthetic digests/approval are not real
runtime evidence. This example trusts only those fixed generated inputs:

```python
import hashlib
from importlib import resources
from taskalong.bindings import ExecutionBinding, HarnessInstallation, ProviderProfile
from taskalong.qualification import EvidenceStore, QualificationReceipt, TrustPolicy, evaluate

root = resources.files("taskalong.resources")
example = root.joinpath("examples/v2.1")
binding = ExecutionBinding(example.joinpath("binding-fixture.json").read_bytes())
installation = HarnessInstallation(root.joinpath("examples/v2/harness-installation.json").read_bytes())
provider = ProviderProfile(root.joinpath("examples/v2/provider-profile.json").read_bytes())
receipt = QualificationReceipt(example.joinpath("qualification-receipt.json").read_bytes())
trust = TrustPolicy(example.joinpath("trust-policy.json").read_bytes())
blobs = {}
for name in ("evidence-observation.json", "capture.txt"):
    raw = example.joinpath(name).read_bytes()
    blobs[hashlib.sha256(raw).hexdigest()] = raw
context = {key: receipt.to_dict()["subject"][key] for key in (
    "artifact_digest", "host_digest", "effective_context_digest", "test_inputs_digest",
    "session_digest", "prior_invocation_digest")}
result = evaluate(binding, installation=installation, provider=provider,
    context=context, mode="start", receipts=[receipt], trust=trust,
    evidence=EvidenceStore.from_blobs(blobs), now="2026-10-22T12:00:00Z",
    minimum_level="offline_fixture")  # Explicit fixture scope only.
assert result.decision.to_dict()["requirements_satisfied"]
assert result.report.to_dict()["production_dispatch_allowed"] is False
```

The bundled binding remains a v2.0 document; the directory groups this example,
not a redefinition of M1. The supplied time is a fixture constant, not a current
approval. Real callers must use trusted current time and evidence. M3 persistence,
M4 admission, live adapters, effective-policy proof and runtime enablement are
separate milestones.
