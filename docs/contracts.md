# Experimental alpha contracts

These provisional contracts use schema version `1.0`; the package/API version is
`0.1.0a1`/`1.0`. Implemented contracts do not establish supported live execution;
see [qualification](qualification.md).

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

The package contains exactly these twelve offline Draft 2020-12 schemas:
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
