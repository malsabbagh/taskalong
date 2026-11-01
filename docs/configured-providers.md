# Configured experimental providers

Status: proposed.

TaskAlong implements a configured experimental route for `codex`, `antigravity`,
and `claude-code`. Claude Code has explicit `anthropic` and `ollama` backends.
Local operator configuration enables this route; there is no additional permanent
activation gate. The route produces proposals for human review and manual
application. Existing production admission and refusal rules remain unchanged.
These interfaces and native flags are experimental; this document does not claim
release qualification or native Anthropic live qualification.

The shared owner checks configuration and source identity, reserves a submission,
owns the local process, streams private capture, decodes observations, and validates
the proposed artifact. Adapters only project fixed invocations and decode their
native protocols. Codex continues through the existing `CodexCLI.run` handoff.
The implementation currently supports macOS and Linux for the shared route.

Codex runs in a fresh controller-owned Git workspace containing only the task's
declared read snapshots and existing writable-file snapshots. Newly declared
files remain absent. The snapshot has its own HEAD/tree, recorded separately
from the original source base; the source repository and its Git configuration
are unchanged. No `--skip-git-repo-check`, global trust setting, remotes, source
hooks or inherited Git configuration are added. The existing system Git is
fingerprinted, runs fixed local plumbing commands with filters/hooks disabled,
and has a 120-second aggregate setup budget with at most 15 seconds per command.
This bounds those subprocesses rather than imposing an OS disk or memory quota.

Preparation and verification precede the provider submission claim. A partial
or expired setup fails without a provider dispatch and is retained for inspection.
The selected-file, Git metadata and control-receipt identities are checked again
at the native gate. Files are private/read-only; these observations do not prove
isolation from another process running as the operator. Whether a particular
native Codex build accepts the resulting repository remains a live qualification
observation, not a bypass of native trust checks.

## Supported choices

| Provider | Adapter format | Backend | Context choices | Proposal formats |
| --- | --- | --- | --- | --- |
| `codex` | `codex-local/1` | Native client | `include`, partial `native-only` | `file-replacements/1`, `unified-diff/1` |
| `antigravity` | `antigravity-native/1` | Native client | `include` | `file-replacements/1`, `unified-diff/1` |
| `claude-code` | `claude-local/1` | `anthropic` or `ollama` | `include`, partial `native-only` | `file-replacements/1` |

Use `include` as the normal policy: preserve the client's existing account and
preconfigured native context. Codex and Antigravity configurations require the
context field explicitly; Claude configuration defaults it to `include`.
Full `exclude` is unsupported and fails explicitly. `native-only`, where available,
requests partial reduction using native options; managed policy and other native
context may remain. It is not a context-isolation guarantee. Antigravity currently
refuses `native-only` as well.

Codex requests read-only sandboxing and noninteractive approval behavior;
Antigravity requests its native sandbox; Claude requests an empty tool inventory,
noninteractive permissions, and empty MCP configuration. Those flags and reported
tool inventories do not establish OS containment or qualify the installed client.
Requested model and effort remain distinct from reported model, effective effort,
and authenticated inference origin. Native internal retries, remote cancellation,
remote usage settlement, and complete descendant cessation can remain unknown.
Hard token and cost caps are unsupported.

## Configuration documents

The closed outer object is `configured-provider-profile/1`, with exactly `format`,
`provider`, `adapter_configuration`, and `limits`. Executable descriptors contain
exactly `path`, `version`, and lowercase 64-character `sha256`. Configure uses
existing installations and checks file fingerprints; it does not install a client,
download a model, log in, or accept credentials or arbitrary command arguments.
Use the native account's existing authentication setup. The shared Anthropic
owner currently accepts only `auth_mode: existing-account`; `api-key` fails before
claiming a submission because selected key-source handling is not implemented.
No ambient Anthropic key is forwarded to the Ollama route.

For Codex with an existing custom `CODEX_HOME`, select
`format: configured-provider-profile/3` and add the required outer field
`native_roots: {"CODEX_HOME": "/absolute/existing/native-root"}`. Profile `/3`
is Codex-only; the map accepts only `CODEX_HOME`. Its value must be a bounded,
normalized absolute path to an existing operator-owned directory, without
user-controlled symlink components (standard OS-controlled macOS aliases remain
supported). No native configuration or authentication file is opened to validate
the root. The selected path becomes part of the configuration digest and is the
only native-root environment variable forwarded; an ambient `CODEX_HOME` never
overrides this explicit selection. API keys, tokens, proxies, and arbitrary
environment overrides are not forwarded.

Use `native_roots: {}` in profile `/3` for the normal HOME-based native discovery
when `CODEX_HOME` is absent. Profiles `/1` and `/2` retain their exact shape and
budget behavior. For any of these profiles without an explicit root, the presence
of ambient `CODEX_HOME`, including an empty or invalid value, causes a typed
`provider_native_root_unsupported` refusal before a submission claim; it never
silently selects HOME instead. No profile format is rewritten automatically.

Explicit configure records sealed directory identity observations and selects
the current observation for that configuration. Run binds a copy before claiming
a submission and rechecks the directory identity before claim and target release.
A missing, unsafe, or replaced directory refuses. After a legitimate replacement,
explicitly configure again: this selects a new observation while retaining all
old observations, run bindings, and consumed or uncertain submission claims.
Reconfiguration cannot redispatch an already claimed task. These checks establish
directory selection and metadata, not the actual native account, loaded context,
or runtime isolation. They do not change the existing Muse route.

The following Python builds JSON-compatible **synthetic examples only**. Every
path, version, model, and hash is a placeholder. They do not describe an observed
installation and must not be submitted as real runtime identity evidence.

```python
from copy import deepcopy

limits = {
    "attempt_seconds": 720,
    "max_output_bytes": 4194304,
    "max_protocol_records": 8192,
    "max_record_bytes": 1048576,
    "max_proposal_bytes": 65536,
    "max_controller_submissions": 1,
}


def descriptor(path, digit="a"):
    return {"path": path, "version": "synthetic-1", "sha256": digit * 64}


def profile(provider, inner):
    return {
        "format": "configured-provider-profile/1",
        "provider": provider,
        "adapter_configuration": inner,
        "limits": deepcopy(limits),
    }


codex = profile("codex", {
    "format": "codex-local/1",
    "executable": descriptor("/example/bin/codex"),
    "model": "synthetic-model",
    "effort": "high",
    "context": "include",
    "runtime_closure": {"kind": "native"},
})

antigravity = profile("antigravity", {
    "format": "antigravity-native/1",
    "executable": descriptor("/example/bin/agy"),
    "model": "synthetic-model",
    "effort": "high",
    "context": "include",
    "print_timeout_seconds": 720,
    "runtime_closure": {"kind": "native"},
})

claude_anthropic = profile("claude-code", {
    "format": "claude-local/1",
    "provider_id": "claude-code",
    "backend": "anthropic",
    "executable": descriptor("/example/bin/claude"),
    "model": "synthetic-model",
    "expected_reported_model": "synthetic-model",
    "effort": "high",
    "context": "include",
    "max_turns": 1,
    "backend_config": {
        "transport": "native",
        "endpoint": "https://api.anthropic.com",
        "auth_mode": "existing-account",
    },
    "runtime_closure": {"kind": "native"},
})

claude_ollama = deepcopy(claude_anthropic)
claude_ollama["adapter_configuration"].update({
    "backend": "ollama",
    "backend_config": {
        "transport": "ollama-launch",
        "endpoint": "http://127.0.0.1:11434",
        "inference": "local",
        "launcher": descriptor("/example/bin/ollama", "b"),
        "saved_model": "synthetic-model",
    },
    "runtime_closure": {
        "kind": "ollama-launch",
        "claude_on_path": descriptor("/example/bin/claude"),
        "path": "/example/bin",
        "settings_file": descriptor("/example/home/.ollama/config.json", "c"),
        "model_pointer": ["integrations", "claude", "models", 0],
    },
})

# A Node entrypoint requires the declared native binary too.
codex_node = deepcopy(codex)
codex_node["adapter_configuration"]["executable"] = descriptor("/example/codex/entry.js")
codex_node["adapter_configuration"]["runtime_closure"] = {
    "kind": "node",
    "node": descriptor("/example/bin/node", "d"),
    "entrypoint": descriptor("/example/codex/entry.js"),
    "native_binary": descriptor("/example/codex/native/codex", "e"),
}
```

Codex effort accepts `low`, `medium`, `high`, or `xhigh`; Antigravity also accepts
`max`. Claude accepts those five values or `null`. The shared Claude configuration
defaults `max_turns` to one; explicit supported values are 1–64. This turn setting
does not count or limit backend model requests. Antigravity's required finite
`print_timeout_seconds` is clamped to the remaining local attempt allowance.

For a Codex Node entrypoint, the owner fingerprints Node, the entrypoint, and the
declared native binary at configuration and release checks. Pinning declarations
does not independently authenticate every loader decision or native descendant.

Ollama uses the existing `ollama launch claude --model ... -- ...` transport.
Its closure must bind the effective `$HOME/.ollama/config.json`, the exact
`integrations.claude.models[0]` selection, the launcher, and the existing `claude`
resolved by the supplied PATH directory. The saved model must equal the selected
model; a known model change fails rather than altering saved preferences. The
owner rechecks settings bytes, HOME, and Claude path identity before release.
There is no `--yes`: setup or model pulls are not automatically approved.

Ollama's endpoint must be an explicit HTTP loopback endpoint with a port. A local
daemon may use local or cloud inference; `inference: "local"` and `"cloud"` are
explicit configuration intent. A model explicitly named with `:cloud` or `-cloud`
cannot be labeled local. Endpoint locality and reported model strings alone do
not prove local-only inference or billing behavior. No live native Anthropic
qualification is claimed by the synthetic configuration or protocol tests.

## Task preparation and use

Codex, Antigravity, and Claude use the same repository request shape:

```json
{
  "repository": "/example/repository",
  "base_commit": "1111111111111111111111111111111111111111",
  "task": "Implement the declared synthetic module using the reference.",
  "read_paths": ["docs/reference.txt"],
  "writable_paths": ["src/new_module.py", "src/existing_module.py"],
  "artifact_format": "file-replacements/1"
}
```

The required keys are `repository`, `base_commit`, `task`, and `writable_paths`.
`read_paths` defaults to an empty list; `artifact_format` defaults to
`file-replacements/1`. Preparation observes an exact clean Git base and the
selected regular UTF-8 text files. It supports at most 32 paths per role,
256 KiB per source file, and 512 KiB combined snapshots. Read inputs must be
tracked. A new writable output must actually be absent and appears as `null` in
the prepared plan's `writable_outputs`. Read-only references never grant write
permission. Protected paths, traversal, symlinks, duplicate/case aliases, and
ancestor aliases are refused. Unselected repository files are not snapshots.

The source API sequence is:

1. `RunService.configure_provider(provider, configuration)` records checked local configuration.
2. `prepare_provider_task(provider, request=request)` observes the task without dispatch.
3. `provider_budget(provider, request=request)` reports the prompt size, local limits, and plan identities without consuming a submission.
4. `run_provider(provider, request=request, output=output)` reobserves source and configuration, reserves one logical submission, and runs the owned experimental process.
5. `inspect(run_id)` and `result(run_id)` read retained state and artifacts. The CLI names these operations `status` and `result`.
6. `cancel(run_id, operation_key=key, expected_revision=revision)` requests cancellation of an active owned attempt. `reconcile(...)` with the same argument names observes retained evidence.

The corresponding CLI commands are `configure-provider`, `prepare-provider-task`,
`provider-budget`, `run --provider`, `status`, `result`, `cancel`, and `reconcile`.
Use an independently chosen operation key and the currently observed revision for
each control operation. A repeated matching operation returns its retained receipt;
a stale revision or conflicting reuse fails. Interrupted cancellation publication
remains unknown and is not automatically replayed. Reconcile never launches,
resends the task, or signals a saved PID. Cancellation is a request consumed by the
current owner, not proof of remote cancellation or settled usage.

The subprocess workspace and control artifacts are private owner locations,
separate from the source repository. The prompt carries the selected snapshots.
A completed native stream is validated independently before `proposed.patch` and
`proposal.json` are staged. `proposal_ready` does not mean applied, tested,
independently accepted, or production qualified. Before manual application, verify
the actual repository/base again and review and test the proposed change.

## Bounds and retained evidence

The default shared profile uses a 720-second local attempt,
4 MiB combined output capture, 8,192 protocol records, 1 MiB per protocol record,
64 KiB canonical decoded proposal, and one reserved controller submission.
Codex's separate result file is also one protocol record: its raw JSON may use
more than 64 KiB, while remaining within the 1 MiB record and combined capture
limits. The decoded canonical object has its own 64 KiB limit.
For a new longer task, select `format: configured-provider-profile/2` and set
`limits.attempt_seconds` explicitly, through **1440 seconds (24 minutes)**.
Version `/3` permits the same 1440-second ceiling for Codex with explicit native
roots. Version `/1` retains its 720-second ceiling. All versions retain the 720-second
default and preserve explicit shorter values. No capture, record or proposal
limit grows with the deadline. For Antigravity also set its explicit
`adapter_configuration.print_timeout_seconds`; the lower of that value and the
remaining shared deadline applies. Codex and Claude use the shared owner deadline.
Smaller supported finite limits may be selected; capture checkpoint capacity is
also finite. The stdin packet is capped at 1 MiB. The generated patch has a separate
1 MiB bound. A small unified diff can edit a preimage larger than 64 KiB without
returning the whole file; the independent validator checks exact hunk positions,
counts, context, and reconstructed hashes, then emits ordinary Git-compatible
context. Claude currently refuses `unified-diff/1` before a submission claim.

These are local bounds. Cleanup and evidence finalization may extend briefly
beyond the attempt deadline. One controller reservation does not imply one native
model request, a cost cap, or remote settlement. Changing transport format or
budget does not create a fresh logical task claim. Failures, overflow, malformed
streams, and uncertain cancellation retain evidence and do not authorize retry.
There is no automatic fallback, apply, acceptance, or retry.

Private capture retains stdout, stderr, and any separate result stream with
bounded raw bytes and immutable integrity checkpoints as output arrives. Closure
reports retained versus observed bytes; truncated or conflicting evidence cannot
be presented as a complete successful proposal. Root exit, group observations,
complete descendant cessation, native terminal status, and remote usage remain
separate facts. Status/result records can include private local paths: review
them locally rather than publishing them as public artifacts.

## Muse compatibility

`muse` retains its existing configured experimental route and legacy request or
prepared-bundle format. It does not accept the generic repository request above.
It now streams through durable private capture and shares cancellation/reconcile
controls through the same `RunService` facade. Native process ownership remains
in its existing macOS route. Default context remains `include`; full exclusion
fails and `native-only` remains partial.

For a **new** longer Muse task, `capture_profile: large-task` selects the new
`local-muse-provider/5` configuration. Set `attempt_seconds: 1440` (or a shorter
finite value). Explicit `max_output_bytes`, `max_proposal_bytes` and
`max_protocol_records` remain separate; for example 1048576, 12288 and 2048
preserve a 1 MiB / 12 KiB / 2048-record packet. This profile caps those values at
4 MiB / 64 KiB / 8192 records. Existing configurations and stored claims are not
rewritten: fixed `implementation` profile `/4` remains exactly 720 seconds, and
older timeout/capture successor cohorts do not gain a longer retry. Choosing a
longer profile never authorizes redispatch of an already consumed task.

Muse's explicitly selected `implementation` capture profile is fixed at
720 seconds, 4 MiB, 8,192 protocol records, and a 64 KiB proposal; legacy profiles
retain their original limits and identities. Its previously defined finite,
explicit successor workflow remains separate from the shared owner. Ordinary
`run` never repeats a consumed claim or schedules a retry. See proposed
[ADR0023](adr/0023-finite-manual-muse-successors.md) and
[ADR0024](adr/0024-bounded-implementation-capture.md).

The authoritative closed configuration and behavior contracts are
[local_provider_adapters.py](../src/taskalong/local_provider_adapters.py),
[local_provider_contract.py](../src/taskalong/local_provider_contract.py),
[local_provider_runtime.py](../src/taskalong/local_provider_runtime.py), and
[claude_local_config.py](../src/taskalong/executors/claude_local_config.py).
The proposed ownership decision is [ADR0026](adr/0026-configured-provider-owner.md).

## One-MiB final proposals

A larger final proposal is an explicit, versioned choice. Existing profiles,
receipts, claims and defaults keep their previous bounds. The time limit remains
independent: select at most 1440 seconds, with 720 seconds still the default.
A failed prior task does not acquire another submission by changing these limits.

For Codex, Antigravity and Claude Code, use `configured-provider-profile/4` and
provide the complete `limits` object. The recommended expanded limits are:

```json
{
  "attempt_seconds": 1440,
  "max_output_bytes": 67108864,
  "max_protocol_records": 131072,
  "max_record_bytes": 16777216,
  "max_proposal_bytes": 1048576,
  "max_controller_submissions": 1
}
```

Profile `/4` also requires `native_roots`: use an empty object for Antigravity or
Claude Code; Codex may explicitly bind `CODEX_HOME` as in profile `/3`. Smaller
positive limits remain selectable. The final limit counts the canonical UTF-8
JSON proposal, including its binding fields and JSON escapes; actual patch or
replacement text can therefore be smaller than one MiB. The separate Codex
response file is limited to 4 MiB of wire JSON before canonical validation.

For Muse, configure `capture_profile: "megabyte-proposal"`. This creates
`local-muse-provider/6` with exactly 64 MiB combined raw capture and 131,072
protocol records. Set `max_proposal_bytes` between 1024 and 1048576 and
`attempt_seconds` between 1 and 1440. The defaults for this new profile are
1048576 and 720 respectively. Its protocol frame limit is 16 MiB and extracted
response-wire limit is 4 MiB. The existing account, model, effort and context
choices remain explicit; selecting a larger output profile does not change them.
After a completed `/6` stream, the identity observer separately reads at most
64 MiB of the selected native session journal, with the same record/frame
ceilings. It retains only the configured-request count and final small identity
fields, checks the held file and directory identities, and compares two streamed
hashes. This is an observation read bound, not a quota on native journal growth.
The legacy 4 MiB startup-context reader remains unchanged.

Raw capture includes prompts echoed by a provider, progress, deltas, terminal
records, stderr and the separately read Codex response. It is much larger than
the final result. Streaming overhead depends on native fragment sizes and
repetition. These finite limits admit representative large streams; they do not
guarantee that every one-MiB proposal will fit. Overflow, excessive records,
malformed frames, missing completion or uncertain cleanup remain failures. There
is no automatic cap growth, retry, fallback, patch application or acceptance.

The new profiles stream original bytes to private capture files instead of
retaining duplicate full-transcript process buffers. Final responses are stored
separately from small, hash-bound references in receipts. Authority documents
retain their original one-MiB ceiling. Independent capture checkpoints retain a
separate ceiling of 8192 records, at most 16 KiB each; this is not the protocol
record count. Reconstruction and normalized review patches have independent
limits (4 MiB generated patch, at most 2 MiB per reconstructed file, and a
source-plus-selected-proposal aggregate bound in the shared validator). Muse's
replacement-only route additionally keeps its selected one-MiB aggregate output
bound. All proposals still require human review and independent tests before
manual application.

These are controller byte and object bounds, not an OS disk quota or a measured
RSS guarantee. Native subprocess memory, native result files while being written,
account journals and remote usage remain outside them. Existing uncertainty about
provider-internal retries, effective effort, remote cancellation and descendants
is preserved. Offline boundary tests establish parser and lifecycle behavior;
they do not qualify an account or prove a live provider will complete the task.

## Explicit recovery after a limited capture

Changing capture limits does not release a consumed task claim. The newer
`manual-muse-successor-plan/3` path is a separate, model-free decision for an
original failed `local-muse-provider/5` large-task run and an explicitly selected
`/6` configuration. It preserves the original deadline, task, binary, account,
model, effort and context. Only the declared capture/proposal envelope changes.
The earlier timeout ladder and `/3` to `/4` capture path remain unchanged.

Request a decision with the existing command:

```text
taskalong --state-dir EXISTING_STATE --json provider-successor-plan muse --predecessor FAILED_RUN --reason capture
```

Eligibility requires independently checked limited-capture hashes and counters,
unchanged run/event/process/invocation/bundle/submission evidence, observed root
exit and owned-group termination without tracking/protocol errors, and a full
stable native journal proving one bound empty-tools/reminders model request and
one conclusive cancellation during that model step. The versioned proof inspects at most 64 owner events and 16 MiB of owner-event
history, separately from the capture checkpoint and native journal bounds. These
observations do not settle remote usage or prove that all descendants ceased.

A complete JSON value assembled from nonterminal output fragments remains an
unsealed candidate. It is never staged or accepted by this path. A completed,
conflicting or ambiguous native terminal, any terminal-bearing torn prefix, or
an existing staged response/proposal blocks a new attempt and requires result
reconciliation. A visible `run.terminal.completed` prefix cut inside its text is
such a stop; treating that text as discardable metadata would be incorrect.

An eligible decision grants no invocation. A separately authorized explicit
`provider-successor` command, using the exact plan digest, operation key and
fresh output directory, can reserve at most one final successor. Reservation
precedes preflight; denial, setup failure or a crash consumes the slot. Repeating
the same operation only observes retained state. Another key, copied State,
restored database or changed scope cannot silently create a new slot. Original
claims, failed evidence and unknown prior exposure remain retained.

The successor path does not recover complete results. When terminal
completion is possible, the owner must first observe the exact bound session's
full native journal or another sealed complete response, with its source,
identity, hashes, completeness and original proposal limits checked. A full
journal showing completion cannot be reused as cancellation proof. Missing or
contradictory evidence is reported; raising a cap or approving another call does
not manufacture the missing facts. No fresh State or cosmetic request change is
a supported recovery mechanism.

## Recovering a sealed result after capture failure

A completed native terminal is a result-reconciliation case, not permission to
submit another attempt. The separate complete-result recovery route observes
the original failed Muse `/5` run and its pinned configuration without invoking
the provider or requiring a newly selected output profile. It does not change
the original run's failed status, capture, events, submission claim or unknown
usage and descendant observations.

The model-free plan requires a full, stable, bound native journal containing one
recognized configured request, one committed assistant response and one completed
terminal, in that order. The retained stream and any torn terminal text must
agree with that sealed response. Fragments alone are insufficient. Provider and
model observations must match the original configuration, and the response must
pass the original task's proposal, source, schema and sensitive-data checks.
An empty declared toolset does not prove absence of all unknown native activity.

A bound durable `session.end` event may close the journal after completion. It
must use the native session-end wrapper and carry only bounded passive metadata;
foreign identities, hidden model/tool/result activity, duplicate closure and any
record after closure are refused. Session closure does not establish remote
settlement, account provenance or complete descendant cessation.

Journal observation has separate local read ceilings of 64 MiB, 131,072 records
and 16 MiB per frame. Committed response wire text is capped at 4 MiB, while its
canonical proposal must still fit the original `/5` limit of at most 64 KiB.
These read bounds do not enlarge the failed submission's capture or proposal
allowance. Plans expose hashes, sizes and provenance rather than response text.

Inspect the decision without staging:

```text
taskalong --state-dir EXISTING_STATE --json provider-result-recovery-plan muse --run-id FAILED_RUN
```

If the exact plan is eligible, an explicit local recovery operation can reserve
one separately recorded result observation and stage its proposed patch:

```text
taskalong --state-dir EXISTING_STATE --json provider-result-recover muse --run-id FAILED_RUN --key RECOVERY_KEY --plan-digest PLAN_DIGEST --output FRESH_OUTPUT
```

This operation makes no inference request. It retains a private response and a
new bound snapshot for proposal validation; the copied original submission marker
prevents the snapshot from becoming a fresh provider task. Its exclusive anchor
also fences cancellation successors and copied or restored State. The same key
observes the existing recovery; another key cannot restage after a crash or
uncertain local outcome. Missing, changed, conflicting or incomplete evidence
refuses recovery. No automatic retry, application, acceptance or usage settlement
is performed. The proposed patch still needs independent review and tests before
manual application.
