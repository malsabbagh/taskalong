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

The default and maximum shared profile uses a 720-second local attempt,
4 MiB combined output capture, 8,192 protocol records, 1 MiB per protocol record,
64 KiB canonical decoded proposal, and one reserved controller submission.
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
