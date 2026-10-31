# TaskAlong

Experimental local CLI for durable development tasks and configured Muse coding
runs on macOS. Provider output is staged for manual patch review. This candidate
is not a package-registry release.

TaskAlong exposes `taskalong.api.RunService` and the `taskalong` console command.
It records immutable tasks, attempts, ordered events, effects and independent
evidence in SQLite, with fenced Git worktrees, bounded process supervision and
exact-intent publication contracts. Independent checks and separately installed
ReviewSensei results govern acceptance; worker output cannot grant authority.

## What is available

- Synthetic task, interruption/recovery, exact-session protocol, cancellation,
  verification and fixture publication journeys.
- Configured local Muse execution on macOS: `configure-provider` followed by
  `run --provider muse`, with bounded capture and proposed patches for manual review.
  It is experimental and requires no separate production activation.
- Offline production Muse preparation/lifecycle contracts remain distinct from
  the configured experimental provider route.
- Installed read-only guides: `taskalong guide`, `taskalong guide operations`,
  `taskalong guide contracts` and `taskalong guide qualification`.
- Explicit Codex, Claude, Cursor and Antigravity synthetic driver projections sharing one supervisor,
  with offline wire decoders and contract tests. Separate local/direct-cloud
  Ollama profiles run through the same Claude fixture driver. These older fixture projections do not imply live execution support.

The Codex production path returns `runtime_policy_unsupported` before dispatch.
Instruction/tool isolation, complete real-worker descendant lifetime, remote
cancellation/accounting and live provider routing remain unqualified. Synthetic
profiles are test boundaries for external fixtures, not a live-execution bypass.
No other installed CLI is automatically admitted and no provider/model fallback
is selected. macOS results do not qualify Linux or a real model/backend.

## Run a configured Muse provider

Create a local JSON config containing the direct native executable path. Muse keeps
its existing login; TaskAlong does not take an API key or start a login flow.
`context` defaults to `include`, preserving preconfigured local context.

```json
{"executable":"/absolute/native/muse","model":"muse-wonder-full-1.0","reasoning_effort":"high","context":"include","attempt_seconds":20,"max_output_bytes":65536}
```

```sh
taskalong configure-provider muse --config provider.json
taskalong providers
taskalong provider-budget muse --request task.json
taskalong provider-context muse --output /absolute/private-context-review
taskalong run --provider muse --request task.json --output /absolute/new-run
taskalong result RUN_ID
```

The task JSON explicitly selects a source snapshot and task; see the
[operations guide](docs/operations.md#configured-local-muse-provider). A configured
provider runs without a second activation/qualification gate. The result is a
proposed patch: review and apply it manually, then run tests in a disposable copy.
There is no automatic apply, retry, model/provider fallback or remote settlement.
Native retries/remote usage/descendant lifetime may remain unknown.

The 20-second default is a short smoke budget. Explicit configuration supports
finite deadlines through 720 seconds. A consumed task can use the separate
[manual timeout successor procedure](docs/operations.md#explicit-manual-timeout-successors):
one 360-second successor and one conditional final 720-second successor after an
original timeout of at most 60 seconds. An original 360-second timeout instead
permits only one linked 720-second successor. Both schedules retain
the original claims and task. Nothing automatically retries or applies a patch.

Set `context` to `exclude` to request full exclusion. The currently supported Muse
client cannot guarantee that with its existing login, so TaskAlong fails clearly
before provider dispatch. `native-only` is an explicit partial option that passes
Muse's foreign-context exclusion flag while retaining native personal context.
For explicitly larger implementation tasks, opt in to the fixed
`"capture_profile":"implementation"` configuration: 720 seconds, 4 MiB combined
protocol, 8,192 records and 64 KiB decoded proposal. Defaults and legacy limits
stay unchanged. A consumed legacy implementation capture failure has a separate
[one-shot capture successor](docs/operations.md#explicit-capture-successor);
it requires retained cancellation evidence and never retries automatically.

Private configuration, context and raw captures stay local; publish code and
sanitized validation summaries only.

## Local artifact trial

Package metadata targets Python 3.11–3.14. The receipt requirements and limits in
[qualification](docs/qualification.md) apply to each actual interpreter/host;
installer compatibility alone is not qualification. Install an explicitly
reviewed local wheel:

```sh
python -m pip install path/to/taskalong-0.1.0a1-py3-none-any.whl
taskalong --version
taskalong guide fixture
```

This does not assume a TaskAlong registry upload exists. The complete synthetic
[walkthrough](docs/fixture-walkthrough.md) uses external fixtures from the matching
sdist and the separately installed released ReviewSensei 0.8.8 fixture backend.
A core-only installation correctly blocks required review and acceptance.

For development, use the exact hash-locked `requirements-dev.lock`, build with
`python -m build --no-isolation --sdist --wheel`, normalize source-archive headers
with `python tools/normalize_sdist.py dist/*.tar.gz`, and audit with
`python tools/check_dist.py --dist-dir dist`. The installed qualification command
is described in [qualification](docs/qualification.md).

## Boundaries and status

See [architecture](docs/architecture.md), [contracts](docs/contracts.md),
[operations](docs/operations.md), [offline Claude protocol](docs/claude-protocol.md),
[Antigravity fixture protocol](docs/antigravity-protocol.md)
and [security guidance](SECURITY.md). These documents distinguish implemented
fixture behavior from actual runtime capabilities. No stable API, arbitrary
runtime compatibility, exactly-once remote effect or hard provider cost cap is
claimed.

## License and provenance

TaskAlong is licensed under the [MIT License](LICENSE). The complete copyright
and permission notice is included in source and built distributions.
See [provenance](PROVENANCE.md) and [dependency inventory](THIRD_PARTY.md).
Dependencies retain their own licenses. Registry publication is a separate
owner decision; this candidate does not imply an available registry release.

The [ordered CLI fixture recipe](docs/ordered-tasks.md) demonstrates bounded two-step
work with durable progress and explicit advance.
