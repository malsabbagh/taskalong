# TaskAlong

Experimental local foundations for durable development tasks. **Live executor
dispatch is disabled.** This candidate is not a supported live coding-agent
service or a package-registry release.

TaskAlong exposes `taskalong.api.RunService` and the `taskalong` console command.
It records immutable tasks, attempts, ordered events, effects and independent
evidence in SQLite, with fenced Git worktrees, bounded process supervision and
exact-intent publication contracts. Independent checks and separately installed
ReviewSensei results govern acceptance; worker output cannot grant authority.

## What is available

- Synthetic task, interruption/recovery, exact-session protocol, cancellation,
  verification and fixture publication journeys.
- Installed read-only guides: `taskalong guide`, `taskalong guide operations`,
  `taskalong guide contracts` and `taskalong guide qualification`.
- Explicit Codex, Claude, Cursor and Antigravity synthetic driver projections sharing one supervisor,
  with offline wire decoders and contract tests. Separate local/direct-cloud
  Ollama profiles run through the same Claude fixture driver. Real CLI execution
  and provider routing are unqualified.

The Codex production path returns `runtime_policy_unsupported` before dispatch.
Instruction/tool isolation, complete real-worker descendant lifetime, remote
cancellation/accounting and live provider routing remain unqualified. Synthetic
profiles are test boundaries for external fixtures, not a live-execution bypass.
No other installed CLI is automatically admitted and no provider/model fallback
is selected. macOS results do not qualify Linux or a real model/backend.

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
