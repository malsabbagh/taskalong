# Contributing

This is an experimental foundation with configured local Muse execution and
separate closed production-qualification contracts. The
project uses the [MIT License](LICENSE). Submit original contributions under
that license and retain applicable notices; no separate contributor agreement
is included in this candidate.

Use original code and synthetic examples. Do not add credentials, private prompts,
source snapshots, operational logs or third-party implementation without recorded
rights and notices. Keep changes small and state actual qualification limits.
Preserve v1 canonical data, durable effects, worktree fencing, unknown-effect
quarantine, independent acceptance and the separate production-qualification boundary.
Configured experimental provider execution must remain usable without a second
activation gate. Preserve explicit context choices, one-use dispatch and manual
patch review; never publish local context, account data or raw provider captures.

Run relevant tests plus `python scripts/check_docs.py`,
`python tools/sync_guides.py --check` and whitespace checks. Full installed
qualification is described in [qualification](docs/qualification.md). A passing
fixture cannot enable a live route. No model/provider/tier/auth/trust fallback or
security-check bypass is an acceptable recovery mechanism.

Publishing, changing repository visibility, changing the license, changing
credentials/security settings or enabling an unqualified runtime requires its
separate owner decision. See [security guidance](SECURITY.md).
