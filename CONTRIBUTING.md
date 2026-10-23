# Contributing

This is an experimental foundation with live executor dispatch disabled. The
project uses the [MIT License](LICENSE). Submit original contributions under
that license and retain applicable notices; no separate contributor agreement
is included in this candidate.

Use original code and synthetic examples. Do not add credentials, private prompts,
source snapshots, operational logs or third-party implementation without recorded
rights and notices. Keep changes small and state actual qualification limits.
Preserve v1 canonical data, durable effects, worktree fencing, unknown-effect
quarantine, independent acceptance and the production refusal.

Run relevant tests plus `python scripts/check_docs.py`,
`python tools/sync_guides.py --check` and whitespace checks. Full installed
qualification is described in [qualification](docs/qualification.md). A passing
fixture cannot enable a live route. No model/provider/tier/auth/trust fallback or
security-check bypass is an acceptable recovery mechanism.

Publishing, changing repository visibility, changing the license, changing
credentials/security settings or enabling an unqualified runtime requires its
separate owner decision. See [security guidance](SECURITY.md).
