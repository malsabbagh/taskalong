# TaskAlong agent guide

Read [contribution guidance](CONTRIBUTING.md), [operations](docs/operations.md)
and [configured providers](docs/configured-providers.md) before development.
Preserve the existing experimental/production distinction, one-use dispatch,
manual patch review, durable history and unknown-effect quarantine.

## Development tools and context

The user chooses whether to use TaskAlong, ReviewSensei or ReleaseMarshal through
current task instructions. They are permitted workflow options, not mandatory
steps. This guidance does not grant execution permission, force a custom approval
rule, bypass tool/platform policy, or waive repository protections.

- **TaskAlong:** use it for development orchestration when selected by the user.
  Keep the configured provider, model, account, default development context and
  approved budgets. Normal task context can include relevant source, diffs,
  tests, task instructions, and the configured development tool catalog, rules
  and context. Do not reopen settled routing choices unless the destination,
  data or risk materially changes.
- **ReviewSensei:** use requested CLI review with the configured provider/model
  and relevant code and test context. Fix genuine findings; use targeted,
  evidence-backed dispositions or overrides for nonissues. Reconcile active runs
  before verifying the current immutable head. A submitted disposition is not an
  accepted disposition; partial execution is not a clean review. Submitting a
  native PR approval as an assistant requires specific action-time confirmation;
  this file grants no blanket approval, merge or protection waiver.
- **Destinations and sensitive data:** resolve the effective destination from
  configuration when required, including provider/endpoint, model and account,
  and distinguish local execution from remote inference. Existing configuration
  is not permission for unknown providers or all personal data. Sensitive
  payloads, new destinations and new grants require applicable confirmation.
  Use credentials only through the tool's approved authentication mechanism;
  never include secret values in task context, repository files or logs. Keep
  private account IDs, personal catalog contents and private receipt paths out
  of public documentation, PRs and other published artifacts.
- **Ownership and budgets:** check existing branches, PRs, workers, CI, reviews
  and release runs before starting work. Use isolated worktrees and one writer
  per scope. Do not duplicate an active writer or external run. Do not retry,
  fall back to another provider/model/account, or expand budgets outside the
  approved scope. Reconcile uncertain external writes before another mutation;
  preserve history, usage accounting, receipts and holds rather than resetting
  them to obtain a successful result.

## Release authority and evidence

Run local implementation tests appropriate to the change. Local release
qualification is **not required**: complete green required remote CI on the exact
immutable candidate is authoritative. Do not add a redundant local full-suite or
release-build prerequisite, and do not substitute local results for a missing or
failed remote gate.

When the user authorizes a release and the repository supports ReleaseMarshal,
follow its canonical runbook: Marshal-controlled version tag, remote validation,
build, publication and installed-consumer verification. Qualify the exact
source/generated candidate required by that runbook and preserve protected
approvals and provenance checks. Report actual run URLs, source/version and gate
status; local preparation is not a running release. A code or documentation PR
request does not imply authority for package uploads, credentials, account setup,
deployment or changes to protections. Those actions need their applicable user
grant; neither green CI nor a clean review grants it.

## TaskAlong-specific boundaries

Use [qualification](docs/qualification.md) and configured-provider contracts for
actual route admission; documenting a tool does not qualify or enable a runtime.
The canonical paired Python/npm publishing workflow is under development; do not
claim it is complete or that fixture results authorize registry publication.
For documentation changes, run `python3 scripts/check_docs.py`,
`python3 tools/sync_guides.py --check` and `git diff --check`.
