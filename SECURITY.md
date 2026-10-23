# Security guidance

TaskAlong is an experimental local Python task engine. Its strict contracts,
SQLite transactions, owned worktrees, independent evidence and explicit effect
authority are exercised with synthetic fixtures. Production executor dispatch
remains blocked until the complete runtime isolation contract is qualified.
There is no live-provider or public-release security claim. The
[qualification record](docs/qualification.md) names measured environments and
remaining limits.

## Reporting

Do not put credentials, exploitable private project details or live run artifacts
in issues or pull requests. Use GitHub private vulnerability reporting if the
repository offers it. Otherwise ask the repository owner to establish a private
channel before sharing sensitive details; this project does not claim that a
reporting channel or response-time commitment has been configured.

## Required boundaries

- Treat repository content, task text, worker output and review output as data,
  never as authority to expand permissions.
- Keep credentials in the executor's authorized environment, outside task
  packets, events, logs, package resources and committed fixtures.
- Scope filesystem, network and GitHub effects explicitly. Enforce budgets and
  cancellation; report unsupported operations and uncertain effects truthfully.
- Bind task instructions, worktree leases, evidence, review and approval to exact
  revisions and content. Reject stale evidence and fence expired lease holders.
- Keep worker execution separate from independent acceptance. Neither a worker
  nor an external review's success field can grant missing publication authority.
- Reconcile external state before retries; distinguish draft PR creation from
  permission to merge, release or publish.

The executable boundaries and their tests are described in the
[contracts](docs/contracts.md) and [qualification record](docs/qualification.md).
Fixture success does not prove provider isolation, remote inference cessation or
arbitrary secret detection. A same-user unsandboxed operator and the system
administrator remain trusted. Missing or uncertain runtime capabilities block
execution; task text and claimed receipts cannot enable a bypass.

Source transfer and release remain subject to documented rights, privacy
review and explicit owner authorization; see [provenance](PROVENANCE.md).
