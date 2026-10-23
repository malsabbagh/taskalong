# ADR 0003: Quiescent maintenance and immutable store history

Status: Proposed

The M3 store upgrade is explicit. Document versions 1.0, 2.0 and 2.1 retain their
original bytes and meanings; database format 2 is a separate version. New stores
still initialize in format 1. No runtime admission, steps or launcher is added.

All current Store clients hold a shared lifetime maintenance gate, including
supervisor, check, review and publication callers. Maintenance requires its
exclusive gate plus SQLite exclusive locking in rollback-journal mode. The WAL
transition must fail while a predecessor client remains open; an already-open
old client cannot be fenced by a new advisory marker alone. Unavailable or busy
kernel/VFS exclusivity refuses maintenance. Local filesystems and one trusted OS
operator remain prerequisites; this is no fence against hostile same-user code.
Quiescence additionally rejects active/uncertain attempts, cancellation, pending
effects, unknown effect kinds and inconsistent control records. Closing a client
does not itself prove a detached worker stopped.

An advisory-only interface was rejected because old clients ignore it. An
operator-provided boolean was rejected because it supplies no exclusion proof.
A replacement backup system was rejected in favor of extending Store.backup:
its original SQLite-file behavior remains, while complete=True requires actual
maintenance ownership and includes private control files and blobs.

The complete control backup uses SQLite backup to include committed WAL state.
Its private manifest binds application-table row/schema fingerprints, files,
directories, original private modes and blob identities. Orphaned captures and
instruction files remain private data. SQLite auxiliary journals and empty
coordination files are explicitly omitted; they are not portable OS locks.
External worktrees, repositories, executables, referenced configuration outside
the control root and remote state are separate dependencies, not silently copied.
Redacted exports cannot substitute for this backup.

Upgrade writes an idempotent operation intent before creating its backup. The
intent binds store identity, target format and backup/restore path identities;
the backup includes the intent and the final receipt names the resulting backup
digest. This avoids recursive hashes. A changed operation request conflicts.
Selected paths reject user symlinks before normalizing trusted OS aliases.
Containment checks also compare existing directory identities so case aliases
cannot hide a nested target; restore checks separation from its backup again.
Before DDL, the complete backup must still match the exclusively owned source,
and a fresh-directory restore must pass independent integrity/row comparisons.
Restore uses a private sibling staging directory. Before copying any payload, a
canonical bootstrap database is committed with a foreign quarantine tag that
both predecessor and current clients reject. The full snapshot replaces only
that bootstrap after independent verification and quarantine. The completed
staging inventory, including directories and modes, must match the trusted backup
manifest. Only then is the directory published atomically without replacement
(Darwin renamex_np RENAME_EXCL or Linux renameat2 RENAME_NOREPLACE). Unsupported
platform/filesystem primitives refuse publication; ordinary rename is no fallback
because it can replace an existing empty directory. Interrupted private stages
remain for inspection. The selected final path is absent or a complete quarantine;
restoring over any existing directory is forbidden.

Only then does numbered SQL 002 create immutable document/migration history,
copy original legacy profile bytes, and atomically update user_version, format
metadata and the operation receipt. DDL uses individual statements inside one
transaction, not executescript's implicit commit. An interrupted upgrade leaves
format 1 plus its durable intent or the complete committed format 2; partial
backup/restore artifacts remain for inspection. Matching complete artifacts may
be verified and reused. Partial artifacts are never overwritten or auto-deleted.

Automatic rollback or restore promotion is intentionally absent: a local snapshot
cannot undo later external effects. Recovery requires reconciliation/forward
repair. Stored M2 decisions remain historical evidence, not current authority;
future admission must revalidate current policy/evidence/revocations and preserve
exact-mode requirements. In particular, required native resume cannot be dropped
to make start admission pass.

Tests exercise actual predecessor source, cross-process locks, committed WAL,
complete manifests, symlink/tamper/missing data, ENOSPC fault injection, SIGKILL
barriers, atomic migration rollback, immutable history and the upgraded synthetic
lifecycle. Synthetic success establishes no real-provider runtime qualification.

The exclusion oracle composes exact predecessor compatibility with separate
real SQLite lock witnesses. The pinned predecessor opens before and after
maintenance, and an already-open predecessor must prevent maintenance acquisition.
While actual maintenance holds exclusive/delete ownership, fresh subprocesses
bypass the advisory gate and must receive numeric SQLITE_BUSY at the protected
read and write-reservation operations. Only those witnesses disable their own
busy retry handler; production and predecessor settings are unchanged. Unlocked
positive controls and an advisory-only counterexample establish sensitivity to
missing kernel exclusion, with unchanged logical application state.
Ten seconds is subprocess test containment, not a product refusal SLA. A timeout,
missing result or unconfirmed reap still fails. The earlier default-handler
constructor timeout remains unexplained; this changed proof does not qualify its
latency or establish its native cause. Local-filesystem/trusted-operator limits
remain unchanged.
