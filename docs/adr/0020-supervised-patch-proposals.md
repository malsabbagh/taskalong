# Offline supervised patch proposal seam

Status: proposed; development/testing only, no live model admission.

A separate POSIX CLI artifact workflow binds an explicitly supplied text snapshot,
task, base-commit claim and provider/model intent to a canonical digest. It creates
a fixed prompt, accepts one bound local response containing full-file replacements,
and generates a proposed unified text patch for human review and manual application.
No repository is opened, observed or modified. Supplied base/content provenance is
unverified, and a staged response cannot claim provider authenticity or test success.

Alternatives: routing through RunService would mix unqualified local content with
owned production attempts and exposure authority. Accepting arbitrary diff text
would require another patch grammar and risk ambiguous paths/modes. Complete text
replacements let the core generate deterministic add/edit/delete hunks against the
supplied snapshot, with literal declared paths, existing protected-path exclusions,
case/ancestor conflict checks, LF text limits and no executable-mode changes. Empty
file creation/deletion, binary data, renames, symlinks and non-LF text are unsupported.
Provider/model fields are opaque intent for later adapters, never executable argv.

The prepare/stage commands run before RunService and create private, exclusive,
fsynced artifacts. An exclusive response claim precedes staging. Failure retains
claim and partial artifacts as uncertain, with no overwrite or automatic replay.
The final review record is written last. Existing source, prompts and histories
are never deleted. Same-user processes can still tamper with files; permissions
and digest checks are not an isolation guarantee.

The public run command unconditionally refuses before any provider action.
Snapshots, prompt instructions and diagnostic receipts cannot open this gate.
Tests use synthetic local responses; a disposable Git fixture verifies generated
patch applicability and is never part of the production staging implementation.
Existing production admission, account holds, exposure ledger and no-retry rules
remain unchanged. No new Store/schema version or provider subprocess is added.

A live supervised route remains a separate implementation/authorization boundary:
qualify the exact effective account/model and finite exposure, context/tool scope,
cancellation and child lifetime; obtain the owner's specific residual-risk decision;
then implement/review a bounded admission contract. This record grants neither
execution nor acceptance. Local stop must not stamp remote usage as settled.
Rollback removes these commands/module and retains artifact directories for review.
