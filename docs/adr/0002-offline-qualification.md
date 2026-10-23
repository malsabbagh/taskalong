# Offline qualification evidence decisions

Status: proposed for review in the M2 PR.

M1 separates semantic execution identity from evidence. M2 adds frozen receipt,
decision and capability-report documents plus a pure evaluator over explicit
in-memory snapshots. No driver, store, authority, process backend or runtime
preflight changes. Version 2.1 preserves M1's exact 2.0 enumeration, schemas and
examples rather than redefining shipped contracts.

An alternative trusts a receipt ID and producer-name allowlist. A worker could
copy an allowed name and fabricate content. Instead, a trusted approval pins the
exact receipt digest after the receipt exists. Receipts never include approval
digests, avoiding a cycle. Trusted approval ingestion/authentication is outside
this evaluator and must not use worker/profile data. Hashes alone do not prove
authority or truth.

An alternative invokes configurable resolvers during evaluation. That adds
ambient file/network/credential access and mutable responses. A bounded immutable
EvidenceStore instead holds explicitly supplied bytes. Installed schemas are
read-only package constants. Typed manifests bind exact subjects, expected and
observed facts, content references and required raw captures. Missing, changed,
revoked or mismatched evidence cannot satisfy a requirement.

Decisions bind build/runtime/host/backend/provider/model/policy/context, exact
mode, trusted policy and supplied UTC time. Receipt and approval expiry are
exclusive. Negative and unknown facts remain distinct. A signal does not prove
descendant cessation; local cessation does not prove remote accounting. Hard caps
need complete facts and the exact limit. Reports retain limitations and individual
nullable usage without inventing totals. Rotation preserves binding identity and
prior decisions.

Independent synthetic manifests test forgery, mismatches, expiry/revocation,
missing captures, native session identity, immutable records and packaged
resources. Every returned decision/report keeps production dispatch false,
including a scoped satisfied decision. Real provider proof and M4 admission are
separate gates. No runtime support follows from these data records.

No migration is needed because nothing is persisted. Additive readers can be
removed before adoption; future readers must preserve shipped 2.1 meanings or
introduce an explicit new version. V1 and all M1 resource hashes remain pinned.
