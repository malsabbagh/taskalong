# Production Muse lifecycle behind exact runtime qualification

Status: proposed; implemented with production dispatch closed.

Version 2.12 adds production configuration, task, packet, projection, handoff and
read-only views. Store 12/SQL 012 is an explicit backed-up compatibility fence.
The actual pinned format 11 reader refuses 12 before journal mutation. All prior
schema/SQL bytes and v2.11 intent/preparation meanings remain unchanged.

The exact registry tuple is `2.12 / muse-production-plain/1 / driver_config / 2.12`.
RunService and Workflow retain authority, one attempt, reservations, exclusive
workspace fences, executor intent, closed-gate spawn observation, independent
verification and completion. No second scheduler, launcher, generic imports,
provider fallback, native resume or automatic retry is introduced.

A separate production admission module measures declared local inputs against
the existing v2.11 requested profile/configuration and binds the new exact task,
source base, budgets and independent-checker/reviewer identities. A v2.11
preparation cannot authorize a new 2.12 task digest. Local hashes remain identity
measurements rather than authentication or effective-input/isolation proof.

The production adapter uses the closed wonder-full/high projection and private
owned capture mechanics. Canonical packet/prompt bytes, original opaque streams
and raw owned receipts are retained exclusively. Shared neutral handoff mechanics
preserve the original 2.9 fixture semantics while production additionally binds
its exact authority and runtime subject across packet, projection and handoff.
An explicit prompt SHA256 binds the complete canonical bytes, distinct from the
sealed semantic digest. Stdout never becomes a vendor success, session or usage
claim. Typed complete cessation is required; unconfirmed results stay reserved.

Every prepare/spawn/capture/finish association comes from authoritative Store
operations and is rechecked before verification, acceptance, readback and reuse.
Recovery reuses committed completion only; ambiguous intent is never relaunched.
Caller-provided flags, settings, digests or fixture receipts cannot satisfy the
closed runtime authenticator. An imported run still rechecks current admission
before allocating an attempt or workspace. Independent review has an immutable
non-fixture provider binding; this selects no paid fallback and grants no access.

The reviewed native 1.4.10 contract has only model-step bounds, with no supported
aggregate observer/judge/subagent ceiling. Darwin's current owner proves only
non-forking lifetimes. Effective OS filesystem/network containment, authenticated
existing-account endpoint/model/included allowance and independent checker/review
qualification remain unsupported for this exact tuple. These are explicit runtime
boundaries, not omitted packet or lifecycle plumbing. No Muse/provider or reviewer
model call is made by registration, validation or refusal tests.

The next owner decision is to select an authorized runtime/host tuple that can
provide enforceable aggregate inference bounds and complete owned lifetime plus
actual containment/account/checker observations. Updating the pinned build or
adding access/terms/security changes requires its specific decision. No current
approval can turn a local hash or fixture into those missing facts.

Rollback preserves format 12 state with a compatible reader. Never lower version
markers, erase history, settle unknown effects or replay an interrupted invocation.
Tests cover public refusal, exact contract/compiler bindings, drift, old-reader
fencing and original fixture completion/recovery on format 12. These tests qualify
contracts, not actual Muse execution. Existing full installed/Windows/CI receipts
remain separate requirements; all eight CI lanes are preserved.
