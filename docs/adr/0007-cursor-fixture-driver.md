# Cursor fixture with observed sessions and private capture association

Status: proposed for review in M7.

Add one closed registry tuple for `cursor-print-fixture/1` and five 2.5 resources.
Use a separate CursorCLI and bounded Cursor decoder, preserving the same durable
Workflow, Store, owned runner, admission, independent checks and budgets. Do not
subclass Claude framing or infer capabilities from binary discovery. Preserve
all earlier schema/SQL bytes and explicit reader meanings.

Cursor-shaped initialization observes a fresh native ID rather than accepting a
preassigned one. The 2.5 packet/mapping use `session_policy: fresh`; worker-result
2.5 contains complete core identities without a manufactured native session.
The original external fixture allocates a distinct UUID. Model display text and
synthetic resolved identity remain separate. No session/model field is repaired
into the worker result. Native continuation and cross-harness transfer refuse.

The runner exposes an optional trusted pre-redaction callback only to in-process
code. Cursor supplies a local bounded assignment closure; task/config cannot
select it. Existing ProcessResult/to_dict defaults remain redacted. A distinct
capture-callback failure preserves actual cleanup evidence and cannot be hidden
by an earlier closed-gate cancellation. No original data is reconstructed from
redacted output.

Retain actual bounded immutable stdout/stderr bytes in private blobs before
finalization. The core independently re-decodes retained stdout under the frozen
dispatch context and checks worker/observation identity, process accounting and
confirmed cessation. A closed association binds packet/mapping/admission,
config/provider, session/model, stream references and result artifact. Its digest
enters the fenced finish request and checkpoint. Check exact active attempt and
generation and known prior session reuse inside that transaction. Revalidate
completion at result, verification/acceptance and dependent recovery/publication.
This includes the exact completed predecessor at restart reservation, supervisor
dispatch and interrupted generation reacquisition; the latest prepared attempt
does not substitute. Failed/nonzero restart keeps its separately proved cessation
and checkpoint rules. A 2.5 failed finish records its blocker once, so its old
supervisor cannot overwrite a newly prepared restart with a redundant blocker.
Missing/corrupt capture refuses; a valid stream cannot establish cessation or
authority. Crashes before finish leave orphan blobs and existing uncertainty.

SQL006 is a format5-to-6 compatibility fence only, with no new table or lifecycle.
Use existing explicit quiescent full backup/restore and immutable numbered
history. Pin the actual accepted format5 predecessor and require its refusal
before journal mutation. Restore only into an admissible empty destination;
never decrement a marker or reinterpret executable state with an old client.

The original fixture's fixed account/model/endpoint declaration performs no
network or credential lookup. Its Edit events and private HOME do not prove
vendor permissions, project instructions/hooks/MCP isolation or actual edits
without force. Current trusted qualification remains exact-mode and is checked
at every existing gate; persisted observations never become current authority.
No fallback, live inference, production or package publication follows M7.
