# Antigravity fixture on the shared observed-session lifecycle

Status: proposed for review in M8.

Add the explicit 2.6 Antigravity tuple, four additive schemas and an independent
driver/decoder. Reuse byte-identical worker-result 2.5, rather than manufacturing
a result version or native session field. Installation/provider/policy identities
remain separate immutable facts. The original fixture uses a synthetic
google-account reference and fixture.invalid endpoint; neither is dereferenced.

Choose one fixed user-envelope NDJSON transport, not prompt/continuation modes.
Keep canonical packet and wrapper identities separate. Observe a new conversation
from init and require it throughout step/result events. Enforce bounded, strict
framing, immutable step identities, sticky errors/denials and whole structured
output. Any stderr refuses success. Report cumulative-looking counters once as
untrusted observations; do not sum them or reinterpret them as enforced budgets.
See the [protocol](../antigravity-protocol.md) for the exact fixture subset.

Extend the existing closed registry with a frozen capture descriptor. Move shared
private retention/revalidation into a neutral helper, retaining the 2.5 Cursor
entry points and all shipped fields, labels, error codes, schema/SQL bytes and
finish-request meanings. Antigravity does not import or subclass another vendor's
parser/driver. There is still one Workflow, Store, supervisor, owned process
runner, authority/evidence gate, reservation budget and independent verifier.
No task selects imports, callbacks or transport code.

Core separately re-decodes exact private captures and binds observed conversation,
intended framed input, immutable packet/mapping/admission/config/provider,
generation, reported counters and result artifact. Known prior conversation reuse
and corrupt completed predecessors refuse at the existing gates. Captures are
consistency evidence, not authority, vendor isolation or proof of delivered input
when a gate never released. Uncertain lifetime/effects remain quarantined.

SQL007 is a numbered format6-to-7 compatibility fence, with no new tables or
historical rewriting. Require exclusive quiescent maintenance, complete verified
private backup and fresh quarantined restore. Pin the accepted format6 Store and
prove that it refuses format7 before journal mutation. Preserve prior resources,
receipts and immutable history. Rollback means verified fresh-directory restore,
never decrementing a marker or overwriting current state.

Alternatives rejected: treating help/version as live qualification, borrowing
Claude/Cursor protocol semantics, preassigning/resuming a conversation, accepting
exit zero or response prose as success, permitting unknown stderr, summing usage,
and adding a second launcher or lifecycle. Native continuation needs its own
future exact-mode proof; start evidence cannot grant it. Production dispatch and
registry publication remain disabled/separate. No real inference is introduced.
