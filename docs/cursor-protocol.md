# Original Cursor fixture protocol

This is a deliberately narrow synthetic contract, not a transcript or a promise
of compatibility with installed Cursor. The closed tuple is task/config/wire/
result 2.5, `cursor-print-fixture/1`, `cursor-cli`, driver
`cursor-print-fixture-1` and installation `synthetic-cursor-1`. Installed help
informed the boundary; no live task, inference or account request qualifies it.

The fixture receives the exact canonical packet on stdin and starts with only
`--print --output-format stream-json --model synthetic-cursor-model`. There is
no session input, resume/latest/create-chat, force/yolo, trust, MCP approval,
endpoint/header or persistence option. The synthetic stdin convention does not
establish vendor packet support. Native resume refuses before launch.

Stdout is bounded strict UTF-8 NDJSON: at most 8 MiB combined with stderr and
the smaller trusted task limit, 1 MiB per line, 4096 frames and depth 32. Duplicate
keys, floats/nonfinite numbers, oversized integers, malformed nested types,
unterminated lines and extra/unknown fields refuse. The state machine requires
one first `system/init`, recognized events, one successful `result`, then EOF.
The init has a canonical UUID distinct from core run/attempt/packet identities
and model `taskalong-fixture-cursor-model`. Every later event repeats that exact
session; later supported model observations must agree.

Assistant/user text observations are never results. A terminal's `result` is a
string containing exactly one whole worker-result 2.5 JSON document. Prose,
fences, concatenated objects, missing fields and worker-supplied native sessions
refuse. The decoder neither extracts nor repairs output. Every core/config/
provider/packet identity and qualification must match the admitted packet.

The only write event is `tool_call` for `Edit` of an explicitly scoped path.
Started/completed pairs require matching unique call IDs, session, tool and
path. Failed, denied, duplicate, orphan, pending or unknown tools refuse.
Explicit errors refuse even with a plausible terminal and exit zero. This
fixture declares no benign stderr: any nonempty stderr prevents completion;
it is retained privately and never parsed as a result. Actual vendor diagnostics
need separate qualification. Nonzero exit, timeout, output limit, cancellation
or unconfirmed owned cessation cannot become a successful handoff.

The owned runner's optional trusted final-output callback freezes bounded
original bytes before redaction. Cursor's local closure only retains those
bytes; task/config data cannot select a callback. Ordinary ProcessResult and
other callers retain their redacted output. Capture-callback failure has its own
fixed error, with safe process/lifetime evidence, including on closed-gate
cancellation; missing originals never fall back to redacted text.

The driver returns immutable private stream bytes, untouched worker JSON and a
separate observation. The core consumes those bytes before serialization, stores
private unredacted content-addressed blobs, re-reads and independently decodes
them against frozen dispatch inputs, and persists a closed association bound to
the existing finish operation. Raw captures/native diagnostics are omitted from
public result, events and export. Private full-store backup includes them under
the existing maintenance contract. Hashes prove consistency, not independent
vendor or same-user attestation. Known prior observed-session reuse refuses;
no global uniqueness or cross-harness opaque-session transfer is claimed.

Restart and interrupted workspace reacquisition revalidate an exact completed
predecessor before consuming its checkpoint, even when the latest attempt is
only prepared. Settled-failed attempts retain their existing restart rules.
Restart after confirmed cessation uses a new attempt/session with retained
budget. Supervisor loss remains unknown and quarantined; captured bytes never
clear an uncertain effect. Token/cost totals remain unknown, not zero. Real
Cursor editing, model routing, instruction/tool/config isolation, complete vendor
lifetime, remote effects and production remain unqualified and disabled.
