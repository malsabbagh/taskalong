# Experimental Claude wire component

This offline component is a preparation step for a future Claude driver. It has
no launcher, process control, provider profile, registry entry or production
admission. Installing it does not add Claude execution support. The existing v1
runtime profile still admits only Codex; production dispatch remains disabled.

The independent part implemented here is parsing bounded byte chunks into one
immutable, packet-bound worker result. Starting, observing and cancelling a real
CLI, proving every descendant stopped, and exact native resume require later
bindings/admission and actual per-mode qualification. Linux capability is not a
prerequisite for these offline tests; it remains a prerequisite for the intended
actual lifetime campaign. No host, CLI, credential or model is installed or chosen.

## Contract

`ClaudeStreamDecoder` requires a validated immutable v1 worker packet, an exact
expected session UUID and expected reported model string. `feed(bytes)` accepts
bounded UTF-8 JSONL. `finish(exit_code=0)` returns frozen `DecodedClaudeTurn` data
only after one initialization and one successful terminal structured output.
There is no text/code-fence extraction, repaired response or model fallback.

Every frame must carry the expected session. Reported models in initialization,
assistant/message-start frames and terminal model metadata must match. These are
untrusted wire reports, not proof of provider routing or resolution of a model
alias. Tools are likewise reported names, not an isolation or permission receipt.

The terminal worker document is independently schema-validated and matched to
packet/run/attempt/spec/digest/qualification inputs. Unknown permission metadata,
observed denial, provider errors, pending external tool work, unsolicited turns,
child sessions, wrong identities, nonzero exit, duplicate/missing terminals and
truncated streams cannot yield a result. Errors are sticky, safe for display,
and carry uncertain effect outcome because parsing cannot establish cessation.
The returned document supplies no acceptance, qualification or lifecycle proof.

Wire cost metadata is parsed as bounded Decimal, never binary float. Reported
cost is converted to integer micro-USD by exact ratio and rounding upward;
caller decimal precision/rounding cannot change it. Invalid/overflowing counters
are rejected. Missing usage remains null. Only terminal metadata is retained;
progress counters are not added again. The counter scope remains explicitly
unknown, so later resume/budget logic cannot assume per-invocation deltas. This
is neither measured billing nor a hard cost/token cap. Worker JSON remains strict
canonical JSON with no decimal/floating-point values.

The decoder bounds aggregate bytes (at most 8 MiB), line bytes (at most 1 MiB),
frames (at most 4096), nesting, collection size and numeric representation. These
stdout limits do not replace a future supervisor's aggregate stdout/stderr,
wall-time, cleanup or process-lifetime controls.

## Evidence and remaining dependencies

All tests are original synthetic frames, not recordings of an installed CLI.
No installed CLI version is qualified by these offline tests. Vendor documentation
describes evolving interfaces; documented flags cannot establish a binary's
tool/config isolation, auth behavior, model routing or lifetime.

Interface research used the official [programmatic CLI documentation](https://code.claude.com/docs/en/headless)
and [CLI reference](https://code.claude.com/docs/en/cli-reference), plus the
[official SDK type reference source](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/types.py)
and [wire-field reader](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_internal/message_parser.py),
read on 2026-10-22. They informed field semantics only: no vendor implementation,
SDK dependency, prompts, credentials or CLI captures were copied into the package.
Actual version-specific transcripts and compatibility remain unqualified.

The implementation deliberately uses a stricter subset: unknown event semantics
fail closed. Missing terminal denial metadata is unknown rather than evidence of
an observed denial. It does not promise forward compatibility with future events.

Before a future launcher can be registered, implement versioned semantic bindings,
immutable provider/model profiles and qualification admission; select an explicit
independent command sandbox; prove actual start/cancel/results and exact-session
resume if supported. Retain applicable protective policy, no silent fallback and
unknown-effect quarantine. Cross-harness continuation uses explicit artifacts and
a new session. MIT licensing does not qualify a live runtime; public publication remains a separate owner decision.
