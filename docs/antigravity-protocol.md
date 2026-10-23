# Original Antigravity fixture protocol

This is an original synthetic dialect, not an observed vendor transcript. The
explicit tuple is task/config/packet/projection 2.6,
`antigravity-headless-fixture/1`, `antigravity-cli`, driver
`agy-headless-fixture-1`, installation `synthetic-agy-1`. It reuses the unchanged
neutral worker-result 2.5 resource. No real account, model or service is called.
Installed agy 1.4.0 help/version informed the boundary; no installed start,
structured-output enforcement, context isolation or conversation persistence was
qualified. The [headless documentation](https://antigravity.google/docs/cli/headless/)
is a separate vendor description, not evidence that this fixture is compatible.

The transport is exactly one UTF-8 NDJSON envelope followed by newline and EOF:
`{"type":"user","message":{"role":"user","content":"<canonical packet JSON>"}}`.
The content string is the complete canonical packet, extracted losslessly. The
packet digest and framed-input SHA256 are distinct identities. Private capture
records the intended input bytes supplied to the owned runner; only a successful
fixture's invocation observation proves that it consumed that wrapper. A closed
gate does not imply delivered input. There is no second turn or control message.

Fixed fixture arguments select stream-json input/output, `fixture-agy-model`,
the exact neutral result schema, a positive `Ns` print timeout no larger than the
remaining attempt, disabled slash commands and sandbox. No prompt flag,
conversation ID, resume/continue, agent selection or permission bypass is used.
The timeout syntax is the fixture's explicit contract, not a vendor guarantee.
The core absolute deadline and owned termination windows remain unchanged.

Stdout is strict UTF-8 NDJSON: aggregate output is at most the smaller task limit
and 8 MiB, each line at most 1 MiB, 4096 frames and nesting depth 32. Duplicate
keys, floats/nonfinite or oversized numbers, truncated lines, unknown shapes and
anything after the result fail closed. Init reports an independent canonical
conversation UUID, exact model/tools/request-review mode/cwd/schema and fixed
fixture agent. It cannot substitute a core run/attempt/packet ID.

Each `step_update` has a bounded index, immutable kind/tool/path identity and
ACTIVE updates followed by one DONE. DONE without ACTIVE and index gaps are
allowed. Duplicate DONE, updates after DONE, identity changes, unfinished steps,
extra user turns, subagents and remote jobs refuse. Only scoped `write_file`
observations are admitted; tool names must agree and error/permission denial is
sticky. Text is never a worker result. A terminal SUCCESS requires integer
`num_turns: 1`, matching conversation, no error and one complete object in
`structured_output`. Response text never supplies a fallback. The worker itself
echoes every core binding, without any injected native session.

Any stderr, including a benign warning or an exit-zero denial, refuses success
as `agy_diagnostics_unqualified`. The fixture deliberately has no benign
diagnostic classification. Unknown diagnostics are not silently accepted.
Terminal usage is a nullable reported cumulative snapshot; step counters are not
summed into it and missing terminal counters stay unknown. The core independently
re-decodes counters before retaining them. They do not establish billing truth,
hard caps, refunds or a reset of the conserved attempt budget.

Private original stdin/stdout/stderr references, observed conversation, model,
packet/mapping/admission/config/provider/generation and result hashes are bound
to the fenced finish. Core revalidates them at dependent reads, verification and
recovery. Public results/events/exports omit raw capture bytes. A valid stream
cannot clear uncertain cessation or effects. Shared capture code preserves all
2.5 field/error/finish meanings; no Cursor or Claude parser is reused here.

Restart uses a fresh attempt/conversation only after confirmed owned cessation
and clear effects, preserving budgets and refusing known prior conversation
reuse. Native resume, provider lookup, remote cancellation, arbitrary tool or
instruction isolation, hard token/cost enforcement and production remain
unsupported. Sandbox flags and private fixture HOME/config directories are not
evidence of real vendor containment. There is no credential lookup or fallback.
