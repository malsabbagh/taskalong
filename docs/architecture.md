# Architecture

RunService and its thin CLI own durable task lifecycle operations, SQLite
state/events, explicit authority, fenced worktrees and independent acceptance.
An internal closed registry selects the worker driver; independent commands have
a separate sandbox seam. Only the existing Codex v1 driver is registered, and
its production preflight always refuses while actual runtime qualification is
incomplete. No task-selected imports, arbitrary vendor flags or fallback exist.

Worker results are untrusted data bound to exact packet, task, attempt and
candidate inputs. Deterministic checks and independent ReviewSensei evidence
cannot be replaced by a worker's success claim. External effects have durable
intent and observation; ambiguity keeps the worktree reserved. A heartbeat,
signal, PID disappearance or empty group is not complete descendant proof.

The offline Claude wire component validates synthetic framing and structured
results only. It does not launch, observe, cancel or resume a real CLI. Provider
profiles, versioned semantic bindings and evidence-backed admission are future
work. Cross-harness continuation must use explicit immutable artifacts and a
new session; opaque sessions are not transferable. No scheduler or task DAG is
provided.

The [contracts](contracts.md), [operations](operations.md) and
[qualification](qualification.md) describe executable behavior and limits. All
runtime/acceptance rules remain in effect regardless of repository visibility.
