# Architecture

RunService and its thin CLI own durable task lifecycle operations, SQLite
state/events, explicit authority, fenced worktrees and independent acceptance.
An internal closed registry selects the worker driver; independent commands have
a separate sandbox seam. Explicit versioned Codex and Claude fixture contracts
are registered; both refuse production while actual runtime qualification is
incomplete. No task-selected imports, arbitrary vendor flags or fallback exist.

Worker results are untrusted data bound to exact packet, task, attempt and
candidate inputs. Deterministic checks and independent ReviewSensei evidence
cannot be replaced by a worker's success claim. External effects have durable
intent and observation; ambiguity keeps the worktree reserved. A heartbeat,
signal, PID disappearance or empty group is not complete descendant proof.

The offline Claude wire component validates synthetic framing and structured
results only. It does not launch, observe, cancel or resume a real CLI. Provider
profiles and versioned semantic bindings now have offline v2 data contracts;
offline qualification evidence has separate v2.1 contracts and a pure evaluator.
Immutable store history now retains these definitions and historical decisions;
durable admission supports explicit synthetic projections; live provider execution
remains unqualified.
Cross-harness continuation must use explicit immutable artifacts and a
new session; opaque sessions are not transferable. No scheduler or task DAG is
provided.

`taskalong.bindings` describes installation identity separately from provider
selection and immutable policy references. Explicit version-aware readers do
not resolve references, look up credentials or register drivers. The proposed
[semantic contracts ADR](adr/0001-semantic-execution-documents.md) records this
boundary and alternatives; [contract examples](contracts.md#offline-semantic-documents-v2)
show the installed resources. V1 lifecycle/store contracts remain unchanged.

The [contracts](contracts.md), [operations](operations.md) and
[qualification](qualification.md) describe executable behavior and limits. All
runtime/acceptance rules remain in effect regardless of repository visibility.

The [offline qualification ADR](adr/0002-offline-qualification.md) describes exact
subjects, explicitly trusted approvals and bounded evidence snapshots. This
evaluator changes no lifecycle or runtime admission; every report keeps production
dispatch disabled. See the [offline example](contracts.md#offline-qualification-v21).

The proposed [maintenance ADR](adr/0003-quiescent-store-maintenance.md) describes
explicit format-2 migration under exclusive ownership, complete private control
backups and quarantined fresh-directory restores. Stored decisions grant no
current authority. The [operations guide](operations.md#quiescent-store-maintenance)
describes the operator API and failure boundaries.

The proposed [single-step admission ADR](adr/0004-single-step-execution-admission.md)
connects exact immutable bindings and current trusted qualification to the same
Workflow, supervisor, reservations and fences. It adds an explicit 2.2 contract
family, independently bound verifier policies, a synthetic Codex wire projection
and read-only capabilities/result views. Explicit format 3 excludes older clients
before executable v2 state is interpreted. No new harness, scheduler or production
dispatch is introduced.

The [Claude fixture ADR](adr/0005-claude-fixture-driver.md) adds a separate 2.3
DriverConfig and exact registry contract to the same lifecycle. Explicit format 4
excludes predecessor clients before executable driver state. The original external
fixture exercises protocol, cancellation and restart; actual CLI execution,
routing and isolation remain unqualified and production remains disabled.

The [Ollama fixture ADR](adr/0006-ollama-fixture-profiles.md) adds one explicit 2.4
contract descriptor to that same Claude driver, with four additive resources
and a backed-up format-5 fence. A pure route plan plus exact capture linkage and
two current exact-mode decisions admit only offline local/direct-cloud fixtures.
The unchanged binding is evaluated in full in both modes. No fifth executor,
provider daemon, HTTP transport or production dispatch is introduced.

The [Cursor fixture ADR](adr/0007-cursor-fixture-driver.md) adds an independent
2.5 driver/decoder to the same lifecycle. It observes a fresh native session
separately from untouched worker JSON and binds exact private captures to the
fenced finish operation. Format 6 excludes predecessor clients. This synthetic
protocol does not qualify actual Cursor execution or enable production.

The [Antigravity fixture ADR](adr/0008-antigravity-fixture-driver.md) adds the
independent 2.6 driver/decoder and four schemas while reusing neutral result 2.5.
A frozen descriptor in the same closed registry selects shared private capture
validation without changing 2.5 meanings or adding another lifecycle. Format 7
fences executable conversation state. Exact input/output and reported usage are
rechecked by core. This original fixture does not qualify actual agy execution.

The [runtime experiment ADR](adr/0009-runtime-experiment-evidence.md) adds a
closed no-inference host-canary tool and pure bounded proof/replay readers.
It reuses the existing process owner, preserves original private captures and
separates original proof subjects from installed replay-verifier identity.
There is no new launcher, Store format, M2 trust authority or production path.
