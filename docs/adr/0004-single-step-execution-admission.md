# Single-step execution admission

Status: proposed for review in the M4 PR.

M1 describes immutable installation/provider/binding identities; M2 evaluates
explicit trusted evidence; M3 supplies backed-up maintenance and immutable history.
M4 connects those boundaries to the existing single Workflow lifecycle. It does
not introduce another scheduler, supervisor, authority owner or process backend.

One alternative adds a second v2 Workflow/Store. Duplicating cancellation,
reservations, recovery and acceptance would create competing state owners.
Another embeds all policy resolution in Workflow. A focused admission module
instead resolves exact content, current trusted evidence and an explicit bounded
projection; Workflow retains transactional intent, leases, fences and effects.

Version 2.2 adds task/packet/evidence/policy and read-only view resources without
changing v1 canonical bytes or the exact 2.0/2.1 resource sets and meanings.
`read_task_spec` selects an explicit version and never upgrades a legacy task.
Worker and independent verifier profiles/sandbox policies are separately bound.
Instructions, tools, sandbox and check records resolve by digest and type, never
the latest revision under a mutable identifier. Stored decisions remain historical
evidence; only the current operator-supplied trust snapshot can satisfy admission.

The first projection, `codex-v1-fixture/1`, is limited to an explicit trusted
registration of a synthetic executable and verifier launcher. It accepts empty
additional instructions, the exact fixture tool policy and fixture-only sandbox
backend. The requested provider declaration is retained as simulated input;
actual transport is an operator-registered local fixture. No real endpoint,
credential, account, model, tool isolation or OS containment is qualified. Merely
setting `qualification=synthetic` on task JSON does not register this projection.
Unrepresentable policies, missing documents, unknown drivers, unsupported modes,
non-null token/cost limits and unsatisfied capabilities fail closed. All binding
requirements remain mandatory under the exact M2 mode; native-resume requirements
cannot borrow start evidence. Explicit restart is a fresh start protocol attempt,
with the existing checkpoint, cessation and budget prerequisites; native resume
remains unsupported for this projection.

Canonical task identity binds authority. Preparation stores exact resolved
documents, a qualification decision, policy/projection identities and authority
identity in the same transaction as reservation, lease, event and workspace intent.
Dispatch rechecks current authority, revocation, executable bytes and policy.
The existing owned process gate performs a final check before target execve.
The canonical packet is frozen first, then the v1 wire packet, then an explicit
mapping binding both identities to the attempt. This ordering avoids digest
cycles. The wire worker result must match the exact mapped packet and actual
changed files. It remains worker evidence. Independent verifier records retain
their existing v1 acceptance path and gain immutable 2.2 evidence projections.

Older clients read familiar task/attempt dictionaries without enforcing new
restrictions. An advisory extension beside a v1 projection is therefore
insufficient. Explicit numbered SQL003 creates immutable projection registrations
and advances the store to format 3. Byte-pinned predecessor clients reject that
format before interpreting executable state. The quiescent maintenance boundary
requires a complete private backup and verified quarantined restore first. No
ordinary open, inspect, v1 run or read-only query upgrades a store. SQL001/002 and
their receipts remain unchanged. A format-2 store must explicitly upgrade to 3
before storing executable 2.2 task/policy/registration state.

Rollback preserves format-3 state and backups; older clients cannot open it.
Restores remain quarantined and cannot be promoted by this change. Removing the
new code is not a downgrade/migration strategy. Shipped document meanings and
immutable histories must remain readable by a compatible version.

Tests observe public submission, authorization, one supervised fixture invocation,
independent acceptance, cancellation, idempotency and read-only views. Refusal
cases cover revocation before intent/dispatch/gate release, expired authority,
changed executables, unrepresentable policy, unsupported budgets/modes and old
reader exclusion. Linux/macOS installed artifact qualification remains distinct
from actual vendor runtime/provider proof. Production dispatch stays disabled.
