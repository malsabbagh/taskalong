# Durable Muse exposure and practical shutdown

Status: proposed; local ledger implemented, whole-process host pending approval.

The user authorizes practical enforceable local/account controls, preserving
unknown accepted remote usage. An absolute vendor cessation promise is not an
admission requirement. No unsupported hard token/cost ceiling is inferred.

Select the existing Store/Workflow transaction as the exposure owner rather than
an adapter-local file/counter or another scheduler. SQL013 adds append-only
history under explicit backed-up format13. The pinned actual format12 reader
refuses13 before journal mutation; all older resource bytes remain unchanged.

Production2.12 preparation reserves a global single-exposure slot in the same
transaction as its authoritative attempt. The owned gate callback records a
possible release before returning to run_bounded. A crash after that commit can
only retain exposure; absence of process/response/usage does not refund it.
Exact run/attempt/config/runtime and owned process/capture identities bind events.

Durable finish keeps local and remote outcomes distinct. Typed complete local
cessation can record local_stopped while remote usage stays unknown. Only an
unreleased attempt with authoritative not-dispatched/no-prepare/no-process proof
can record not_sent. No public reset, settlement, PID-kill or retry control is
added. The read-only muse-exposure view cannot grant execution. Changing a
profile, task or destination alias cannot obtain a second local slot in the
same Store while exposure remains held. Other stores/manual clients are outside
this controller limit; it is not an account-wide spending ceiling.

Compare placements: adapter-local state cannot atomically cover attempt creation,
gate release and recovery; core transactional state can. A global account broker
would need authenticated account identity and control over all other clients,
which are not supplied here. The conservative per-Store single slot is useful
without claiming either capability. No task can select an observer or import a
authenticity receipt to open the existing closed runtime gate.

Keep the existing Darwin fork quarantine and local INT/TERM/KILL escalation.
A disposable Linux system service with a nondelegated cgroup, distinct dynamic
UID, read-only control hierarchy, no new privileges, ExitType=cgroup, Restart=no
and an independent finite runtime is the proposed whole-process boundary.
Local root/group/PID disappearance alone never proves it. Actual manager unit
InvocationID plus cgroup-empty observation must bind the exact owned job.
The candidate and its model-free fork/setsid/ignored-signal cases are reviewable
in ../muse-shutdown.md; applying them needs specific host/security approval.

Tests exercise transactions, concurrent reservations, immutable history,
closed-gate crash uncertainty, typed observations, reopen/no replay and actual
predecessor refusal without granting a production fixture. No Linux qualification
or vendor/account cap follows from those tests. Existing8CI/Windows lanes stay.
Rollback preserves13 state with a compatible reader; never lower markers,
rewrite history, settle unknown remote usage or relaunch an uncertain turn.
