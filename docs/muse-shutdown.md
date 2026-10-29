# Muse shutdown and recovery execution plan

The local portion implements practical usage exposure containment. The complete
whole-process boundary still needs an approved Linux host and actual tests.
Production remains closed. No vendor-wide cessation guarantee is demanded.

## Implemented local controls

Explicit backed-up Store13 maintenance adds append-only exposure history.
Production2.12 attempts reserve one slot before allocation commits, record possible
gate release before the target can execute, and retain exact local finish
observations. A crash, cancellation, timeout or output overflow cannot clear a
possibly released remote exposure. Even completed local execution leaves usage
unknown until an authentic settlement path exists; none is implemented here.
An authoritative never-prepared/unreleased attempt may record not_sent.

`taskalong --state-dir STATE --json muse-exposure` inspects this history without
launching, retrying, settling or modifying it. The existing cancel command requests
owned local cancellation. On this Mac, observed forks retain uncertainty; do not
signal a stored PID or promote disappearance to complete cessation.

One potentially dispatched invocation holds every later Muse slot in that Store,
including another task/profile/destination alias. This is a controller limit,
not an account-wide cap and not a bound on remote tokens/cost. Local elapsed time,
output bytes and main-model steps are separate limits. A request for hard
aggregate token/cost enforcement remains unsupported. Unknown remote usage must
not be reported as zero or as a successful provider cancellation.

## Exact host action awaiting approval

Use an owner-approved disposable Ubuntu24.04 Linux host with systemd255+, unified
cgroupv2 and an existing Python3. Do not provision a paid host or install software
by implication. With specific owner approval, copy the reviewed
[unit](proposals/taskalong-muse-model-free.service) and
[original helper](../tests/fixtures/muse_owned_tree.py) to root-owned paths on
that host, then run its model-free cases. No Muse install, credential transfer,
account access or network/inference change is included in this approval request.

The unit uses a dedicated nondelegated cgroup, a dynamic unprivileged identity,
read-only/inaccessible host controls, no capabilities/new privileges, private
network/tmp, Restart=no, ExitType=cgroup, RuntimeMaxSec=5, and bounded INT-to-KILL
stop. The system manager enforces the runtime even if the controller dies.
The service/helper are preparation files: they have not been applied or qualified.
A real invocation must use a fresh unique unit name and bind manager InvocationID,
verified effective properties and control-group path to the controller journal.
Unit text alone is not evidence that a kernel/controller supports these controls.

Qualification must observe cgroup membership and populated=0 after root exit,
fork+setsid, ignored INT/TERM, suspended child, controller loss and explicit stop.
No old campaign is replayed. Missing/changed InvocationID, unavailable hierarchy,
manager errors, late/unknown child or lost receipt fail and retain exposure.
The helper prints only model-free case/role facts; it contacts no provider.

After actual containment passes, implement the trusted runtime observer and bind
the exact existing account/endpoint/model/allowance and independent checker.
Select any required Linux Muse build or account cap change separately for
specific approval. A later allowance snapshot is observation, not a spending
ceiling or remote cancellation receipt. No new grants, fallback or automatic
provider retry is authorized. Only then consider one disposable public CLI turn
with wonder-full/high,<=60seconds,<=1MiB output and one retained exposure slot.

## Recovery and remaining boundaries

Keep local cessation, remote usage and financial settlement as separate facts.
The two earlier installed campaigns have no currently observed matching process,
but their original descendant cleanup remains unconfirmed. This plan and a new
host test cannot settle those histories. Preserve2origins/14holds and failed logs.

A stopped local service cannot cancel a request the provider already accepted.
Use supported vendor cancellation if available; absent authenticated completion,
retain remote uncertainty and prohibit redispatch. Neither this plan nor approval
can turn missing observations into facts. A new Store or direct client is outside
the per-Store limit and must not be used to work around an unresolved exposure.

Official systemd255 references: [service lifetime](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html),
[group termination](https://www.freedesktop.org/software/systemd/man/255/systemd.kill.html),
[execution isolation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html).
