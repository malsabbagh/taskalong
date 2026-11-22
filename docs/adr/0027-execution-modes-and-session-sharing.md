# ADR 0027: Execution backends and session sharing

Status: proposed. Tracks [issue #30](https://github.com/malsabbagh/taskalong/issues/30).

## Decision

Direct execution on the current machine is the default. The operator selects
the installed CLI and uses its supported existing sign-in. Local Docker,
remote Docker and session sharing each require explicit selection and their
own qualification. A failed selection returns a typed blocker and leaves the
selected backend, CLI, model, account and billing route intact.

| Capability | Default | Admission boundary |
| --- | --- | --- |
| Direct local CLI | Enabled for supported configured experimental routes | Pin the executable, installation closure, CLI version, adapter configuration and observed local lifecycle capabilities. |
| Local Docker | Off | Select a qualified image by digest, a compatible embedded CLI, a disposable workspace and an explicitly supported authentication route. |
| Remote Docker | Off | Pin a separately authorized host and image digest. Require an explicit file allowlist, independent job ownership and demonstrated isolation and cleanup. |
| Session sharing | Off | Authorize a specific source session or artifact selection, named destination, owner and expiry independently of backend and account selection. |

The adapter owns the exact native invocation, input/output protocol and
continuation semantics. The backend owns workspace preparation, process identity,
observation, cancellation and cleanup. TaskAlong's control plane retains the
immutable task, checks, acceptance, operation keys, budgets, lease and effect
journal. Qualify each adapter/backend pair against those existing boundaries.

## Workspace and result lifecycle

An execution selection binds its measured runtime and backend to the approved
task, declared input hashes, write scope, destination and required limits before
any submission. Renew proof when those identities drift. Stage only the
allowlisted bytes in a fresh workspace. Retain verifier tools, controller state
and checkout history outside worker write authority.

Docker workspaces receive explicit inputs and a bounded result channel. Exclude
host home mounts, native credential stores, controller sockets and unrelated
repository data. The selected container authentication mechanism requires its
own grant. Local native login remains with the installed CLI. Any remote
qualification must document what the host operator can inspect and prove
parallel jobs cannot share workspaces, sessions or controls.

Record direct-child exit, process-group cessation, descendant cessation and
remote-provider settlement separately. Keep the lease and pending effects held
when required cessation or cleanup remains unknown. Bind independent tests and
review to the actual task, execution identity and candidate after writer
cessation. Apply the selected wall, output and invocation limits before launch.
Require enforceable hard usage limits when the task declares them.

## Session and artifact authority

Use an explicit grant scoped to the source identity, content selection,
destination, owner and retention period. A grant expires or can be revoked
before subsequent access. Delivered copies remain subject to the destination's
retention and deletion policy. A grant conveys only access to the selected
content. Runtime authentication, tool and publication permissions remain under
their existing authorities.

Native continuation requires exact same-CLI/session compatibility evidence and
exclusive session ownership. Use the immutable handoff contract for sanitized
cross-CLI context. Its consumer starts a fresh session with its own binding.
Store hashes, identity and revocation evidence separately from shared content.

## Qualification and delivery order

1. Qualify the exact local configured CLI route with a bounded coding block,
   independently checked proposal and observed start, result, cancel and
   writer-cessation behavior. Keep unknown outcomes explicit when a CLI forks.
2. Qualify one local Docker image and its supported separate authentication
   route using the same fixture. Exercise missing authentication, cancelled
   jobs and bounded capture before offering a live route.
3. Qualify selected-content sharing and expiry/revocation separately. Exercise
   unauthorized destinations and unsupported native continuation before export.
4. Qualify remote Docker on an existing approved host. Run overlapping jobs and
   verify input isolation, cancellation, cleanup after interruption and
   destination-scoped authentication.

Report exact host, CLI, image and configuration identity with each outcome.
Require a typed refusal before the relevant effect when the backend, authentication,
approved destination or required lifecycle proof is unavailable. Keep the
execution-mode acceptance criteria open until those observed results exist.

## Current evidence

- Configured experimental Muse has a bounded real macOS proposal trial and
  manual review. It is separate from production and strict descendant
  qualification. [Implementation and evidence](https://github.com/malsabbagh/taskalong/pull/38)
- The strict Darwin path quarantines an observed fork. Experimental foreground
  mode records the weaker process observations it can establish.
  [Darwin process design](0014-experimental-darwin-foreground.md)
- The tracker records inert Docker checks. A qualified coding image/authentication
  pair, remote-job isolation evidence and session-sharing implementation are
  outstanding. [Execution-mode tracker](https://github.com/malsabbagh/taskalong/issues/30)
- M11 proves synthetic immutable artifact transfer in both directions. M12
  tracks the actual two-harness proof and the separate E1 trial.
  [Artifact handoff](../artifact-handoff.md) · [M12](https://github.com/malsabbagh/taskalong/issues/12)
