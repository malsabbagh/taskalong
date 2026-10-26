# Immutable synthetic artifact handoff

Status: proposed for M11, issue #11. Live provider dispatch remains disabled.

M10's accepted 2.7 family supplies an ordered prefix of immutable completion
receipts, one Workflow/Store owner, conservative reservations and fenced
workspace recovery. Its task, packet and receipt meanings are unchanged. M11
uses explicit family 2.10, store format 11 / SQL011 and this ADR, as allocated
by Astra. Preserve all 78 inherited schema/SQL resources and any intervening
accepted additions, including Muse 2.9 and the separate experimental ADR0014.
Upgrade only through the existing exclusive, backed-up maintenance protocol.
The actual pinned format-10 reader refuses 11 before journal changes. Restores
remain quarantined; rollback never means lowering a version marker.

The alternative of filling future hashes into TaskSpec changes its authorization
identity. Selecting a latest output makes delayed attempts ambiguous. An output
catalog or another scheduler splits ownership. Instead the submitted task names
closed exact selectors and export declarations. Core resolves immutable outputs
only from designated completed producer attempts and retains separate sealed
`output_manifest`, `resolved_inputs` and `import_journal` documents.

The new family contains at most eight ordered required steps and two explicit
registered fixture routes. Each step names one exact route; no model, provider,
tier or credential fallback is selected. This version admits only existing
`codex-v1-fixture/1` and `claude-print-fixture/1` registrations, each independently
qualified through its original admission path. The outer owner conserves the
whole task budget while each route admits one bounded fresh invocation. The
independent check profile must agree across routes.

A selector is exactly `{kind:step_output,from_step_id,output_id,expected_kind,
max_bytes}`. It must name a strictly earlier step and one declared output.
Repository `{path,sha256}` inputs retain their immutable-base meaning. Unknown
versions, fields, modes, outputs, duplicate identities and expanded scopes refuse.
Task identity binds export declarations, exact target bindings, selectors and
disclosure destinations. Current Store authority must authorize the exact task
at preparation and dispatch. Export permission, target admission and destination
permission all remain necessary, including for every referenced patch payload.

Only strict UTF-8 text, including empty text, and a closed canonical JSON
`file_set_patch` are representable. Classification is `synthetic_fixture` only.
There are at most eight selectors/outputs per step, 1 MiB per artifact including
referenced payload volume, 8 MiB imported per target and 256 patch entries.
Strict JSON depth and document limits also apply. These are ceilings; tighter
task, packet, transport and workspace limits win. A syntactically valid artifact
does not authorize a larger packet or qualify that capacity on another driver.

A patch names literal add/modify paths, exact before SHA/size or absence, exact
after SHA/size, fixed supported mode and a declared text-output payload identity.
Envelope and referenced payload bytes both count. Destination collisions and
file/directory-prefix overlap across all selected patches refuse before writes.
No general Git patch parser, shell, embedded instruction execution, binary edit,
rename, deletion or mode change is introduced.

The producer manifest is admitted only under its current settled fence, after
authoritative local process cessation and scope/checkpoint validation. Worker
success claims, root exit, empty groups, missing PIDs and experimental foreground
completion cannot establish cessation. The manifest binds the exact completion
receipt **blob SHA-256**, packet/admission, route, base and checkpoint/content
digests. The blob content address differs from its embedded sealed-document
digest; validate both. An intermediate checkpoint is never called a candidate.

Target ownership, a fresh attempt/fence and no-refund capacity reservation precede
import effects. The new chain explicitly binds:

`producer receipt -> predecessor checkpoint -> committed import journal -> effective target start -> target attempt`

The old 2.7 equality edge is retained unchanged. Core checks import scope,
subsequent worker delta and cumulative task scope separately. A text-only import
still binds its resolution even when the candidate checkpoint is unchanged.
On retry, preserve the original import and first-start checkpoint; never reapply
the patch or select a newer producer output. Cancellation prevents target launch
and further import writes. Known before/after states may be observed and settled;
unexplained partial bytes remain blocked and are never overwritten by recovery.

Ingress, blob readback and staging use descriptor-relative no-follow bounded
regular-file reads, pre/post descriptor and entry validation, single-link and
owner checks. FIFOs are opened nonblocking and refused as special files. Patch
writes use held descriptors so entry replacement cannot redirect writes to a
foreign replacement. Fresh staging copies use generated paths under the owned
scratch directory, separate from control files, with mode 0400 and exact readback.
These checks reject observed changes and avoid following replacement links;
they do not prove every transient hardlink or same-inode concurrent writer never
existed. File modes do not establish isolation from a same-user process.

Resolution and import finish before executor intent or gate release. Reconcile
uses the existing supervisor lock and durable no-dispatch state, not a saved PID,
to resume an interrupted import with the same attempt, journal and reservation.
Unknown target dispatch keeps existing quarantine behavior. An orphan blob or
an unreferenced sealed document grants no authority. Store operation receipts
bind manifest attachment, import prepare/commit and actual executor effects.

The new canonical packet and mapping bind the full 2.10 task, step/attempt,
workspace/fence, exact admitted route/configuration, producer receipts, committed
import and ResolvedInputs. Existing compilers still produce their own distinct
2.2/2.3 canonical documents and wire construction; these are not relabelled.
Their bytes are retained and the new mapping binds their exact identities and
the emitted wire packet. Worker results must match that wire packet and map
back to the new canonical subject. Seal order is cycle-free: source receipt and
manifest, target import/resolution, new canonical packet, wire, then mapping.

Targets use fresh sessions and only selected artifacts plus immutable approved
task context. No source credential homes, native-resume tokens, transcripts or
hidden reasoning are copied. Distinct sessions, attempts, fences and artifact
hashes are exercised in both original synthetic driver directions. Actual
two-harness proof remains M12. Handoff never establishes correctness: complete
ordered receipts, current immutable inputs and the actual final candidate still
require independent commands and the pinned ReviewSensei review before acceptance.
No runtime branch/PR publication or production route is enabled.
