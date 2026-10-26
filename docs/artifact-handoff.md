# Immutable fixture artifact handoff

M11 adds explicit 2.10 ordered-task contracts for synthetic Codex/Claude artifact
handoff. It requires explicit backed-up store format 11. Existing 2.7 tasks still
use one fixed fixture and reject future-output selectors. Actual provider or
cross-harness qualification remains separate in M12; this feature cannot enable
a live route or publish a branch/PR.

Use the existing trusted `RunService.configure_execution` registration path for
each exact original fixture. Registration is separate from task authorization.
The task's execution object lists one or two exact route records:

```json
{
  "routes": [
    {
      "route_id": "target-fixture",
      "binding_digest": "EXACT_REGISTERED_BINDING_SHA256",
      "configuration_digest": "EXACT_REGISTERED_CONFIGURATION_SHA256",
      "disclosure_destination_id": "EXACT_REGISTERED_DESTINATION"
    }
  ],
  "check_route_id": "target-fixture"
}
```

The uppercase placeholders are explanatory; a submitted task requires actual
64-character lowercase hashes. Top-level permissions list the exact
`disclosure_destination_ids`. Each step adds `route_id`, `outputs` and
`import_scope` to the ordered step shape. An export declaration is explicit:

```json
{
  "output_id": "note",
  "artifact_kind": "utf8_text",
  "path": "handoff/note.txt",
  "max_bytes": 4096,
  "classification": "synthetic_fixture",
  "allowed_target_binding_digests": ["EXACT_TARGET_BINDING_SHA256"],
  "allowed_disclosure_destination_ids": ["EXACT_TARGET_DESTINATION"]
}
```

The producer path must fit its step edit scope. A later step's `inputs` may
contain this closed selector:

```json
{
  "kind": "step_output",
  "from_step_id": "A",
  "output_id": "note",
  "expected_kind": "utf8_text",
  "max_bytes": 4096
}
```

Selectors never name a path, URL, latest attempt or fallback. Existing repository
inputs remain `{path,sha256}` and bind the original repository base. Core keeps
the submitted task bytes unchanged and resolves a separate immutable input
document only after the designated producer's actual cessation and completion.
Missing, wrong-kind, changed, undeclared or unauthorized inputs block the target.

Use the same public CLI flow as the [ordered fixture](ordered-tasks.md):

```sh
taskalong --state-dir STATE validate --spec handoff.json --json
taskalong --state-dir STATE submit --spec handoff.json --key submit-handoff --json
taskalong --state-dir STATE authorize RUN_ID --decision-digest SPEC_DIGEST \
  --scope execute verify commit_candidate --json
taskalong --state-dir STATE start RUN_ID --key start-handoff --expected-revision REVISION --json
taskalong --state-dir STATE status RUN_ID --json
taskalong --state-dir STATE advance RUN_ID --step-id B \
  --predecessor-digest A_RECEIPT_BLOB_SHA256 --key advance-handoff \
  --expected-revision CURRENT_REVISION --json
taskalong --state-dir STATE result RUN_ID --json
```

Status/result reads never launch or reconcile work. New result views include
immutable resolution/import/packet references in `handoffs`; source bytes,
credentials and sessions remain private. A worker completing B is not acceptance.
Only the complete receipt chain and exact candidate, independently checked and
reviewed, can report `independently_accepted: true`.

`file_set_patch` is a sealed 2.10 JSON document, not a Git patch or a script. Its
bounded `files` records bind literal destination, add/modify operation, exact
before SHA/size or absence, after SHA/size, supported unchanged mode and
`payload_output_id`. That payload must itself be a declared allowed UTF-8 output
from the same producer. Core journals and applies exact authorized writes before
the target starts. Imported and worker edits have separate scope checks.

An interrupted import retains its owned workspace and reservations. Use explicit
`reconcile`; it may finish only exact known journaled writes. Foreign or partial
bytes that match neither before nor after remain blocked. Retry retains the
original import and receipt identities. Cancellation prevents target launch and
new final checks. No charge is refunded merely because an import or worker failed.

The original shared contract runner exercises both synthetic directions:

```sh
PYTHONPATH=src:tests python -B -m unittest \
  test_artifact_handoff test_artifact_import test_artifact_io test_artifact_store \
  test_steps test_evidence test_scope test_acceptance test_crash_recovery -v
```

`test_steps` forwards explicit milestone commands to `test_ordered_tasks`;
ordinary test discovery includes that suite once. Reviewer-required cases need
the checksum-verified released 0.8.8 reviewer selected through
`TASKALONG_REVIEW_EXECUTABLE`; core-only runs explicitly withhold acceptance.
The [ADR](adr/0015-immutable-artifact-handoff.md) records ownership, compatibility,
limits, no-follow behavior and the exact qualification boundary. See also
[installed qualification](qualification.md).
