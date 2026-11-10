# Prepare a two-harness handoff campaign

`tools/qualify_handoff.py` validates a bounded manifest and its local evidence
snapshots. It is preparation only: it cannot start a campaign, reserve a provider
submission, run task checks, open a Store, register trust or change durable state.
There is no actual campaign invocation or `--execute` mode. This slice does not
complete issue #12/E1 or qualify an actual route.

The [public example](examples/handoff-campaign/campaign.json) is generated from
the synthetic fixture in [the campaign tests](../tests/test_handoff_campaign.py).
It includes generated arithmetic input, a prewritten handoff note and eight
synthetic mode-evidence files. Installation paths, account references, source/build
hashes and context identities are placeholders, not observations of an installed
client or account. No credentials or real provider output are included. The
prewritten note does not prove that a producer emitted it.

## Read-only example

From the source checkout, using an existing supported Python environment with the
repository's dependencies:

```sh
python -B tools/qualify_handoff.py --help
PYTHONPATH=src python -B tools/qualify_handoff.py \
  --manifest docs/examples/handoff-campaign/campaign.json --dry-run
```

The second command is expected to exit **3** with blocked preparation: the
example supplies neither independent operator trust nor destination approval,
and its receipts are explicitly synthetic. Receipt dates can also become stale;
the validator evaluates current UTC time rather than accepting a manifest clock.
It never contacts the declared endpoints or launches the commands in the task.

Exit codes are **0** for preparation checks passing, **2** for malformed or
unavailable input, and **3** for a well-formed blocked preparation. Even exit 0
does not admit execution. Every completed preparation assessment retains these
boundaries:

```json
{
  "qualification": "preparation_only",
  "execution_admitted": false,
  "production_dispatch_allowed": false,
  "controller_submissions": 0,
  "state_mutated": false,
  "producer_association_verified": false,
  "source_identity_verified": false
}
```

## Manifest and separate operator inputs

The closed wrapper is `handoff_campaign_preparation`, schema version `1.0`.
`source` pins declared commit, wheel, sdist and dependency-lock identities;
`task_spec` is an unchanged [M11 2.10 task](artifact-handoff.md). The two `routes`
pin distinct harness declarations, M9 installations/profiles/bindings, configuration
and context digests, and start/observe/cancel/result receipts. Artifact references
pin local relative paths, hashes, byte sizes, media types and public classification.
`fixture`, `handoff_artifact`, finite `limits` and the closed `cleanup` policy
complete the wrapper. Unknown fields and native/cross-harness resume modes refuse.

The manifest cannot grant its own trust or destination permission. An operator
can provide destination IDs independently with repeated `--allow-destination ID`
arguments, and an existing private, operator-controlled M9 policy with
`--trust-policy POLICY.json`. These inputs only affect offline assessment; they
are not execution grants. The synthetic example remains blocked even if its
destination IDs are supplied. The report hashes the operator inputs separately
from the campaign manifest.

Use the existing [M9 qualification rules](qualification.md) for trusted receipts,
approvals, revocations and exact subject/mode evidence. Do not turn synthetic
claims into actual evidence by changing their level, names or hashes. A supplied
policy does not authenticate the source/build declarations or the truth of a
measurement. Missing, stale, mismatched, revoked or tampered proof remains a
blocker; artifact and receipt diagnostics identify the relevant digest.

## Bounds and filesystem support

The manifest is limited to 1 MiB, with at most 128 artifacts, 1 MiB per artifact
and 16 MiB in total. Reads are also bounded by each declared size. Preparation
ceilings are eight submissions, 1,440 seconds, 64 MiB capture and 1 MiB handoff
artifact; task and route budgets must fit them. These declarations allocate no
calls, time, account spending or runtime capacity.

The filesystem-backed CLI uses POSIX descriptor-relative safe file reads. It
requires owned regular single-link files, rejects symlink/path escapes and does
not weaken checks for portability. Evidence paths resolve beneath
`--evidence-root`, or beneath the manifest directory when omitted. Trust-policy
reads additionally require private permissions. Filesystem campaign reads on
Windows are not qualified; the existing Windows portable checks do not establish
support for this new CLI. An unsupported safe read can return exit 2 rather than
falling back to an unsafe reader.

Actual two-harness execution, runtime/source authentication, authoritative
producer-output association, containment and settlement proof remain separate
unimplemented or unproven campaign obligations. Preparation never settles old
unknown effects or changes historical receipts.
