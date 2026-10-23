# Semantic execution documents

Status: proposed for review in the M1 PR.

The existing v1 profile combines one Codex executable and model with operational
configuration. Multiple harnesses require explicit identities without admitting
unqualified launchers. M1 adds immutable v2 HarnessInstallation, ProviderProfile
and ExecutionBinding documents and explicit offline readers. It changes no store,
registry, process backend or admission path.

One alternative extends v1 RuntimeProfile with provider conditionals. That would
reinterpret saved canonical data and couple model/backend choices to launcher
configuration. Another adds launch and qualification behavior to document
constructors. That would make reading portable data perform effects and blur
trusted evidence admission. The selected seam keeps documents inert and preserves
the original v1 validation path; qualification and resolution follow separately.

Installation and dependency closure, provider/destination/auth, policy references,
required capabilities and budgets are semantic inputs. Qualification receipts
refer to binding identity later and do not enter its digest. Worker sandbox and
independent check binding are distinct references. Native compatibility binds
all semantic inputs and its exact-session protocol; it does not grant resume.

Tests pin original public v1 schema hashes/canonical fixtures, check strict closed
boundaries, immutable copies and installed resources, and retain production
refusal tests. Synthetic linked examples are packaged with schemas. Their hashes
are declarations; trusted subject/evidence resolution is explicitly absent.

No migration is needed: these records are not persisted through the existing
store API. Removing additive readers before adoption rolls back code; any shipped
document version must retain its meaning in future readers. Unknown versions
fail closed. Later steps or policy records require explicit compatible additions
or new versions, never rewriting sealed v1/v2 history.
