# Qualification

This candidate is a fixture-qualified foundation with **production dispatch
disabled**. It does not claim usable live Codex/Claude execution, model review,
provider cancellation, complete runtime isolation or actual GitHub publication.

Candidate receipts are kept by the owner outside the distribution and bind exact
source, interpreter/host versions, artifact, lock and test-input hashes.
Linux-specific lifetime tests are skipped on macOS and require actual Linux
execution; no macOS result qualifies them. Local checks do not qualify a different
hosted OS image. Every intended Python/platform cell needs its own exact-head CI
receipt; matching Python versions alone do not establish platform equivalence.

```sh
python -m pip install --require-hashes -r requirements-dev.lock
python -m build --no-isolation --sdist --wheel
python tools/normalize_sdist.py dist/*.tar.gz
python tools/check_dist.py --dist-dir dist
python tools/qualify_installed.py --dist-dir dist --artifact wheel --mode fixture
python tools/qualify_installed.py --dist-dir dist --artifact sdist --mode fixture
python tools/qualify_installed.py --dist-dir dist --artifact wheel --core-only
```

The qualifier creates fresh ordinary environments outside the checkout. Source
reads/import fallback are denied. External synthetic CLI/GitHub fixtures remain
outside the installed wheel. ReviewSensei 0.8.8 is checksum-pinned and uses its
actual released fixture backend; this is not live model review. Synthetic
lost-response publication must reconcile one fixture create. Missing required
review blocks acceptance. These checks produce no runtime authority.

The existing Codex CLI target is 0.163.0. Prior controlled-responder probes did
not establish complete descendant cessation or effective instruction/tool
isolation. Resume must not follow an unconfirmed lifetime. The current Darwin
backend quarantines forks; Linux subreaper tests still do not, by themselves,
qualify a real CLI, filesystem/network containment or remote provider cessation.
Use an existing approved runtime environment and exact profile for a separate
actual start/cancel/resume/tool/isolation campaign. No runtime installation,
credential change, model pull or provider fallback is implied.

The single-step 2.2 admission path currently admits only an explicitly trusted
`codex-v1-fixture/1` registration. The shared executor contract suite observes one
supervised fake CLI, real local cancellation, canonical/wire identity mapping and
independent synthetic verification. It also checks production/native-resume
refusal. The simulated provider declaration does not prove the actual endpoint,
account, model, instructions, tools or containment of any vendor CLI. Revocation
before dispatch or before owned gate release prevents target execution; retained
unknown windows remain quarantined rather than manufacturing cessation evidence.
Adding another shared driver case or installing a binary grants no runtime
authority. Production stays disabled until separately reviewed exact-mode proof.

Claude wire tests are original synthetic frames, not installed-version
transcripts. Its decoder is unregistered and reports untrusted protocol data;
no provider identity, billing proof, native-resume or cessation receipt follows.

The intended CI matrix is standard GitHub-hosted Ubuntu 24.04 x64 and macOS 15
arm64, Python 3.11–3.14. A configured workflow is not evidence that those cells
passed; each requires its own exact-head results. Repository visibility does not
override runtime preflight or qualify an execution mode.

The explicit distribution inventory excludes control stores, credentials, user
homes, raw logs, Git history and unrelated source. Pattern screening is a
secondary check, not proof of arbitrary-secret absence or rights ownership.
Source-archive normalization removes tar ownership, extended metadata and build
timestamps without changing file payloads or modes. The auditor rejects those
headers if they return, optional wheel metadata, and unapproved package contact
or source-URL metadata. These checks complement the source/content review.
The project uses the [MIT License](../LICENSE). The auditor requires exactly
the approved MIT metadata and license bytes in source, wheel and sdist, while
rejecting additional identity/contact/source metadata. License and notice changes
require rebuilding and fresh qualification. Public visibility and registry
publication remain separate owner decisions.
