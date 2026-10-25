# Muse offline protocol preparation

Status: proposed; offline argument projection and private raw capture only.
Semantic event decoding remains unsupported. No live driver is registered.

The integration goal is one TaskAlong task interface across the named coding
CLIs. RunService, Workflow and the existing closed executor registry continue to
own authority, attempts, effects, workspace fences, cancellation and acceptance.
A separate generic command runner would duplicate those responsibilities and
make recovery ambiguous. A separately versioned synthetic Muse route now connects raw capture to the
existing lifecycle; its proposed [handoff ADR](0012-muse-supervisor-handoff.md)
describes the additive 2.9 contracts. No live Muse route is enabled.

## Established boundary

The installed Muse Code 1.4.10 (1.4.10-R6427.1) help documents `exec --json`,
explicit model/workspace/prompt-file/profile selection and finite model steps.
The [official headless documentation](https://dev.meta.ai/docs/muse-code/extending#headless-and-ci)
describes JSONL output and exit meanings: zero means turn completion, while
failure/cancellation, usage errors and signals have distinct nonzero exits.
Turn completion does not certify correct code or passing independent checks.

Neither that documentation nor the installed help specifies the event fields,
ordering, identity correlations or usage representation. Public official-source
searches did not establish them. Binary serializer names are insufficient to
infer their complete shapes. The separate MSP schema describes `muse serve`;
it must not be substituted for `muse exec --json`.

Consequently `muse_protocol.project_exec_argv` only returns an immutable argument
tuple as data. It pins the observed build, uses an explicit Meta provider/model,
prompt file, profile and bounded steps, and retains untrusted approvals and
proxy-only shell networking. It exposes no arbitrary extra flags, credentials,
shell interpolation, workspace trust switch or permission bypass. Path checks
are lexical POSIX checks, not filesystem identity or containment verification.
The supplied profile/model/build declarations do not attest their actual state.

## Plain-output capture slice

`project_plain_exec_argv` omits `--json`. The synthetic-only `muse_capture`
adapter passes those fixed arguments through the existing `run_bounded` owner;
it adds no subprocess launcher, generic command escape or scheduler. Exact
bounded stdout/stderr, including non-UTF-8 bytes and redaction-like text, are
retained privately using the existing original-capture callback. Receipts bind
run/attempt/spec/profile/fence, prepared prompt hash, executable hash, requested
configuration and argv identity. Files are exclusive 0600 writes in a new 0700
attempt subdirectory, flushed before a final receipt is returned. Existing output
refuses another invocation, including after an incomplete or uncertain attempt.
The capture control directory must be separate from the worker workspace; equal,
nested or alias paths refuse before execution. This is path separation, not proof
that a real runtime cannot read or write outside its authorized workspace.

The executable and prepared prompt are rechecked around the trusted spawn
callback before gate release. Original input is retained separately; detectable
prompt drift fails. These measurements do not prove what an unqualified runtime
consumed or prevent transient changes: effective OS isolation remains required.

Only exit zero, no boundary error/limit/timeout/cancellation and confirmed owned
cessation produce `local_turn_completed`. This is not coding correctness or
independent acceptance. Exit one remains ambiguous failure/cancel/step exhaustion.
Callback and cleanup errors retain their codes and boundary observations; unknown
termination wins over apparent success. Actual model/session/usage/cost remain
unknown, even if output claims otherwise. Native resume, provider lookup and
structured results are unsupported. Production calls refuse before dispatch.

The raw helper does not interpret vendor output. The closed original fixture
route uses it through RunService and retains a supervisor-authored handoff 2.9,
not a vendor worker-result. Core validation checks authoritative Store records,
raw captures, cessation and a scope snapshot before independent verification.
The [handoff ADR](0012-muse-supervisor-handoff.md) specifies that separate
versioned boundary and compatibility fence. It remains synthetic only.

## Remaining protocol work

Obtain authoritative headless serialization definitions or a separately approved
exact-build capture before implementing the semantic decoder. Establish actual
session/run/model identities, event ordering, terminal states and usage fields;
do not invent them. Then retain original wire bytes and their hash, enforce
strict incremental UTF-8/JSONL byte/line/frame limits, reject malformed/truncated
records, conflicting identities and duplicate terminals, and correlate nonzero
process exits. Missing usage must stay unknown. Tests for these semantics are
pending this source dependency, rather than tests of fabricated vendor fields.

## Admission and lifetime

Existing fixture tuples, production refusals and earlier schema meanings stay
unchanged. The synthetic handoff adds an explicit format 9 compatibility fence. Importing the module, building arguments or passing a synthetic test
creates no authority. Invalid projections refuse with `not_sent`; the projection
itself never sends anything. A future live driver must qualify exact executable
and dependency closure, effective instructions/hooks/tools, filesystem/network
isolation, account/model/endpoint and owned descendant lifetime before dispatch.
Darwin's tracker supports only its measured non-forking lifetime; observed forks
quarantine the attempt. Do not relax that boundary for a real coding CLI.
The [vendor changelog](https://dev.meta.ai/docs/muse-code/changelog) records later
profile deny-enforcement fixes. A requested 1.4.10 permission profile is not
evidence of containment. Later usage interfaces likewise do not establish usage
observations for this pinned build; the raw adapter does not parse such text.

Unknown termination stops dispatch, replay, acceptance and workspace reuse.
Local cancellation is not remote cancellation or billing-cessation evidence.
Model-step limits alone do not bound observer, subagent, judge or remote usage.
The [subscription documentation](https://dev.meta.ai/docs/muse-code/subscriptions)
distinguishes the subscription-connected credential from separately created API
keys billed by usage. Before any live call, verify the intended existing route
uses included allowance without unintended paid fallback and enforce the finite
campaign's effective bounds. No login, installation, grant or paid call occurs
in this offline preparation.

## Validation and compatibility

Original projection tests check literal argv transport and pre-dispatch refusal
of unobserved builds, unbounded steps and option-like input. Original non-forking
Python fixtures exercise the raw adapter's real supervised invocation, exact
captures, timeout, cancellation and failure paths. A fault-injected cessation
observation tests conservative mapping without leaving an unknown live child.
Existing synthetic drivers exercise durable start-key/result behavior; none of
these tests qualify Muse. Independent checks and ReviewSensei
acceptance remain separate from worker completion and from native PR approval.

Rollback preserves private raw attempts and Store history with a compatible
reader; removing code cannot reconcile uncertain effects. No live activation,
package release or global runtime setting is introduced. These ADRs are
proposals for review, not live qualification authority.
