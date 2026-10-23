# Ollama profiles through the existing Claude fixture

Status: proposed for review in M6.

Ollama is a provider profile, not a fifth executor. Keep the single Workflow,
Store, supervisor, ClaudeCode driver, strict decoder and owned bounded runner.
The closed registry selects an internal immutable descriptor for this exact
tuple: task/config/wire 2.4, projection `claude-ollama-fixture/1`, driver version
`claude-print-ollama-fixture-1` and installation `synthetic-claude-ollama-1`.
Task data cannot select a callable, launcher or fallback. The earlier 2.3 tuple
retains its meanings and refuses Ollama providers.

Four additive resources describe driver-config, task-spec, worker-packet and
packet-projection. Reuse ProviderProfile/HarnessInstallation/ExecutionBinding
2.0, qualification 2.1, policies/read-only views 2.2 and worker-result 2.3.
The packet explicitly names that result version. Configuration, provider,
packet, admission and fresh attempt/session identities remain exact references.
The canonical packet and stdin wire packet are identical. No opaque session
crosses harnesses or provider profiles.

Executable 2.4 state requires explicit, quiescent, completely backed-up format
4-to-5 maintenance. SQL005 adds a compatibility fence without new tables or
history rewrites. The actual accepted format-4 Store is pinned as a predecessor
fixture; it must refuse before journal mutation. Never advance markers by hand,
automatically upgrade at submit/start, restore over existing data or reinterpret
a prior format's stored documents.

The pure provider-route reader accepts only canonical numeric HTTP loopback
with an explicit port for local fixtures, or exact `https://ollama.com` for
direct-cloud fixtures. Local uses local-no-secret/null reference/local-only;
cloud uses an explicit fixture-only reference/provider-only. Server/model
availability, exact synthetic model digest, local/cloud origin, tool/result
protocol and absence of external effects must be independently captured.
Aliases, forwarding, unknown origin, unavailable models, path/query/userinfo,
effort/tier, auxiliary routes and explicit managed-route conflicts refuse.
No discovery, network, settings/keychain read, login, model pull or daemon
operation occurs in the route module. URL shape alone is not model-origin proof.

DriverConfig contains a closed synthetic leaf capture with no enclosing config
digest, M2 subject, approval or self-digest. This avoids an evidence cycle:
provider/capture precede config, effective context and qualification subject;
an observation then references the exact canonical capture; its receipt is
separately approved by trusted operator policy. Capture syntax is never authority.

ExecutionBinding 2.0's required-capabilities enum does not contain
`provider_lookup`; do not broaden it or reduce a binding to manufacture support.
At each existing admission, dispatch and owned-gate boundary, use the original
binding, installation, provider, context, receipts, trust and evidence snapshot
to evaluate **both start and provider_lookup**, using one current timestamp.
Both full decisions must satisfy every original requirement plus the operation
capability. No vote crosses modes. Native continuation or other unsatisfiable
requirements stay unsatisfied. Each contributing provider-lookup observation
must reference the exact canonical inline capture by hash, size and JSON media
type, with retrieved bytes equal to that capture. A matching unrelated blob,
start observation, rejected receipt or historical decision cannot substitute.

The immutable admission snapshot retains the ordinary start decision and a
separate lookup decision/report and contributing observation hashes. Its digest
binds both chains. Capability summaries reflect their conjunction. Reevaluate
current trust/time at every gate; do not cache an old successful lookup as
authority. Registration may retain a valid unqualified declaration for later
inspection or revocation, without advertising it as admitted.

The shared driver starts from its minimal environment and private HOME/config/
temp. It supplies only validated ANTHROPIC_BASE_URL, a local placeholder or
closed registered nonsecret fixture sentinel in ANTHROPIC_AUTH_TOKEN, and empty
ANTHROPIC_API_KEY. It omits effort and inherited keys, model defaults and proxies.
Real credential references are never dereferenced. The deterministic responder
lives inside the original fake Claude process, validates its fixed synthetic
inventory, and records route/model/config/provider/session identities plus token
presence/match predicates. It logs no token and opens no socket or SDK request.
This is route/environment simulation, not actual HTTP compatibility proof.

Confirmed cancellation covers only the owned fixture process. No server request
was sent, so no durable provider effect is invented. Client exit cannot prove
external-server cessation, cost, refund or retry safety. Unknown effects remain
quarantined; reported usage never becomes known totals. Restart uses a fresh
attempt/session and the same persisted budget. Native resume, hard token/cost
enforcement, live inference and production remain disabled pending separate
exact-mode qualification. No package-registry publication follows M6.
