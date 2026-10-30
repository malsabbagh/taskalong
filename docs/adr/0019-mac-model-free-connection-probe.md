# Pinned Mac model-free connection probe

Status: proposed; diagnostic only, not live admission.

Expose a fixed echo-host initialize-only probe before the CLI opens RunService.
Compared with teaching admission to trust a supplied receipt, a separate diagnostic
cannot open the production gate. Compared with ad-hoc scripts, it preserves a
reviewable fixed argv/request and private evidence/error contract.

The operator supplies a direct file whose bytes must equal the measured pinned
1.4.10 Mac binary, and a new private evidence directory. Fresh HOME/XDG/workspace
contain no real user configuration or credentials. Restrictive disable-shell and
disable-write switches are process-local; no setting, trust or grant is changed.
Only initialize is sent, with zero requested capabilities; no session or turn.
No commands or model prompts can be supplied. Unexpected grants, protocol/build
identity, missing/extra frames, unknown sandbox state, incomplete process or
identity drift refuse. Missing or failed evidence persistence never passes.

Observed Mac sandbox availability differs across execution contexts. The native
host reports unavailable under the enclosing tool sandbox and available under
an approved ordinary execution context. Neither means shell/file/network denial
has been independently exercised. The real account, effective model context,
agent tools, remote accounting and coding-session lifetime remain unqualified.
Native initialization itself forks; retain unknown descendants even when the
root/group exit. Never auto retry, escalate, reuse prior evidence or stamp it
as a production receipt. Existing exposure holds and live refusals are unchanged.

Rollback removes the diagnostic command/module; no Store/schema migration.
