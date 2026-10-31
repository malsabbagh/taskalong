# Versioned implementation capture and a final explicit successor

Status: proposed.

Real coding responses can emit thousands of small native delta records. A
64 KiB proposal allowance does not imply that the complete session protocol fits
1 MiB or 2,048 records. Preserve those existing identities while adding an
explicit fixed implementation profile: config `/4`, 720 seconds, 4 MiB combined
raw bytes, 8,192 records and 64 KiB canonical proposal. No adaptive growth or
protocol filtering is permitted. The line parser shares the total byte bound.

A separate reason-specific successor migrates only an original 720-second /
1 MiB / 64 KiB capture failure to this profile. Same State, task bundle, binary,
account, requested model/effort, context and all other configuration remain bound.
Plan/enrollment/reservation `/2` bind `reason: capture`; old timeout bytes and
schedules remain unchanged. Both reasons use the same exclusive reservation
indexes and private external history fence. Capture grants one final logical
slot, reserved before native preflight; failed setup, crash or restored database
never refunds it. No child has a further successor.

Admission requires actual overflow, observed root/group cleanup and matching
native cancellation evidence, with no completed proposal or conflicting result.
The sole torn-tail exception recognizes an ordered, identity-bound prefix of
pinned native delta metadata before result text. It never discards arbitrary
incomplete JSON, rewrites captures or permits success decoding of truncation.
All original hashes, submission claims and unknown usage obligations remain.

Alternatives of changing a request nonce, replacing State, increasing a legacy
limit in place, omitting metadata from captures or automatically retrying would
lose identity, accounting or evidence. They are rejected. Model instructions are
not enforced output bounds. The fixed profile can still fail; failures retain
unknown remote usage/native retries/complete descendant cessation honestly.

Qualification covers whole-protocol/proposal/record exact boundaries, completed
streams above the legacy record limit, strict partial/malformed/cancelled streams,
legacy identities, scope/claim drift, duplicate/concurrent reservations and
crash/restored-State fencing. Live validation is a separate explicitly limited
owner action after offline review, installed proof and unchanged full CI.
Rollback refuses new formats while preserving every legacy and new claim.
