# SBX-006 IPv4-mapped IPv6 CIDR-deny discriminator

This bounded PoC tests only a researcher-controlled HTTPS observer on port 443. It asks whether a subnet deny for a current controlled IPv4 address `T/32` also blocks the equivalent IPv4-mapped IPv6 destination `::ffff:T`.

The controller snapshots the observer's current A records, selects `T`, and selects a distinct optional `S` when available. Every IP probe still uses the controlled observer hostname for strict TLS SNI and HTTP `Host`, so certificate verification remains enabled and the request can only address the controlled virtual host.

Two fresh nonpersistent sandboxes are used:

1. Baseline (`allow-all`): hostname A, fixed T, mapped `::ffff:T`, and optional fixed S must reach the observer with correlated events and verified TLS. If the mapped baseline returns `ENETUNREACH`, the result is indeterminate and the deny phase is skipped.
2. Deny policy: domain A remains allowed while `subnets.deny` contains exactly `T/32`. Fixed T must be blocked with no event. Optional S must still reach A as a non-denied edge control. The mapped destination is then tested.

Interpretation:

- `candidate`: fixed T is blocked, optional S works when present, but `::ffff:T` reaches A;
- `pass`: fixed T and `::ffff:T` are both blocked while all available controls pass;
- `indeterminate`: baseline reachability, exact-deny, optional edge, evidence, or cleanup validation fails.

## Prerequisites and run command

```sh
npm ci
export OBSERVER_BASE_URL="https://<researcher-controlled-observer>"
export OBSERVER_ADMIN_KEY="<random-observer-admin-key>"
npx sandbox login
npx tsx pocs/SBX-006/ipv4-mapped-deny-bypass.ts
```

For noninteractive access, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together instead of running device login.

The artifact records the DNS snapshot and timestamps, selected T/S/M values, policies, sandbox session IDs, guest-observed remote addresses, verified TLS/certificate metadata, raw controlled observer events, and all cleanup results. It is ignored by Git and written mode `0600` under `artifacts/`.

No destination outside the current A records of `OBSERVER_BASE_URL` is used. Every sandbox that is created always attempts stop and delete; cleanup failure makes the command exit nonzero. The deny sandbox is not created when baseline reachability or baseline cleanup is inconclusive.
