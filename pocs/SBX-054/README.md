# SBX-054 — legacy-runtime v2 create policy-attachment differential

Status: **LOCAL-ONLY FROZEN/READY. No Vercel, tunnel, DNS, or public-endpoint call has been made.**
Do not run live without coordinating the SBX-050 slot cleanup and rechecking current program scope.

## Exact server-side seam

The installed `@vercel/sandbox@3.0.0` client chooses the create endpoint solely from the presence
of `runtime`:

- no `runtime` (default/image sandbox) -> `POST /v3/sandboxes`;
- `runtime: "node24"` (supported legacy runtime) -> `POST /v2/sandboxes`.

Both paths receive the same normalized `networkPolicy: { mode: "deny-all" }`. The untested seam is
therefore server-side create orchestration: the legacy v2 handler may accept and project the policy
but fail to attach it to the new microVM/network boundary. This packet does not claim an SDK defect.

Estimated execution feasibility is high with one eligible account and one owned Quick Tunnel.
Estimated positive probability is deliberately low (**5–10%**) because the mature v2 path likely
shares enforcement with v3. The run is still high-ROI: two short-lived sandboxes, one ordinary HTTPS
attempt per matrix row, no VPS, custom DNS, second account, destructive operation, or third-party data.

## Minimal proof matrix

| Gate | Create path | Requested/read-back policy | Allowed decisive result |
| --- | --- | --- | --- |
| Pre-comparator | v3, SDK default image | literal `deny-all` in create response, active sandbox/session, and fresh `Sandbox.get({ resume: false })` | known bounded pre-connect denial; zero receiver events |
| Target public | v2, `runtime: "node24"` | the same four literal `deny-all` projections | one exact keyed public receipt at the owned receiver, the comparator's exact denial tuple, or the exact Node24 `ENOTFOUND/getaddrinfo/-3008` denial paired with the v3 `EAI_AGAIN/getaddrinfo/-3001` bracket |
| Post-comparator | the same v3 comparator, fresh distinct request/canary | fresh active and independent literal `deny-all` readbacks before and after | the pre-comparator's exact denial tuple; receiver ledger byte-for-byte unchanged |
| Target impact | same v2 target | fresh active and independent readbacks still literal `deny-all` | only after the public receipt, exact HMAC proof that the receiver obtained a fresh mode-0600 file secret |

The controller generates four unique canaries; the receiver is configured with and retains only
their HMAC commitments. It
stores no raw canary, secret, body, secret digest, admin key, or action key. The guest makes one
strict-TLS request with no redirect, retry, custom CA, proxy, or trust override. An unexpected
comparator event, duplicate/reordered event, policy projection change, ambiguous error, receiver
noise, response mismatch, a nonmatching pre/post v3 denial tuple, or cleanup failure is `indeterminate`.
The Node24 `ENOTFOUND` tuple is accepted only as a noncandidate clean-denial result; it can never
establish public reach or a candidate. The controller captures the target final policy readback,
final observer snapshot, and receiver postflight before classifying any noncandidate result.

The fresh secret is generated only after both the guest receipt and HMAC-only receiver event prove
the v2 public boundary reach **and** the distinct post-target v3 comparator again fails closed with
zero additional event. The controller then stages the raw bytes locally in receiver memory
and writes the same bytes to `/tmp/sbx-054/operator-secret` with requested mode `0600`. The fixed
guest independently requires an exact mode-0600, single-link regular file, unlinks it before the
request, sends it once, and zeroes its buffer. High requires matching guest and receiver secret
HMACs plus an opaque action-keyed operation ID. The public receipt alone caps at Medium.

The guest permits and attests the three inherited platform trust names observed in prior Vercel
sandbox evidence: `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`, and `SSL_CERT_FILE`. It emits only
the sorted names, never their values. It still rejects `NODE_TLS_REJECT_UNAUTHORIZED=0`, nonempty
`NODE_OPTIONS`, trust/runtime-injection `process.execArgv`, unknown trust-store environment names,
and every controller-configurable custom CA/trust override. Every request explicitly keeps
`rejectUnauthorized: true` and the exact destination server name.

## Why this is distinct

This is not a DNS, IP-literal, TLS, HTTP parsing, redirect, proxy, ECH, or protocol-policy bypass.
It uses ordinary fresh HTTPS and attributes a difference only if v3 blocks while v2 reaches the
same owned origin. It does not update policy before the probe and does not fork, resume, restore a
snapshot, revoke an existing connection, or exercise published routes. It is therefore distinct
from SBX-017/018/025/031/033/047 and from the same-owner functional behavior in SBX-045. If both
paths escape, or their policies/readbacks differ, it collapses to an existing generic root and the
verdict fails closed.

## Recovery and retention

A mode-0600 durable journal is checkpointed before receiver configuration and before each create.
A create attempt that returns no exact-provenance handle is never treated as a clean absence: the
lock and journal remain for coordinated cleanup. Cleanup restores literal `deny-all`, verifies it
through active and fresh handles, stops/deletes the exact UUID/tag-bound targets in reverse order,
performs two absence reads, deletes receiver state, and performs two receiver absence reads. The
final mode-0600 artifact is fsynced before lock/journal release.

## Offline verification

```sh
./node_modules/.bin/vitest run \
  test/sbx-054-sdk.test.ts \
  test/sbx-054-receiver.test.ts \
  test/sbx-054-verdict.test.ts

./node_modules/.bin/tsc --noEmit --strict \
  --target ES2022 --module NodeNext --moduleResolution NodeNext \
  --esModuleInterop --skipLibCheck pocs/SBX-054/*.ts test/sbx-054-*.test.ts

node --check guest/sbx-054-legacy-create-policy-probe.mjs
```

All SDK tests inject a fake `fetch`; receiver tests use loopback only.

## Coordinated live command (not authorization)

Start one fresh Quick Tunnel to the dedicated loopback receiver:

```sh
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43154
```

In the receiver terminal, generate two distinct keys without printing them and start the receiver:

```sh
task_sbx054_admin_key=$(openssl rand -base64 48 | tr -d '=+/\n' | head -c 64)
task_sbx054_action_key=$(openssl rand -base64 48 | tr -d '=+/\n' | head -c 64)
export SBX054_ADMIN_KEY="$task_sbx054_admin_key"
export SBX054_ACTION_KEY="$task_sbx054_action_key"
export SBX054_PUBLIC_ORIGIN='https://<FRESH-ID>.trycloudflare.com'
export SBX054_RECEIVER_PORT=43154
./node_modules/.bin/tsx pocs/SBX-054/receiver.ts
```

In the controller terminal, reuse those two in-memory key values without logging them:

```sh
export SBX054_SCOPE_CONFIRMATION='I_RECHECKED_SBX054_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_V2_V3_CREATE_POLICY_DIFFERENTIAL'
export SBX054_EXPECTED_ALIAS='swve@wearehackerone.com'
export SBX054_MANUAL_ALIAS_CONFIRMATION='swve@wearehackerone.com'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export VERCEL_TOKEN='<eligible non-JWT Vercel PAT>'
export SBX054_ADMIN_KEY='<same receiver admin key>'
export SBX054_ACTION_KEY='<same receiver action key>'
export SBX054_PUBLIC_ORIGIN='https://<FRESH-ID>.trycloudflare.com'
export SBX054_ADMIN_ORIGIN='http://127.0.0.1:43154'
./node_modules/.bin/tsx pocs/SBX-054/legacy-create-policy.ts
```

If the controller retains a recovery journal/lock, keep the same receiver and credentials, set the
exact journal run ID, and rerun the controller only in cleanup mode:

```sh
export SBX054_RECOVERY_RUN_ID='<UUID FROM THE RETAINED SBX-054 JOURNAL>'
./node_modules/.bin/tsx pocs/SBX-054/legacy-create-policy.ts
```
