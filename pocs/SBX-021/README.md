# SBX-021 explicit CIDR-deny precedence with operator-data proof

Status: **local packet complete; no live run performed**.

This deterministic packet tests one narrow promise: an exact `subnets.deny` entry must override a domain allow for the same destination address. Vercel's current Sandbox documentation states that denied ranges take precedence over domain rules and allowed ranges. A successful request to the denied address would therefore be a policy violation, not the documented limitation around CIDR-only DNS controls.

The packet is hard-pinned to the researcher-owned Worker at:

```text
https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action
```

The hostname currently has multiple Cloudflare IPv4 edges. The controller resolves the current A set, selects distinct addresses `T` (target) and `S` (safe control), and pins every socket directly while preserving the Worker's hostname as TLS SNI and HTTP `Host`. The application endpoint is researcher-controlled; the underlying Cloudflare anycast addresses are not claimed as researcher-owned infrastructure.

## Exact sequence

One fresh, nonpersistent alias-owned sandbox starts with:

```json
{ "allow": ["vsc-tls-deny-swve.cyrus-206.workers.dev"] }
```

1. The controller writes a fresh base64url synthetic operator secret to `/tmp/sbx-021/operator-secret` with mode `0600`. The HMAC key never enters the guest.
2. `baseline-target-allow` pins HTTPS to `T`, uses a public canary, verifies the Worker's public certificate and HTTP/1.1, and must return the exact controller-derived HMAC operation ID.
3. The same sandbox session is updated to:

   ```json
   {
     "allow": ["vsc-tls-deny-swve.cyrus-206.workers.dev"],
     "subnets": { "deny": ["T/32"] }
   }
   ```

4. Both the sandbox-level and `currentSession()` policy views on the active handle and a fresh non-resuming `Sandbox.get` handle must report that exact policy and the original `sbx_…` session ID.
5. `restricted-safe-control` pins HTTPS to `S` with another public canary and must return its exact HMAC operation ID. This proves the hostname, Worker, policy, and guest network remain healthy.
6. `restricted-target-secret` pins HTTPS to `T`, reads the operator-secret file only at request time, and sends it to the non-reflecting Worker action. The guest result and retained evidence contain neither the raw secret nor a digest of its secret-bearing request target.

There are at most three sequential endpoint requests, no retries, no redirects, no DNS-based connection choice inside the guest, and no third-party targets.

## Verdict and proof bar

- `candidate`: every setup, baseline, exact-policy, same-session, safe-address, and cleanup control passes; the request to `T` completes verified TLS to `T`; and the Worker returns the exact HMAC operation ID for the file-backed secret.
- `pass`: all controls pass and `T` is blocked before any HTTP response or operation ID.
- `indeterminate`: any endpoint, policy readback, session attribution, certificate, safe-address, response-shape, or target-block signal is ambiguous.
- `error`: controller execution or cleanup fails.

A positive result with only public reachability would fit the program's Medium policy-boundary tier. The file-backed secret plus exact non-reflecting HMAC action is required before considering the program's High network-exfiltration example. Because the initial `T` and `S` controls are two paths to the same logical Worker, use this packet for discovery and then reproduce with separately controlled `T` and `S` receivers behind one certificate/hostname before making an unqualified High claim. Otherwise state the maximum impact conservatively and let Vercel triage assign severity. Do not claim High from a timeout difference, DNS result, TCP handshake, HTTP status, or unverified response.

## Root-cause consolidation

If positive, this is one root cause: **an explicit CIDR deny is not applied to a connection authorized by its TLS hostname**. Do not file a separate report for CNAME, DNS rotation, address ordering, or Happy Eyeballs variants if they fail for the same reason. The existing `SBX-003-021` rotating-DNS packet would become a supporting variant, not another bounty report. This is distinct from:

- `SBX-006`, which tests alternate IPv4-mapped address parsing;
- `SBX-013`, which tests URL-path canonicalization in credential matchers;
- `SBX-031`, which tests the semantics of encrypted versus visible SNI.

## Local verification only

```sh
npx vitest run test/sbx-021-explicit-deny-high.test.mjs
node --check pocs/SBX-021/explicit-deny-precedence.mjs
python3 -m py_compile guest/fixed-ip-deny-probe.py
```

## Live command — hold until explicitly selected

No live execution was performed while building this packet. When selected for a bounded live run, first confirm the Worker and its secret are still deployed, then use the HackerOne-alias Vercel account:

```sh
export SBX021_SCOPE_CONFIRMATION=I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_CIDR_PRECEDENCE_TESTING
export SBX021_ENDPOINT_URL=https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action
export H3_ACTION_KEY='<same controller-only key configured on the owned Worker>'

# Optional: pin the expected current A-record roles explicitly.
export SBX021_TARGET_IPV4=104.21.61.182
export SBX021_SAFE_IPV4=172.67.212.197

task_vercel_token=$(node --input-type=module -e '
  import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js";
  const auth = getAuth();
  if (!auth?.token) process.exit(2);
  process.stdout.write(auth.token);
')

DOTENV_CONFIG_PATH=.env.local \
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
node pocs/SBX-021/explicit-deny-precedence.mjs
task_sbx021_status=$?
unset task_vercel_token
printf 'SBX-021 exit status: %s\n' "$task_sbx021_status"
```

The controller requires explicit credentials for the verified HackerOne-alias team/project, verifies the token's email through Vercel's read-only `/v2/user` endpoint before sandbox creation, and rejects addresses that are not in the controlled endpoint's current public A set. Every SDK operation is time-bounded. It always attempts sandbox stop and deletion and stores private evidence mode `0600` under ignored `artifacts/`.

## Primary references

- [Vercel Sandbox firewall](https://vercel.com/docs/sandbox/concepts/firewall)
- [Advanced egress firewall filtering for Vercel Sandbox](https://vercel.com/changelog/advanced-egress-firewall-filtering-for-vercel-sandbox)
- Local challenge policy: `notes/HACKERONE_PROGRAM_POLICY.md`
