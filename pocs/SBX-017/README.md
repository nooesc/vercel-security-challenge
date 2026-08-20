# SBX-017 HTTP/3/QUIC under literal `deny-all`

This deterministic packet asks whether a sandbox can exfiltrate a fresh synthetic operator secret in an authenticated HTTP/3 request over QUIC/UDP after literal `deny-all` has demonstrably blocked HTTPS/TCP to the same researcher-controlled hostname and controller-pinned public IPv4 address.

The HackerOne policy explicitly includes bypassing `deny-all` to reach an unauthorized destination, and current Vercel guidance describes CIDR controls as covering non-TLS traffic. A bounded live run is therefore authorized when it uses only the researcher's alias-owned sandbox and owned endpoint, stays within the request cap, and stops at the first confirmation. This implementation makes five sequential endpoint requests and performs no scanning, fallback, persistence, or service-degradation action.

## Controlled endpoint contract

The researcher-controlled HTTPS route must support both HTTP/1.1 over TCP and HTTP/3 over QUIC at exactly `/v1/h3-action`. The supplied route is an owned Cloudflare Worker running on Cloudflare's shared network; the controller-resolved IPv4 is pinned only to make the H3 and TCP comparisons address-identical, not as a claim that the researcher owns Cloudflare's underlying anycast address. For a `GET` request with the query parameters `run`, `case`, and `canary`, it returns only:

```json
{"authorized":true,"operationId":"h3_<base64url digest>"}
```

The digest is:

```text
HMAC-SHA256(H3_ACTION_KEY, run + "\n" + case + "\n" + canary)
```

The response must not echo inputs or secrets and must be sent with `Cache-Control: no-store`. `H3_ACTION_KEY` is controller-only and must contain at least 32 bytes. The controller independently computes the expected opaque operation ID.

For each control, the guest receives a different non-secret public canary. Before the policy is tightened, the controller writes a fresh random synthetic operator secret to the fixed guest path `/tmp/sbx-017/operator-secret` with mode `0600`, compares its contents transiently with the controller buffer, and wipes both buffers. The final `deny-h3-target` configuration contains no canary: only that fixed case reads the file and sends its value as the `canary` query parameter. The raw operator secret and a standalone digest of it never enter guest configuration, command arguments, output, or evidence; evidence retains only a boolean setup result and the endpoint's necessary opaque HMAC proof.

## Sequence and proof controls

One fresh nonpersistent alias-owned sandbox starts at literal `allow-all`:

1. Install exactly `curl_cffi==0.13.0` into an isolated `/tmp` target and independently verify the installed version.
2. Write the fresh synthetic operator-secret file before `deny-all`, verify its exact mode and contents transiently, then wipe the comparison buffers without printing or retaining a digest.
3. Send one `v3only` request with its own public control canary while `CURLOPT_RESOLVE` pins the controller-selected A record. The response must report actual HTTP version 3, the exact pinned primary IP, verified TLS, no redirects, and the expected HMAC-derived operation ID.
4. Send one HTTP/1.1 request with a different public control canary, the same TLS hostname, pinned IP, and endpoint contract. This proves TCP is initially healthy.
5. Await `sandbox.update({ networkPolicy: "deny-all" })`, independently read the sandbox back, and wait 1.5 seconds. Sandbox- and session-level policy on both handles must report literal `deny-all`, and both handles must retain the original `sbx_…` session ID.
6. Send one pinned HTTP/1.1 request with a third public control canary. A conclusive block requires libcurl error 7 (`CURLE_COULDNT_CONNECT`), no HTTP response, and no negotiated HTTP version. A timeout or TLS/application error is not accepted as this control.
7. Only after that barrier, run `deny-h3-target`; it reads the fixed synthetic secret file and sends one `v3only` request to the same hostname and IP.
8. Re-read active and independent sandbox/session policy, again requiring literal `deny-all` and the original session ID, then send a second public-canary HTTP/1.1 request. It must still be conclusively blocked. No H3 outcome is accepted without this post-target barrier.

The guest disables redirects, retries, proxy environment use, and protocol fallback. It forces an empty proxy and `NO_PROXY=*`, keeps certificate verification enabled, and never accepts caller-supplied TLS or proxy options. A receive callback retains at most 1 KiB and aborts on the first oversized libcurl chunk; libcurl's receive buffer is set to its 1 KiB minimum. All five endpoint requests are sequential and begin no faster than once per 250 ms (4 requests/second maximum).

## Verdicts

- `candidate`: both allow-all controls pass, literal `deny-all` is independently confirmed before and after the target on the same SDK session, HTTPS/TCP is conclusively blocked before and after, and the target exfiltrates the fresh synthetic operator secret using actual HTTP/3 from the same pinned IP with the exact controller-verified operation ID. This adds the operator-data exfiltration proof required for the challenge policy's High-impact network-boundary category.
- `pass`: all controls pass and the final `v3only` request fails before any HTTP response with a bounded connection/timeout error.
- `indeterminate`: an endpoint, protocol, pin, TLS, policy-readback, or TCP-block control fails, or the HTTP/3 result is ambiguous.
- `error`: controller execution or owned-resource cleanup fails.

The controller uses a full deterministic run name, recovers only an exact-tag/time-window orphan after create-response loss, stops and deletes the sandbox in every outcome, and independently confirms its absence. Private body-free evidence is stored mode `0600` under ignored `artifacts/`. A candidate intentionally exits nonzero so it cannot be mistaken for an ordinary passing test.

## Required environment

```sh
export SBX017_SCOPE_CONFIRMATION=I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_HTTP3_TESTING
export SBX017_H3_ENDPOINT_URL=https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action
export H3_ACTION_KEY='<same controller-only secret configured on the endpoint>'

task_vercel_token=$(node --input-type=module -e '
  import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js";
  const auth = getAuth();
  if (!auth?.token) process.exit(2);
  process.stdout.write(auth.token);
')

VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
npx tsx pocs/SBX-017/quic-deny-all.ts
task_sbx017_status=$?
unset task_vercel_token
printf 'SBX-017 exit status: %s\n' "$task_sbx017_status"
```

The controller requires all three explicit credentials for the exact eligible alias scope and verifies `/v2/user` returns `swve@wearehackerone.com` before creating anything.

## Local validation only

```sh
npx vitest run test/http3-deny-probe.test.ts
npx tsc --noEmit -p tsconfig.poc.json
```

`curl_cffi` documents `http_version="v3only"` as HTTP/3 without fallback and exposes both the negotiated HTTP version and primary server IP: <https://curl-cffi.readthedocs.io/en/v0.13.0/advanced.html#selecting-http-version>.
