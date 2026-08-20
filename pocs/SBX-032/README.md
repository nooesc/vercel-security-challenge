# SBX-032 TLS ClientHello record-reassembly probe

SBX-032 tests one root cause: whether the Vercel Sandbox host firewall parses the TLS SNI only when the entire ClientHello is present in one TLS record, instead of reassembling a standards-valid handshake message that spans multiple TLS records. A parser discrepancy could let a denied hostname pass the network boundary without escaping the microVM.

This is distinct from ordinary TCP segmentation. TLS permits handshake messages to span records, and a receiver must reconstruct the handshake byte stream. The guest therefore uses Python's standard-library `SSLObject` with `MemoryBIO` to obtain the real ClientHello produced by the system TLS implementation. It locates the configured hostname inside the `server_name` extension and uses three transmission modes:

- `normal`: one unmodified initial write.
- `tcp-segmented`: the unmodified TLS record is sent in two socket writes split inside the SNI hostname.
- `record-fragmented`: the first plaintext handshake record is rewritten into two syntactically valid handshake records split inside the SNI hostname. Concatenating their payloads exactly reproduces the original ClientHello; only the record framing changes.

Raw ClientHello bytes and HTTP bodies are never retained. Evidence includes only lengths, record counts, split position, hostnames, and SHA-256 values proving exact reassembly.

## Eight-request proof matrix

One fresh, nonpersistent, researcher-owned sandbox starts at literal `allow-all`. All requests are sequential, use a new IPv4 socket and new TLS context, pin the controller-resolved address, require normal public-root certificate and hostname verification, negotiate HTTP/1.1 explicitly, follow no redirects, perform no retries, ignore proxy environment variables, and are started no faster than once every 300 ms (3.34 requests/second maximum).

1. `allow-normal-b-control`: ordinary TLS reaches denied-test hostname B and returns the exact HMAC operation ID for a public canary.
2. `allow-tcp-segmented-b-control`: the same original TLS record, split only across two socket writes inside SNI, reaches B and returns exact HMAC proof.
3. `allow-record-fragmented-b-control`: the standards-valid two-record ClientHello reaches B and returns exact HMAC proof. This is the end-to-end server-validity control.
4. The controller installs `{allow: [A]}`, confirms it on the original active SDK session, independently reads it back with `Sandbox.get`, and waits 1.5 seconds. `restricted-normal-a-control` must reach allowed hostname A with ordinary TLS and return exact HMAC proof.
5. `restricted-normal-b-negative`: ordinary TLS to B must be actively rejected before any HTTP response. Timeouts are deliberately not accepted as proof of firewall blocking.
6. `restricted-record-fragmented-a-control` then tries the allowed hostname with the two-record ClientHello. If fragmented A is actively blocked, the controller sends only `restricted-record-fragmented-b-public-negative`; B must also actively block the public canary, and the synthetic operator secret is never sent. Otherwise fragmented A must succeed before testing the secret-bearing target.
7. On the candidate path, `restricted-record-fragmented-b-target` reads the fresh mode-`0600` synthetic operator secret from a fixed file and sends it to B with the two-record ClientHello. A candidate requires verified TLS and the controller-computed, non-reflecting HMAC operation ID for that unknown-to-configuration secret. On the fail-closed path, request 7 is instead the public-canary fragmented-B negative described above.
8. The controller rechecks the exact policy on the active SDK session and an independent non-resuming handle, requires both to retain the original session ID, then runs `restricted-normal-b-post-negative`. Ordinary TLS to B must still be actively rejected. No result is conclusive without this post-attempt barrier.

The controller HMAC key and raw synthetic operator secret never enter guest source, JSON configuration, command arguments, environment, stdout, stderr, or the evidence artifact. The controller writes the secret file through the Sandbox file API before restriction and verifies its exact mode and contents without retaining a standalone secret digest. The evidence necessarily retains only the keyed HMAC operation ID proving receipt. The guest response parser rejects a body that reflects the canary.

## Endpoint contract

Both A and B must be distinct DNS hostnames controlled by the researcher and serve the existing action contract at `/v1/h3-action`:

```json
{"authorized":true,"operationId":"h3_<base64url digest>"}
```

The digest is `HMAC-SHA256(H3_ACTION_KEY, run + "\n" + case + "\n" + canary)`. Responses must be HTTP 200 JSON with `Cache-Control: no-store`. The two hostnames may terminate at the same owned service, but they must be distinct so the tightened domain policy has an unambiguous allowed A and denied B.

## Required environment

Do not run until both hostnames are confirmed as researcher-owned and the Vercel account is the HackerOne alias account.

```sh
export SBX032_SCOPE_CONFIRMATION=I_CONTROL_BOTH_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TLS_REASSEMBLY_TESTING
export SBX032_ALLOWED_ENDPOINT_URL=https://vsc-tls-allow-swve.cyrus-206.workers.dev/v1/h3-action
export SBX032_DENIED_ENDPOINT_URL=https://vsc-tls-deny-swve.cyrus-206.workers.dev/v1/h3-action
export H3_ACTION_KEY='<same controller-only key configured on both owned Workers>'

task_vercel_token=$(node --input-type=module -e '
  import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js";
  const auth = getAuth();
  if (!auth?.token) process.exit(2);
  process.stdout.write(auth.token);
')

VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
npx tsx pocs/SBX-032/tls-record-reassembly.ts
task_sbx032_status=$?
unset task_vercel_token
printf 'SBX-032 exit status: %s\n' "$task_sbx032_status"
```

The controller requires all three explicit credentials for the exact eligible alias-owned scope and verifies the token email through Vercel's read-only `/v2/user` endpoint before creating anything. Every outcome writes one private mode-`0600` evidence file, then stops, deletes, and independently confirms absence of the deterministic sandbox name. A candidate intentionally exits nonzero so it cannot be missed in automation.

## Verdicts

- `candidate`: every normal, TCP-write, standards-validity, pre/post policy-readback, allowed-A, and pre/post ordinary-denied-B control passed; fragmented B completed verified TLS and returned the exact HMAC proof for the file-backed synthetic secret. This demonstrates the program's High-table impact category (firewall bypass with synthetic operator-data exfiltration), but Vercel triage assigns severity.
- `pass`: either ordinary A succeeded while both fragmented A and public-canary fragmented B failed closed and pre/post ordinary B remained blocked (so the secret target was not sent), or every full-path control passed and the firewall actively blocked fragmented B before a response.
- `indeterminate`: any control failed, a timeout occurred, policy readback differed, or the target result could not be attributed conclusively.
- `error`: controller execution or sandbox cleanup failed.

The report, if any, should stay scoped to this single TLS handshake-record reassembly root cause. TCP write segmentation is a control, not a separate claimed vulnerability.

## Local validation only

These commands do not create a Vercel Sandbox or contact either endpoint:

```sh
python3 -m py_compile guest/tls-record-reassembly-probe.py
npx vitest run test/sbx-032-tls-record-reassembly.test.ts
npx tsc --noEmit -p tsconfig.poc.json
```

The tests ask the real local Python TLS implementation to generate ClientHellos for all three modes, then verify that the two new record payloads concatenate byte-for-byte to the original ClientHello and that the split lies inside the SNI hostname. A separate bounded local request with a public canary can be used to confirm that the owned B endpoint accepts the rewritten records before any sandbox execution; it must never use the operator-secret file.

On 2026-08-18, one such non-sandbox interoperability request was completed against the existing owned Worker B. The controller-pinned peer address matched, public-root certificate and hostname verification passed, HTTP/1.1 returned 200 with a correctly shaped operation ID, and the endpoint accepted the Python-generated ClientHello after its original one handshake record was rewritten as two records split inside the SNI hostname. Payload reassembly matched byte-for-byte. This establishes server-side standards validity only; it is not evidence of a Vercel firewall bypass.

Protocol reference: RFC 8446 section 5.1 (record-layer fragmentation).
