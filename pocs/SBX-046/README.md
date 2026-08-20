# SBX-046: published-port revocation

Status: **FROZEN/READY for one separately coordinated bounded live run. No live run has been performed.**

This packet tests one narrow server-side question: after Vercel accepts
`sandbox.update({ ports: [] })` and both the active handle and a fresh
`Sandbox.get({ resume: false })` return an empty published-route list for the
same named sandbox session, can the previously issued `*.vercel.run` URL still
reach the service?

This is not an SDK-cache-only hypothesis. `@vercel/sandbox@3.0.0` documents
`ports` as the complete desired list, sends it to Vercel's sandbox API, and
replaces the active routes with the server response. Vercel's official Sandbox
skill likewise states that ports omitted from an update are deregistered:

- [Vercel Sandbox skill: updating sandbox configuration](https://github.com/vercel/sandbox/blob/main/skills/sandbox/SKILL.md#updating-sandbox-configuration)
- [Vercel Sandbox skill: exposed ports](https://github.com/vercel/sandbox/blob/main/skills/sandbox/SKILL.md#exposed-ports)
- [Vercel Sandbox product documentation](https://vercel.com/docs/sandbox)
- [Vercel Sandbox product page](https://vercel.com/sandbox)

The API does not expose a separate configured-ports getter. Consequently, the
runtime proof is accurately described as **empty server-returned published-route
state**, not a literal `ports` property readback.

## Safety and proof matrix

The controller uses one fresh named, nonpersistent sandbox and port `3000`.
The guest service binds `0.0.0.0:3000`; its local-only HMAC key and configuration
are mode `0600`. Each request has a unique public challenge and returns only an
opaque operation ID. The guest ledger stores identity/correlation fields and the
operation ID, never the key, request body, or a secret digest.

The run is bracketed as follows:

1. Verify the exact HackerOne alias account, team, and project. Acquire the
   fixed mode-`0600` SBX-046 live lock and record the intended full-UUID name.
2. Create one nonpersistent sandbox with `ports: [3000]`, `deny-all`, and exact
   run tags. Active and independent readbacks must identify one running session
   and the same single public route.
3. Prove the service over loopback, then prove the saved public route using a
   fresh strict-TLS POST and a matching guest-ledger event.
4. Await the literal `sandbox.update({ ports: [] })` call.
5. Require active and independent same-session readbacks with `routes: []`, and
   require `domain(3000)` to throw on both handles.
6. Prove the same guest service still works locally after revocation.
7. Probe only the saved old URL at absolute offsets `+5s`, `+30s`, and `+90s`.
   Every request uses a fresh connection, unique challenge, no retry, no cache,
   and no redirect.
8. Reconfirm empty routes and local service health, overwrite the guest key,
   stop/delete the sandbox, and verify absence three times plus by name prefix.

Verdicts are intentionally strict:

- `candidate-low`: all controls and cleanup pass, and **all three** delayed
  old-route probes return their exact keyed receipt with exactly one matching
  guest event. This is a sustained silent fail-open, not credential exfiltration.
- `pass`: all controls and cleanup pass, and all three old-route probes receive
  conclusive terminal route denial with zero matching guest events.
- `indeterminate`: any mixed result, propagation-only reachability, timeout,
  transient DNS/TLS/socket error, duplicate request, response/event mismatch,
  identity/session/route mismatch, or cleanup uncertainty.

Do not claim Medium or High from this packet. A keyed synthetic canary proves
route enforcement only; it does not demonstrate operator-data or credential
exfiltration.

## Local validation

These commands do not contact Vercel or the public route:

```sh
npx vitest run \
  test/sbx-046-guest.test.ts \
  test/sbx-046-published-port-revocation.test.ts \
  test/sbx-046-controller.test.ts
npx tsc --noEmit
npx tsc --noEmit -p tsconfig.poc.json
node --check guest/published-port-revocation-service.mjs
```

## Future bounded live command

Run only after the packet is independently frozen and no other challenge lane
is using Vercel. The controller refuses inferred credentials and requires the
exact eligible alias scope.

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

task_vercel_token=$(node --input-type=module -e \
  'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')

VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ" \
VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa" \
SBX046_ALIAS_EMAIL_CONFIRMATION="swve@wearehackerone.com" \
SBX046_SCOPE_CONFIRMATION="I_OWN_THIS_ALIAS_SCOPE_AND_AUTHORIZE_ONE_PUBLISHED_PORT_REVOCATION_TEST" \
npx tsx pocs/SBX-046/published-port-revocation.ts

task_sbx046_status=$?
unset task_vercel_token
printf 'SBX-046 exit status: %s\n' "$task_sbx046_status"
```

The controller intentionally exits nonzero for `candidate-low`, `indeterminate`,
or `error`. Judge the structured assessment and cleanup fields in the mode-`0600`
private artifact, not the process status alone.
