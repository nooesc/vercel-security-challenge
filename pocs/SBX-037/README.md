# SBX-037 — `forwardURL` request-target origin escape

Status: **final diagnostic hardening; local checks and independent review required
before one last bounded rerun**.

A prior bounded run on 2026-08-19 passed every scope, policy, syntax,
direct-B, OIDC, and cleanup control, but its one network-path attack received an
unattributed JSON `404` with zero A/P/B event. It produced no candidate. This
packet exists only to make that final `404` outcome attributable; repeating the
old packet unchanged is not useful.

## Exploit question

The final sandbox policy permits only owned origin **A** and forwards its HTTP
requests to owned terminal sink **P**:

```json
{
  "allow": {
    "a.example": [{ "forwardURL": "https://p.example/v1/sbx037/forward/<run>" }]
  }
}
```

The guest opens a fresh, verified HTTP/1.1 TLS connection whose TCP destination,
SNI, and `Host` are all A. It then sends either an absolute-form request target
for owned but denied origin B or a network-path target naming B. The question is
whether Vercel evaluates the request as A, then lets the request target replace
the configured terminal destination P.

This differs from SBX-034: that lane tested whether Vercel's host-side client
followed a `307` returned by P. SBX-037 makes P completely terminal—no redirect,
fetch, or proxy—and changes only the guest's raw request target.

It also differs from SBX-008, which tested SNI/Host/absolute-authority behavior
for ordinary policy transforms. SBX-037 holds TCP, SNI, and `Host` at A and asks
whether the separate host-side `forwardURL` client lets the request target
replace its configured terminal origin P.

## Proof bar

The bounded live controller uses one nonpersistent sandbox and fresh TLS
connections for:

1. direct-B reachability under a temporary A+P+B allow policy;
2. public-body absolute-form and network-path eligibility controls at A. Each
   form must either terminate exactly at A with a `202` receipt, or match the
   exact public-only `400` normalization diagnostic observed at A ingress. At
   least one form must be supported;
3. each supported public raw target sent directly through P, where it must
   terminate at P with zero OIDC, forwarded metadata, or B events, excluding
   routing by P's own edge/tunnel;
4. exact active and independent same-session readback of the A-to-P policy;
5. a direct-B block immediately before the attacks;
6. an origin-form A control that reaches P, where P independently verifies the
   Vercel OIDC token with audience P and exact sandbox claims;
7. exactly one attack for each supported form, carrying a fresh synthetic
   file-backed operator secret;
8. a final policy/session readback and direct-B block.

That is eight to ten sequential guest requests, each on a fresh connection. The
secret file is not staged until both A eligibility results, every supported-form
P control, both the direct-B barrier and authenticated origin-form baseline have
passed. A form matching the exact public-only A-ingress normalization diagnostic
is recorded as unsupported and is never run with the secret; it cannot itself
be a pass or candidate. Any other rejection is indeterminate.

Classification is deliberately narrow:

- **High candidate:** an exact normal or early-ingress B event independently verifies one Vercel OIDC
  token whose audience remains P and exact sandbox identity, or authorizes the
  non-reflecting keyed action for the file-backed secret;
- **Medium candidate:** an exact normal or early-ingress B request, but no token or secret
  proof;
- **pass:** every eligible supported attack form either terminates at authenticated
  P, produces an exact P path-join fallback, or produces an exact A ingress
  rejection; B sees no attack event and every required dynamic control passes;
- **terminal indeterminate / close lane:** the diagnostic request again returns
  `404` without an exact receiver receipt/event join;
- **indeterminate:** no supported form, ambiguous eligibility/events, or any scope, policy,
  session, direct-block, terminal-sink, or cleanup failure.

Every handled receiver response carries `x-sbx-role: A|P|B`. An exact
correlated request that reaches an otherwise unrecorded A/P/B `404` branch also
receives a fresh opaque `x-sbx037-fallback-receipt`. The guest retains only that
validated receipt and role; the controller requires byte-exact equality with
one bounded receiver fallback record. Receiver readback alone can never create
a candidate. P fallback proves a non-escaping path-join rejection. B fallback
proves denied-destination reachability and can independently verify the same
OIDC or file-HMAC impact gates as the normal B route. A second zero/unattributed
result closes SBX-037 without another retry.

Raw tokens, token digests, the synthetic secret, and a standalone secret digest
must never enter stdout or the mode-`0600` evidence artifact. Only sanitized
verification booleans, public identity claims, and necessary opaque action IDs
are retained.

The probe keeps `rejectUnauthorized: true` and accepts no configurable CA,
certificate, identity-check, or TLS-verification override. Vercel Sandbox may
inherit the standard process trust inputs `NODE_EXTRA_CA_CERTS`,
`NODE_USE_SYSTEM_CA`, `OPENSSL_CONF`, `OPENSSL_MODULES`, `SSL_CERT_FILE`, and
`SSL_CERT_DIR` for its host network proxy. The probe permits those inherited
inputs and records only a sorted list of the names that were present—never a
path, value, module, configuration, or certificate. Every name remains invalid
as a probe-configuration field. Controller-provided custom trust remains
forbidden and is separately attested in evidence.

P accepts only Vercel's exact documented composition of the configured
`forwardURL` plus the original guest path, and it requires exact single
`vercel-forwarded-*` host/scheme/port/path metadata. Its verifier derives the
issuer-scoped JWKS URL from a safe `https://oidc.vercel.com/...` token issuer.
B does not pretend to observe the guest's original request line: normal-route attribution is
the join of the guest's exact pinned raw-request evidence, the initial
A-terminal syntax controls, and B's independently observed unique
case/correlation receipt. A fallback accepts a rewritten request target only
when the receiver-generated role and opaque receipt exactly join the guest and
readback records for that unique run/case/correlation. Raw fallback paths are
diagnostic only and never substitute for this join.

## Local verification

These commands must remain local-only:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

npx vitest run \
  test/sbx-037-raw-target-probe.test.ts \
  test/sbx-037-receiver.test.ts \
  test/sbx-037-verdict.test.ts \
  test/sbx-037-controller.test.ts

node --check guest/raw-forwardurl-target-probe.mjs

npx tsc --noEmit --strict --exactOptionalPropertyTypes \
  --target ES2022 --module NodeNext --moduleResolution NodeNext \
  --types node --skipLibCheck \
  pocs/SBX-037/receiver.ts \
  pocs/SBX-037/verdict.ts \
  pocs/SBX-037/request-target-origin-escape.ts
```

## Future bounded live prerequisites

Do not run these commands until the coordinating task confirms no other live
Vercel test is active. Three distinct researcher-owned HTTPS origins are needed.
Quick Tunnels can be started first; they may briefly report that their local
origin is unavailable until the receiver starts.

Terminals 1–3:

```sh
cloudflared tunnel --url http://127.0.0.1:43137 --no-autoupdate
cloudflared tunnel --url http://127.0.0.1:43138 --no-autoupdate
cloudflared tunnel --url http://127.0.0.1:43139 --no-autoupdate
```

Treat the resulting HTTPS origins as A, P, and B respectively. In terminal 4:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

export SBX037_ADMIN_KEY='<fresh-random-32+-character-value>'
export SBX037_ACTION_KEY='<different-fresh-random-32+-character-value>'
export SBX037_A_PUBLIC_ORIGIN='https://<owned-a-quick-tunnel>'
export SBX037_P_PUBLIC_ORIGIN='https://<owned-p-quick-tunnel>'
export SBX037_B_PUBLIC_ORIGIN='https://<owned-b-quick-tunnel>'

SBX037_A_PORT=43137 SBX037_P_PORT=43138 SBX037_B_PORT=43139 \
  npx tsx pocs/SBX-037/receiver.ts
```

After all three `/healthz` endpoints respond, terminal 5 uses the same five
`SBX037_*` values plus the explicit HackerOne-alias credentials:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

export SBX037_ADMIN_KEY='<same-admin-value-from-terminal-4>'
export SBX037_ACTION_KEY='<same-action-value-from-terminal-4>'
export SBX037_A_PUBLIC_ORIGIN='https://<same-owned-a-quick-tunnel>'
export SBX037_P_PUBLIC_ORIGIN='https://<same-owned-p-quick-tunnel>'
export SBX037_B_PUBLIC_ORIGIN='https://<same-owned-b-quick-tunnel>'
export SBX037_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'

task_vercel_token=$(node --input-type=module -e '
import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js";
const auth = getAuth();
if (!auth?.token) process.exit(2);
process.stdout.write(auth.token);
')

SBX037_SCOPE_CONFIRMATION='researcher-controlled-sbx037-origins-only' \
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
npx tsx pocs/SBX-037/request-target-origin-escape.ts

task_sbx037_status=$?
unset task_vercel_token
printf 'SBX-037 exit status: %s\n' "$task_sbx037_status"
```

The controller first checks `GET /v2/user`. If the Sandbox CLI token is scoped
and that endpoint returns only `401` or `403`, it requires the exact alias
confirmation above and independently reads the hard-pinned HackerOne-alias team
and project IDs. Any other status, identity mismatch, or resource mismatch fails
before sandbox creation. The evidence records which verification method passed.

The controller holds a fixed live lock, spaces all requests below 5 qps, uses no
redirects or retries, and requires stop, delete, repeated absence confirmation,
receiver-state deletion, and lock release before any candidate is valid.
