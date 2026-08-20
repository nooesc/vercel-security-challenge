# SBX-048 — `forwardURL` OIDC token accepted by the Sandbox control plane

Status: **LOCAL-ONLY READY; NOT LIVE-RUN.** This packet must not be run while another bounded
Vercel test is active. It needs one fresh researcher-owned HTTPS Quick Tunnel and one fresh owned
Sandbox. No Vercel, tunnel, DNS, or public endpoint was contacted while implementing or testing it.

## Hypothesis

The Sandbox firewall sends a short-lived, Vercel-signed JWT to the configured `forwardURL` in the
`vercel-sandbox-oidc-token` header. Its exact audience is the proxy URL, and its claims identify the
source team, project, session, and sandbox name. The receiving proxy is supposed to use that token
only to authenticate the forwarded request.

The Sandbox control-plane SDK also authenticates to `https://vercel.com/api/v2|v3/sandboxes/...`
with bearer Vercel OIDC JWTs. If the server accepts the proxy JWT without enforcing its proxy-only
audience and purpose, a service that is trusted only as the egress proxy can use that JWT to read or
change the originating sandbox.

This is credible at the server boundary, not an SDK-only observation:

- installed `@vercel/sandbox@3.0.0` sends its token as `Authorization: Bearer ...` to the Sandbox
  control plane (`dist/api-client/base-client.js`);
- the installed SDK expressly accepts Vercel OIDC JWTs as control-plane credentials, selecting
  `owner_id` and `project_id` (`dist/utils/get-credentials.js`);
- the proxy verifier accepts a separately scoped RS256 JWT from the same team-scoped
  `https://oidc.vercel.com/...` issuer, requires audience=`forwardURL`, and reads `team_id`,
  `project_id`, `sandbox_id`, and `sandbox_name` (`dist/proxy.js`);
- prior owned live evidence already confirmed that exact issuer/audience/source-identity shape, but
  retained neither the raw token nor a token digest.

Acceptance remains only a hypothesis until this packet is personally run. A 401/403 is the expected
clean negative.

## Fixed live sequence

The packet allows exactly this sequence:

1. Verify the exact HackerOne-alias account, owned team, and owned project.
2. Create one fresh named sandbox with one owned proxy hostname directly allowed.
3. Configure the owned receiver with the exact run, sandbox name/session, forward audience, source
   path, and correlation canary.
4. Run one direct owned-origin control. It must use verified TLS, contain no brokered OIDC header,
   and join one opaque receiver operation ID.
5. Install and independently read back the exact `hostname -> forwardURL` policy. An owner PAT then
   performs one raw, non-retrying GET of the exact session route and must receive the exact source
   session and raw custom-policy shape.

   The current top-level Sandbox projection exposes only the exact allowed-host list, while
   `currentSession().networkPolicy` retains the exact `forwardURL` rule. The controller requires
   that exact split plus the raw owner-token policy response; it does not infer the rule from the
   host list alone.
6. The receiver sends one deliberately invalid bearer value to the same route. It must receive
   401/403. This proves the endpoint is not anonymously readable.
7. Run one guest request. The receiver independently verifies RS256, the exact team-scoped issuer,
   the exact proxy audience, temporal claims, and exact source team/project/session/name. It also
   verifies the same JWT fails JOSE verification for a distinct wrong audience.
8. Without retaining the JWT or its digest, the receiver sends it in exactly one raw, non-retrying
   GET to `/api/v2/sandboxes/sessions/:sessionId?teamId=<verified-team_id>`.
9. Only if that GET returns 200 with the exact session and original raw forward-policy shape, the
   receiver sends exactly one `POST .../network-policy` with `{ "mode": "deny-all" }` using that
   same transient JWT. A rejected or malformed read can never trigger the mutation.
10. The owner PAT immediately reads the same session route. If the mutation was accepted, both raw
    and independent SDK reads must show literal deny-all on the pinned live session while the named
    sandbox default remains the original forward policy.
11. The owner PAT restores the pinned live session to the exact original policy and verifies it by
    raw and independent SDK reads before stop/delete. A `finally` path repeats this restoration if
    any post-probe step fails. Sandbox deletion needs two independent 404s, receiver state is deleted,
    and the live lock is removed.

Proxy-token control-plane request counts are therefore exactly two for a clean rejection
(fake GET + brokered GET) or exactly three for an accepted read
(fake GET + brokered GET + conditional mutation). Calls are spaced by at least 250 ms. The receiver
has no SDK retry path.

## Verdict and impact boundary

- **pass:** every control passes, the proxy JWT receives 401/403 on the exact source-session read,
  no mutation occurs, the owner sees the original policy, and cleanup is exact.
- **candidate / read-only:** the audience-restricted proxy JWT receives 200 for the exact session
  and original policy. This alone is a real authentication/audience bypass; do not inflate its
  severity without the program's impact mapping.
- **candidate / modification:** the exact read succeeds, the conditional deny-all mutation returns
  an exact response, the owner independently observes that mutation, and the owner restores the
  original policy before cleanup.
- **indeterminate:** every other response/status/policy shape, extra/missing call, attribution gap,
  TLS-trust gap, failed restoration, or cleanup problem.

Do not claim credential exfiltration, High, cross-tenant access, or sandbox takeover beyond what a
live artifact proves. The strongest planned result is same-owned-sandbox policy modification by a
proxy-audience credential. Severity is for Vercel triage.

## Token and TLS handling

- The raw proxy JWT exists only in the receiver request scope and the two bounded `fetch` calls.
  It is never logged, returned, hashed, or stored. Evidence records only signature/audience/source
  verification booleans, allowlisted identity values already owned by the researcher, and whether
  `owner_id` / `team_id` claim names were present.
- Control-plane response bodies are parsed in bounded buffers, zeroed where practical, and reduced
  to status/exact-session/exact-policy booleans. Headers and bodies are not retained.
- The controller requires an opaque PAT, preventing the SDK's ambient OIDC refresh path from adding
  hidden requests.
- The local controller and receiver reject `NODE_TLS_REJECT_UNAUTHORIZED=0`, non-empty
  `NODE_OPTIONS`, and every process-level CA/OpenSSL trust override before any action or bind. The
  guest rejects global verification disablement and additionally fixes `rejectUnauthorized: true`,
  exact SNI/Host, no proxy environment use, no retries, and no redirects. Platform-inherited guest
  trust variables are retained only as a sorted allowlisted list of names, never values.
  Configuration cannot add `ca`, `secureContext`, or `checkServerIdentity`.

## One-tunnel runbook (do not run until coordinated)

Use three terminals. Replace only `<P>` with the lower-case Quick Tunnel hostname and generate a
fresh admin value locally. Never paste the admin value or any Vercel token into chat.

Terminal 1 — tunnel:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43148
```

Terminal 2 — receiver:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX048_ADMIN_KEY="$(openssl rand -hex 32)"
printf '%s' "$SBX048_ADMIN_KEY" | pbcopy
export SBX048_PUBLIC_ORIGIN='https://<P>.trycloudflare.com'
export SBX048_PORT=43148
npx tsx pocs/SBX-048/receiver.ts
```

Wait for `{"ready":true,"port":43148}`. Keep that terminal open. The command above placed the fresh
value on the local clipboard without printing it; Terminal 3 reads the same value with `pbpaste`.

Terminal 3 — controller:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX048_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX048_SCOPE_CONFIRMATION='I_CONTROL_SBX048_PROXY_ORIGIN_AND_AUTHORIZE_ONE_BOUNDED_OIDC_CONTROL_PLANE_TEST' \
SBX048_ADMIN_KEY="$(pbpaste)" \
SBX048_PUBLIC_ORIGIN='https://<P>.trycloudflare.com' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-048/oidc-control-plane-confusion.ts
task_sbx048_status=$?
unset task_vercel_token
printf 'SBX-048 exit status: %s\n' "$task_sbx048_status"
```

Exit code 2 means candidate, 0 means clean rejection/pass, and 1 means indeterminate/error. Use the
private JSON artifact and cleanup fields, not exit code alone. Stop the receiver and tunnel only
after the controller reports exact cleanup.

## Local verification

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
npx vitest run test/sbx-048-guest.test.ts test/sbx-048-receiver.test.ts test/sbx-048-verdict.test.ts \
  test/sbx-048-controller.test.ts test/sbx-048-sdk-audit.test.ts
node --check guest/sbx-048-forward-probe.mjs
./node_modules/.bin/tsc --noEmit --skipLibCheck --strict --exactOptionalPropertyTypes \
  --noUncheckedIndexedAccess --module NodeNext --moduleResolution NodeNext --target ES2022 \
  --types node pocs/SBX-048/verdict.ts pocs/SBX-048/receiver.ts \
  pocs/SBX-048/oidc-control-plane-confusion.ts
```
