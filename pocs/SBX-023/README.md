# SBX-023: `forwardURL` reserved-header integrity

This packet tests whether guest-supplied `vercel-forwarded-*` metadata survives
the Vercel Sandbox firewall's server-side `forwardURL` processing and changes the
authenticated original request reconstructed by the official
`defineSandboxProxy` helper.

The strongest differential keeps the real request path identical. Both baseline
and decisive host cases request the action suffix from allowed origin A. The
baseline must reconstruct `https://A/.../forwarded-action`; the attack adds only
a guest-supplied B authority and can become a candidate only if the helper
authenticates the exact sandbox and reconstructs
`https://B/.../forwarded-action`. This preserves the forwarding URL's OIDC
audience normalization and isolates authority mutation from path mutation.

## Exact authorized scope

The controller is invocation-pinned for one bounded run to:

- A: the exact fresh `SBX023_A_PUBLIC_ORIGIN` Quick Tunnel origin
- B: the distinct exact fresh `SBX023_B_PUBLIC_ORIGIN` Quick Tunnel origin
- alias: `swve@wearehackerone.com`
- team: `team_n98ERpVwV7HqmWRudAyK8sXQ`
- project: `prj_CyyVykdN06Nrkla6KidZcecLgbCa`

Both environment values must be lowercase origin-only HTTPS URLs under
`trycloudflare.com`; paths, ports, credentials, queries, fragments, and equal
A/B origins are rejected. Both Quick Tunnel origins route to the
researcher-controlled observer. Before
creating a sandbox, the controller performs an admin-authenticated event query
through both hard-pinned origins and requires an empty fresh run. B also requires
an authenticated proxy-configuration write and exact readback. The fixed scope
confirmation is mandatory.

The explicit `VERCEL_TOKEN`/`VERCEL_TEAM_ID`/`VERCEL_PROJECT_ID` triple is
required; inferred credentials are rejected. The token is checked against
`/v2/user`, and its email must be the exact eligible alias.

## Controls and matrix

The maximum is 16 sequential endpoint requests, with no retries or redirects and
at least 500 ms between requests (at most 2 requests/second):

1. The sandbox starts with a temporary exact allow list containing only A and B.
   Active and independent handles must read back that policy on the same SDK
   session.
2. Under that temporary policy, a direct B control uses one controller-resolved,
   pinned public B IPv4 address with B's TLS SNI and Host. It must prove a TCP
   connection to that exact IP and port 443, complete TLS, receive B's exact HTTP
   204, and produce exactly one correlated B observer event with no proxy action.
3. The same sandbox is updated to the final A-to-B `forwardURL` policy and given
   1.5 seconds to settle. Both active and independent `sandbox.networkPolicy`
   getters must show the SDK's documented `{allow: [A]}` projection, while both
   same-session `currentSession().networkPolicy` values must retain the exact full
   A-to-B `forwardURL` rule.
4. A direct request to the same pinned B IP and port must then complete TCP but
   receive `ECONNRESET` within two seconds, before TLS or HTTP, with no B event or
   proxy action. `errno` may be absent or Linux `-104`; `syscall` may be absent,
   `connect`, or `read`. DNS failures, timeouts, unreachable/refused connections,
   TLS failures, HTTP errors, wrong peers, and slower resets are never firewall
   proof.
5. The baseline requests the action suffix from A and must produce one
   OIDC-authenticated operation reconstructing the exact A/action URL and exact
   team/project/session/name claims.
6. The fixed attack matrix tests unique host authority, scheme/port, fake OIDC,
   duplicate/case variants, and path fail-closed behavior. Decisive host cases
   keep the real A action path and do not override forwarded path or OIDC.
7. The projected/full same-session final-policy readback and same-IP fast-reset
   control are repeated after the attack matrix.

The controller stops early after any B-only action, but still executes the
post-attack policy and direct-denial controls. A clean `pass` requires the entire
fixed attack matrix.

## Root-cause attribution

The observer audits reserved metadata from Node's `IncomingMessage.rawHeaders`
before converting the request to WHATWG `Headers` or invoking
`defineSandboxProxy`. It retains ordered, bounded non-secret field names and
values plus OIDC header counts; it never retains an OIDC value. The guest-created
fake OIDC value is detected only by comparing a controller-registered SHA-256
digest and is retained as a boolean.

Quick Tunnels may lowercase, combine, or reorder duplicate headers before the
application hop, so duplicate-order-only action signals are always
`indeterminate`. A `candidate` requires all of:

- exact initial/final policy and same-session controls, plus same-IP positive
  TCP/TLS/HTTP reachability followed by conclusive pre/post fast resets;
- one baseline operation with exact raw metadata, exact A/action reconstruction,
  exact OIDC identity, and matching opaque operation ID;
- a unique guest-controlled B authority visible in the pre-helper raw audit;
- exact authenticated B/action reconstruction and the same opaque operation ID
  in the guest response and observer record.

The official helper supplies cryptographic OIDC authentication. The independent
pre-helper audit is what distinguishes a Vercel forwarding-boundary signal from
a helper-only duplicate-normalization behavior.

## Evidence and cleanup

The guest returns only structured response fields and structured connection
errors. Raw HTTP response bodies and arbitrary error messages are not retained.
The observer scrubs all credential-bearing headers before event persistence. The
controller rejects evidence containing the Vercel token, observer admin key, or
raw fake OIDC value, then creates the schema-v3 private artifact with mode `0600`
and exclusive `wx` semantics. Direct controls retain only structured socket peer,
TLS, HTTP, timing, and error-code telemetry.

Every SDK operation has an abort deadline. Sandbox names and tags contain the
full UUID. An ambiguous create is recovered only after exact tag and creation-time
checks; an unrelated resource is left untouched. Stop/delete are followed by
three independent `404` confirmations. Observer proxy configuration deletion is
also read back as absent. `candidate`, `indeterminate`, and `error` exit nonzero.

## Local verification

```sh
npx vitest run \
  test/forwarded-header-probe.test.ts \
  test/sbx-023-forwarded-metadata.test.ts \
  test/observer.test.ts

npx tsc --noEmit -p tsconfig.poc.json
```

## Authorized live command

Start the observer and two fresh Quick Tunnels to its local port, then pin their
exact origins in the controller invocation:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

export SBX023_SCOPE_CONFIRMATION=I_CONTROL_BOTH_PINNED_TRYCLOUDFLARE_ORIGINS_AND_AUTHORIZE_BOUNDED_FORWARDING_TESTING
export SBX023_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'
export SBX023_A_PUBLIC_ORIGIN='https://<fresh-A>.trycloudflare.com'
export SBX023_B_PUBLIC_ORIGIN='https://<fresh-B>.trycloudflare.com'

task_sbx023_vercel_token=$(node --input-type=module -e '
  import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js";
  const auth = getAuth();
  if (!auth?.token) process.exit(2);
  process.stdout.write(auth.token);
')

DOTENV_CONFIG_PATH=.env.local \
VERCEL_TOKEN="$task_sbx023_vercel_token" \
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
npx tsx pocs/SBX-023/forwarded-metadata.ts
task_sbx023_status=$?
unset task_sbx023_vercel_token
printf 'SBX-023 exit status: %s\n' "$task_sbx023_status"
```

The token command must resolve to the verified alias account. A candidate still
requires a fresh manual reproduction and evidence review before submission.
