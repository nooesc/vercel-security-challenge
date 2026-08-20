# SBX-040: HTTP/1 CL.TE desynchronization across transformed virtual hosts

## Concrete hypothesis

This packet tests one specific parser differential, not a generic request-smuggling scan.

The Sandbox policy allows and transforms only owned virtual host A. The guest opens one certificate-verified TLS connection with SNI A and sends a request containing both `Content-Length` and `Transfer-Encoding: chunked`.

The candidate requires this exact split:

1. Vercel treats the full `Content-Length` body as one allowed-A request.
2. The raw owned origin follows `Transfer-Encoding`, ends the A request at `0\r\n\r\n`, and interprets the remaining bytes as a pending request for denied virtual host B.
3. On the same guest TLS connection, the guest sends a separate ordinary request for A. Vercel applies the A-only credential transform to that request.
4. The origin consumes the transformed A request bytes as the body of B's pending request. B validates the exact credential through a keyed commitment and returns only an opaque operation ID.

That construction is protocol-feasible and is the classic CL.TE direction. TE.CL does not provide the required proof here: a CL-priority origin would swallow the next request into the first A request's body rather than create a B virtual-host request.

The live hypothesis can still fail cleanly. Vercel may reject requests containing both framing headers, follow `Transfer-Encoding`, or use a separate upstream connection for each request. Any of those outcomes is a non-finding.

Relevant specifications and product claims:

- <https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length>
- <https://vercel.com/changelog/advanced-egress-firewall-filtering-for-vercel-sandbox>
- <https://vercel.com/changelog/vercel-sandbox-firewall-now-supports-request-proxying-and-filtering>

## Evidence gates

Each stage runs these bounded cases at no more than four starts per second:

1. direct B before the experiment: active firewall block and no receiver event;
2. normal A: exactly one injected transform credential reaches A;
3. TLS/SNI A with an ordinary `Host: B`: rejected, with no B event;
4. Content-Length only: the embedded B bytes remain A's body and cannot create B;
5. Transfer-Encoding only: the embedded B bytes remain chunk data and cannot create B;
6. ambiguous request alone: no B credential action;
7. ambiguous request followed by a separate A request: the sole candidate path;
8. direct B after the experiment: still actively blocked, with no receiver event.

Before and after, active and independent SDK readbacks must show the same session and the exact A-only transform policy. The raw receiver records only request framing lengths/hashes, matching booleans, and opaque operation IDs. It does not retain raw credentials, headers, bodies, command output, or guest configuration.

The public stage must produce the complete B-only action before the controller creates a second sandbox. High-capable evidence requires the same result in that fresh sandbox with a newly generated controller-only transform credential. Without the second reproduction the harness caps its own assessment at a public/Medium candidate. Vercel triage determines the actual severity.

## Required raw topology

A and B must be distinct owned DNS names that resolve to the exact same set of public IPv4 addresses. Both names must terminate directly at this byte-preserving TLS listener on TCP/443, and the certificate must cover both names. A CDN, Worker, Quick Tunnel, or HTTP reverse proxy is not valid because it may reject or normalize the ambiguous bytes before this receiver sees them.

The shared IP is intentional: A and B are separate HTTP virtual hosts on one origin. The denied-domain proof is `Host: B`, while the transport stays on the already-authorized A connection. The controller independently reaches both SNI/Host combinations and requires the receiver-specific terminal header before it creates a sandbox.

The admin API binds only to loopback. If the controller runs on another owned machine, forward it locally, for example:

```sh
ssh -N -L 43140:127.0.0.1:43140 <owned-raw-origin>
```

Do not expose the admin port publicly.

## Local verification

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
node --check guest/http1-desync-probe.mjs
npx vitest run test/sbx-040-receiver.test.ts test/sbx-040-verdict.test.ts
npx tsc --noEmit --strict --noUncheckedIndexedAccess --exactOptionalPropertyTypes \
  --target ES2022 --module NodeNext --moduleResolution NodeNext --skipLibCheck \
  --types node,vitest/globals \
  pocs/SBX-040/receiver.ts pocs/SBX-040/verdict.ts pocs/SBX-040/http1-desync.ts \
  test/sbx-040-receiver.test.ts test/sbx-040-verdict.test.ts
```

## Receiver on the owned raw origin

Generate the admin value locally; do not paste or commit it.

```sh
cd "/path/to/vercel-security-challenge"
export SBX040_ADMIN_KEY="$(openssl rand -hex 32)"
export SBX040_TLS_KEY_PATH='/absolute/path/to/a-b.key.pem'
export SBX040_TLS_CERT_PATH='/absolute/path/to/a-b.fullchain.pem'
export SBX040_RAW_HOST='0.0.0.0'
export SBX040_RAW_PORT=443
export SBX040_ADMIN_HOST='127.0.0.1'
export SBX040_ADMIN_PORT=43140
npx tsx pocs/SBX-040/receiver.ts
```

Wait for `{"ready":true,"rawPort":443,"adminPort":43140}`. Confirm that the A and B DNS records both point directly to this host and that public TLS verification succeeds for both names.

## Controller (live only after raw infrastructure is explicitly authorized)

No live call was made while building or validating this packet.

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX040_SCOPE_CONFIRMATION='I_CONTROL_BOTH_SBX040_VIRTUAL_HOSTS_AND_AUTHORIZE_BOUNDED_HTTP1_DESYNC_TESTING' \
SBX040_ADMIN_KEY="$SBX040_ADMIN_KEY" \
SBX040_ADMIN_ORIGIN='http://127.0.0.1:43140' \
SBX040_A_PUBLIC_ORIGIN='https://a.<owned-domain>' \
SBX040_B_PUBLIC_ORIGIN='https://b.<owned-domain>' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-040/http1-desync.ts
task_sbx040_status=$?
unset task_vercel_token
printf 'SBX-040 exit status: %s\n' "$task_sbx040_status"
```

Use the JSON assessment and private artifact, not the process exit status alone. A candidate may intentionally end with a nonzero status elsewhere in the harness; an infrastructure or attribution failure is always inconclusive here.
