# SBX-039 — MySQL server-first pre-authorization forwarding

Status: **public-canary live controller implemented and locally verified; no live run has occurred**.

## Decision

This is technically testable, but lower probability than SBX-036.

Vercel's current Sandbox firewall documentation lists domain filtering support
for HTTP/HTTPS and Postgres, not MySQL. MySQL compatibility is therefore not an
expected feature. Under an exact `allow[A]` policy, the correct result is a
fail-closed timeout before the firewall contacts denied endpoint B.

The security question is narrower: does the firewall speculatively connect to B
to relay MySQL's server-first greeting, then forward client bytes before it has
authorized the later TLS SNI?

Primary protocol evidence:

- Vercel Sandbox firewall: <https://vercel.com/docs/sandbox/concepts/firewall>
- MySQL connection phase: <https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_connection_phase.html>
- MySQL HandshakeV10: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html>
- MySQL SSLRequest: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html>

MySQL's documented encrypted flow is:

1. Server B sends `HandshakeV10`.
2. Client sends a 32-byte `SSLRequest` packet.
3. Client and server perform TLS, starting with ClientHello/SNI.
4. The client sends its authentication response inside TLS.

Unlike SBX-036, this does not depend on the PostgreSQL SSLRequest parser. The
candidate root cause is speculative upstream connection or pre-authorization
forwarding for a server-first upgrade protocol.

## Falsifiable public proof

The receiver sends a valid, per-case tagged MySQL greeting. The guest then sends
an exact MySQL SSLRequest followed by a real TLS ClientHello. A 32-hex public
canary is placed in a syntactically valid denied SNI label:

`s39p-<canary>.<denied-owned-hostname>`

Only an exact receiver-side match produces an opaque operation ID. The receiver
does not retain raw ClientHello, SNI, or payload bytes.

Minimum matrix:

1. Outside-Sandbox coalesced B preflight succeeds.
2. `allow-all` direct-TLS B control succeeds.
3. `allow-all` normal split MySQL SSLRequest / ClientHello control succeeds.
4. `allow-all` MySQL coalesced B target-shape control succeeds.
5. Stop/delete the allow-all sandbox.
6. Create a fresh sandbox directly under exact `allow[A]`; verify active and
   independent same-session readbacks.
7. HTTPS A health control returns 200.
8. Direct denied-SNI ClientHello to B yields no B connection or receipt.
9. Immediate raw public frame to B yields no B connection or receipt.
10. Split MySQL SSLRequest / ClientHello negative runs with a fixed delay.
11. Coalesced MySQL SSLRequest + ClientHello target runs once.
12. Repeat the policy readback and direct denied-SNI negative.
13. Stop/delete the restricted sandbox and delete every receiver case.

Interpretation:

- No B connection: pass; unsupported MySQL failed closed.
- B connection plus exact tagged greeting at the guest, but no client canary at
  B: candidate pre-authorization reach, likely Medium at most.
- Exact public canary at B while direct/raw controls are absent: defensible
  public policy bypass candidate.
- Direct TLS or raw frame also reaches B: alternate, simpler root cause; do not
  label it MySQL-specific.
- A High claim requires a separate fresh sandbox and exact one-time mode-0600
  synthetic file secret receipt. The verdict/receiver/guest have that gated
  primitive, but the public stage must succeed first.

## Local verification

```sh
npx vitest run \
  test/sbx-039-controller.test.ts \
  test/sbx-039-guest.test.ts \
  test/sbx-039-receiver.test.ts \
  test/sbx-039-verdict.test.ts

./node_modules/.bin/tsc --noEmit \
  --target ES2022 \
  --module NodeNext \
  --moduleResolution NodeNext \
  --strict \
  --skipLibCheck \
  --types node \
  pocs/SBX-039/mysql-server-first-upgrade.ts \
  pocs/SBX-039/verdict.ts \
  pocs/SBX-039/receiver.ts \
  test/sbx-039-guest.test.ts \
  test/sbx-039-controller.test.ts \
  test/sbx-039-receiver.test.ts \
  test/sbx-039-verdict.test.ts

python3 -m py_compile guest/mysql-upgrade-probe.py
```

The receiver tests use a real Node-generated TLS ClientHello and exercise
segmented TCP delivery of the exact MySQL SSLRequest and ClientHello. No public
endpoint or Vercel request is made by these tests.

## Live public-canary command

The B hostname/IP/port must route to the researcher-owned raw receiver, and its
resolved IPv4 set must be disjoint from the fixed A Worker. Keep the admin API
on loopback (or reach it through a local SSH forward).

Receiver terminal:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX039_ADMIN_KEY='<FRESH_RANDOM_64_HEX>'
export SBX039_DENIED_HOSTNAME='<OWNED_RAW_B_HOSTNAME>'
export SBX039_DENIED_IPV4='<ONE_CURRENT_PUBLIC_A_RECORD_FOR_B>'
export SBX039_DENIED_PORT='8443'
export SBX039_ADMIN_PORT='43139'
npx tsx pocs/SBX-039/receiver.ts
```

Wait for the one-line `{"ready":true,...}` response. Then run the controller
with the same values:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX039_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX039_SCOPE_CONFIRMATION='I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_MYSQL_PRETLS_TESTING' \
SBX039_ALLOWED_HTTPS_ORIGIN='https://vsc-h3-action-swve.cyrus-206.workers.dev' \
SBX039_DENIED_HOSTNAME='<OWNED_RAW_B_HOSTNAME>' \
SBX039_DENIED_IPV4='<ONE_CURRENT_PUBLIC_A_RECORD_FOR_B>' \
SBX039_DENIED_PORT='8443' \
SBX039_ADMIN_ORIGIN='http://127.0.0.1:43139' \
SBX039_ADMIN_KEY='<SAME_RANDOM_64_HEX>' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-039/mysql-server-first-upgrade.ts
task_sbx039_status=$?
unset task_vercel_token
printf 'SBX-039 exit status: %s\n' "$task_sbx039_status"
```

Generate the admin value locally with `openssl rand -hex 32`; do not paste or
commit it. The controller uses only public canaries, runs each case once, writes
a mode-0600 artifact, and always attempts stop/delete. A candidate remains
Medium until a separately reviewed fresh-secret stage is implemented and run.

## Files

- `guest/mysql-upgrade-probe.py`: one-attempt probe and plan validation.
- `receiver.ts`: raw MySQL greeting listener, TLS ClientHello/SNI parser, and
  loopback-only authenticated case API.
- `verdict.ts`: strict public, alternate-root, reach-only, pass, and gated
  fresh-secret classifications.
- `mysql-server-first-upgrade.ts`: public-only Vercel lifecycle controller with
  outside, allow-all, fresh exact-allow, readback, negative, target, and cleanup
  stages. It registers exactly one receiver case at a time.
