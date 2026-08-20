# SBX-043 — SMTP STARTTLS pre-authorization forwarding

Status: **local-only public-canary packet ready; never run against Vercel**.

## Decision

This is credible but lower probability. Vercel documents SNI-based domain
filtering and a special parser for PostgreSQL's pre-TLS upgrade, but does not
document SMTP STARTTLS support. The expected safe behavior under exact
`allow[A]` is therefore fail-closed before the firewall contacts SMTP B.

Port 25 is separately blocked by Vercel. Use a researcher-owned raw listener on
port 587 (or another owned non-25 port); do not use a mail provider.

Primary sources:

- [Vercel Sandbox firewall](https://vercel.com/docs/vercel-sandbox/concepts/firewall)
- [Vercel Postgres firewall support](https://vercel.com/changelog/vercel-sandbox-firewall-now-supports-postgres-connections)
- [Vercel SMTP port-25 limitation](https://vercel.com/kb/guide/serverless-functions-and-smtp)
- [RFC 5321 SMTP](https://www.rfc-editor.org/rfc/rfc5321.html)
- [RFC 3207 STARTTLS](https://www.rfc-editor.org/rfc/rfc3207.html)

RFC 3207's normal flow is server greeting, client `EHLO`, server STARTTLS
advertisement, client `STARTTLS`, server ready response, then TLS. This creates
a pre-SNI client-to-server line. The probe places one random public canary in a
bounded EHLO domain and never sends mail, authentication, or recipient data.

## Decisive proof

The controller runs each case once and spaces probes below 5 qps:

1. Outside Sandbox, owned B completes normal SMTP STARTTLS with certificate and
   hostname verification.
2. A sandbox with `allow-all` completes the same flow.
3. A fresh sandbox starts directly under exact `allow[A]`; active and
   independent same-session policy readbacks must match.
4. HTTPS A returns 200.
5. Direct TLS B and immediate raw B controls produce zero receiver contact.
6. B sends a case-bound `220` greeting. The target sends exactly one
   `EHLO s43p-<canary>.B` and attempts STARTTLS.
7. The exact policy is read back again and a second direct-TLS B control remains
   silent.
8. Both sandboxes are stopped/deleted and all receiver cases are deleted.

Interpretation:

- No SMTP B connection: pass; unsupported SMTP failed closed.
- Case-bound B greeting reaches the guest, but no EHLO reaches B: denied-B reach
  candidate only.
- Exact EHLO canary reaches B while direct/raw controls remain silent:
  defensible Medium policy bypass candidate.
- Direct/raw B also reaches the receiver: alternate simpler root cause; do not
  label the finding SMTP-specific.
- A High claim requires a separately reviewed, fresh-sandbox mode-0600 file
  secret stage after the public candidate. The guest/receiver/verdict contain
  the gated primitive, but this controller intentionally does not execute it.

This may consolidate with SBX-039 if both prove the same generic server-first
pre-authorization root cause. Submit only the strongest reproducible variant
for one root cause.

## Local verification

```sh
python3 -m py_compile guest/smtp-starttls-probe.py

npx vitest run test/sbx-043-smtp-starttls.test.ts

./node_modules/.bin/tsc --noEmit \
  --target ES2022 \
  --module NodeNext \
  --moduleResolution NodeNext \
  --strict \
  --skipLibCheck \
  --types node,vitest/globals \
  pocs/SBX-043/smtp-starttls.ts \
  pocs/SBX-043/verdict.ts \
  pocs/SBX-043/receiver.ts \
  test/sbx-043-smtp-starttls.test.ts
```

The receiver test performs a real local SMTP greeting, EHLO, STARTTLS upgrade,
TLS handshake, and post-TLS EHLO. It stores no raw transcript or proof value.

## Live prerequisites

- One researcher-owned public raw TCP endpoint on port 587.
- A lowercase DNS name B whose A record contains the pinned public IPv4.
- A public-CA certificate/key for B on the receiver.
- B's IPv4 set must be disjoint from the fixed allowed Worker A.
- The authenticated admin API must remain loopback-only (use an SSH local
  forward if the receiver is remote).

Receiver:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX043_ADMIN_KEY="$(openssl rand -hex 32)"
export SBX043_DENIED_HOSTNAME='<OWNED_RAW_B_HOSTNAME>'
export SBX043_DENIED_IPV4='<B_PUBLIC_IPV4>'
export SBX043_DENIED_PORT='587'
export SBX043_ADMIN_PORT='43143'
export SBX043_TLS_KEY_PATH='<B_PRIVATE_KEY_PATH>'
export SBX043_TLS_CERT_PATH='<B_FULLCHAIN_PATH>'
npx tsx pocs/SBX-043/receiver.ts
```

After the receiver reports ready, run the controller with the same admin key
and B values:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX043_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX043_SCOPE_CONFIRMATION='I_CONTROL_DISTINCT_ALLOWED_AND_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_SMTP_STARTTLS_TESTING' \
SBX043_ALLOWED_HTTPS_ORIGIN='https://vsc-h3-action-swve.cyrus-206.workers.dev' \
SBX043_DENIED_HOSTNAME='<OWNED_RAW_B_HOSTNAME>' \
SBX043_DENIED_IPV4='<B_PUBLIC_IPV4>' \
SBX043_DENIED_PORT='587' \
SBX043_ADMIN_ORIGIN='http://127.0.0.1:43143' \
SBX043_ADMIN_KEY='<SAME_ADMIN_KEY>' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-043/smtp-starttls.ts
task_sbx043_status=$?
unset task_vercel_token
printf 'SBX-043 exit status: %s\n' "$task_sbx043_status"
```

A candidate may intentionally return a nonzero status. Use the JSON assessment
and mode-0600 artifact, not the shell exit code alone.
