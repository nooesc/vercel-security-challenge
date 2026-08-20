# SBX-036 — PostgreSQL pre-TLS coalescing fail-open

Status: **local harness ready; never run live**.

## Hypothesis

The PostgreSQL-aware firewall may recognize the exact eight-byte PostgreSQL
`SSLRequest` but forward bytes coalesced immediately after it before applying
the TLS SNI/domain policy. The hostile packet is:

```text
00 00 00 08 04 d2 16 2f || bounded discriminator
```

The discriminator suffix is deliberately adversarial parser-smuggling. It is
**not** claimed to be a standards-valid PostgreSQL TLS flight. A reportable
public signal requires an independently owned denied listener to attest that
the exact discriminator arrived. A High candidate additionally requires a
fresh sandbox to send one file-backed synthetic secret and the receiver to
validate it against a controller-registered commitment.

The official references behind the model are:

- [Vercel: Sandbox firewall now supports Postgres connections](https://vercel.com/changelog/vercel-sandbox-firewall-now-supports-postgres-connections) — Vercel says the domain policy is applied before the Postgres connection is forwarded.
- [PostgreSQL: Message Flow](https://www.postgresql.org/docs/current/protocol-flow.html) — describes the SSL negotiation and the server's one-byte `S`/`N` response.
- [PostgreSQL: Message Formats](https://www.postgresql.org/docs/current/protocol-message-formats.html) — defines `SSLRequest` as length 8 and code 80877103.

## Required owned topology

- Allowed A: the fixed owned HTTPS health endpoint
  `vsc-h3-action-swve.cyrus-206.workers.dev:443`.
- Denied B: an owned DNS hostname resolving directly to an owned public IPv4
  and raw TCP listener, on a configurable port from 1–65535.
- A and B must have completely disjoint resolved public IPv4 sets. This is
  required because the raw pre-TLS packet does not identify B by hostname.
- B must present a publicly trusted certificate for its hostname so the normal
  PostgreSQL/TLS interoperability controls can verify both chain and hostname.
- The receiver admin API stays on `127.0.0.1`; use an SSH local forward when
  the data listener is remote.

Do not use an HTTP/TLS tunnel, Tailscale Funnel, or a private-only `*.ts.net`
address for B. They do not provide the direct raw TCP + public-DNS attribution
this proof needs. Creating DNS, certificates, listeners, SSH forwards, or
firewall rules requires the operator's explicit authorization.

## Safety and verdict gates

The controller uses one attempt per case, no retries, a 300 ms inter-probe gate
(at most 3.34 qps), bounded reads, exact active and independent same-session
policy readback, and mandatory stop/delete cleanup. Before the first
`Sandbox.create`, it reads the receiver ledger and fails closed unless the
configured epoch and exactly three outside receipts are exact: normal TLS,
coalesced pre-TLS, and the raw control. Missing, duplicate, unexpected,
wrong-operation, wrong-listener, retained-payload, or reused-connection evidence
causes zero Sandbox create calls.

Local lifecycle state uses the fixed repo-root
`artifacts/SBX-036-live-active.lock` plus a per-root-run mode-`0600` recovery
journal. The lock wrapper reuses the frozen SBX-053 ownership/lease transaction
implementation; `SBX-053-GIT-CREDENTIAL-RETENTION` in lock metadata is therefore
the lock implementation identifier, not SBX-036 experiment provenance. The
SBX-036 journal independently binds both deterministic sandbox names, all five
tags, nonpersistence, canonical sessions, public/secret receiver run IDs, and
every create/stop/delete intent and result. It never stores a token, canary,
operation ID, secret, commitment, digest, guest output, or response body.

Cleanup runs secret before public, deletes every attempted receiver state,
requires three spaced exact-name 404s plus an empty exact-prefix list, and
requires three receiver `configured:false` readbacks. A create response without
an authoritative handle remains cleanup-indeterminate until the 45-second
request window, requested 300-second sandbox lifetime, and 30-second margin all
expire; only then can three named absences plus prefix-list absence settle it.
An exact get/list recovery candidate is journaled before stop/delete. If the
secret-file write was attempted, cleanup first overwrites its fixed path with a
fixed nonsecret mode-`0600` value. The journal and lock are released only after
all attempted sandbox and receiver state is conclusively absent. Artifacts are
unique, no-clobber, mode `0600`, and retain neither response bodies,
discriminators, secret values, nor secret digests.

The public stage requires all of these controls:

1. Outside Sandbox, normal B PostgreSQL/TLS succeeds.
2. Outside Sandbox, `SSLRequest || public discriminator` reaches B.
3. Outside Sandbox, the same raw discriminator without `SSLRequest` reaches B.
4. Under `allow-all`, normal B PostgreSQL/TLS and the coalesced packet reach B.
5. Under exact `allow[A]`, A HTTPS succeeds while normal B TLS and raw B are
   blocked with no B receipt.
6. Under the same restricted policy, only the coalesced target is attempted,
   followed by policy reread and another normal B negative.

A public receipt is a Medium candidate. Only after that candidate and successful
cleanup does the controller create a fresh sandbox for the secret stage. The
secret is generated after public controls, written to the fixed guest path with
mode `0600`, sent once, overwritten in the guest, and never put in guest config
or retained evidence. A commitment-backed opaque `pgs_…` receipt is a High
candidate. A conclusive pre-connect target block with no receipt is a clean
pass. Anything missing an exact control is indeterminate, not a finding.

## Local verification

These checks make no Vercel or public endpoint calls:

```sh
npx vitest run test/sbx-036-postgres-pre-tls-coalescing.test.ts
npx vitest run test/sbx-036-safety.test.ts
npx tsc --noEmit -p tsconfig.poc.json
python3 -c 'compile(open("guest/postgres-pre-tls-coalescing-probe.py", "rb").read(), "guest/postgres-pre-tls-coalescing-probe.py", "exec")'
```

The focused suite includes segmented `SSLRequest`/frame delivery and an
end-to-end local `SSLRequest || ClientHello` MemoryBIO handshake into the
receiver's `TLSSocket` path.

## Operator commands (do not run until prerequisites are independently checked)

On the owned B host, start the direct listener. Replace bracketed values only:

```sh
cd "/path/to/vercel-security-challenge"
export SBX036_ADMIN_KEY='<fresh high-entropy admin key>'
export SBX036_ALLOWED_HOSTNAME='vsc-h3-action-swve.cyrus-206.workers.dev'
export SBX036_ALLOWED_IPV4='<one current A IPv4; must match receiver metadata>'
export SBX036_ALLOWED_PORT='443'
export SBX036_DENIED_HOSTNAME='<owned public B hostname>'
export SBX036_DENIED_IPV4='<owned public B IPv4>'
export SBX036_DENIED_BIND_HOST='<B bind address>'
export SBX036_DENIED_PORT='<B public/listen port>'
export SBX036_DENIED_CERT_PATH='<public certificate chain path>'
export SBX036_DENIED_KEY_PATH='<private key path>'
export SBX036_ADMIN_PORT='43136'
npx tsx pocs/SBX-036/receiver.ts
```

Expose only the raw B data port. Reach the loopback admin API locally or with an
SSH local forward. Then, from the controller host:

```sh
cd "/path/to/vercel-security-challenge"
export VERCEL_TOKEN='<verified HackerOne-alias token>'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export SBX036_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'
export SBX036_SCOPE_CONFIRMATION='I_CONTROL_DISTINCT_HTTPS_ALLOW_AND_DIRECT_POSTGRES_DENIED_ENDPOINTS_AND_AUTHORIZE_BOUNDED_PRETLS_TESTING'
export SBX036_ALLOWED_HTTPS_ORIGIN='https://vsc-h3-action-swve.cyrus-206.workers.dev'
export SBX036_DENIED_HOSTNAME='<same owned B hostname>'
export SBX036_DENIED_IPV4='<same owned B IPv4>'
export SBX036_DENIED_PORT='<same B port>'
export SBX036_ADMIN_ORIGIN='http://127.0.0.1:43136'
export SBX036_ADMIN_KEY='<same admin key>'
npx tsx pocs/SBX-036/postgres-pre-tls-coalescing.ts
```

If an interrupted run retains its journal and fixed lock, do not rerun the
experiment or retry either create. An exact untouched journal with no receiver
configure or Sandbox create intent is finalized locally before credentials or
topology are read. Otherwise, keep the same exact identity, topology, and admin
variables present and run cleanup-only recovery using the root UUID from
`artifacts/SBX-036-recovery-<ROOT-UUID>.json`:

```sh
npx tsx pocs/SBX-036/postgres-pre-tls-coalescing.ts --recover '<ROOT-UUID>'
```

Recovery performs no create. It writes a separate unique mode-`0600`
`recoveryOnly:true` artifact with no assessment, candidate, or experiment
verdict fields. Any unproven create response, provenance mismatch, incomplete
secret neutralization, sandbox absence, or receiver absence retains the lock
and journal as cleanup-indeterminate.

The JSON assessment and mode-0600 artifact are authoritative; an error or
indeterminate result must not be submitted as a vulnerability.
