# SBX-001 direct authoritative deny-all DNS discriminator

This is the preferred SBX-001 packet. It asks one falsifiable question: after a sandbox's active policy becomes the literal `deny-all`, can the host resolver still forward an operator-controlled DNS query to the researcher-owned authoritative server?

The older `run.ts` / `verify.ts` packet remains as a sampled Cloudflare-analytics fallback. It cannot turn an absent sampled row into a clean negative. `direct-run.ts` uses a direct UDP+TCP authoritative receiver, so a controlled run can produce a defensible `pass`, Medium public signal, or High file-secret candidate without waiting for adaptive analytics.

## What the direct packet proves

One fresh non-persistent sandbox performs this exact sequence:

1. The controller verifies the HackerOne alias (including the scoped-token fallback) and requires an exact one-NS/one-A delegation with no AAAA or CNAME ambiguity.
2. The controller generates a different 128-bit nonce for every public case. Immediately before each query it arms only that case at the receiver. The receiver enforces the sequence and ignores exact names observed before their case was armed.
3. The controller sends one UDP and one TCP query directly to the owned authoritative IPv4. Both must receive authoritative answers and exact post-arm receiver receipts.
4. Under `allow-all`, ordinary HTTPS to the owned control Worker succeeds and one fresh public DNS canary reaches the authoritative receiver.
5. The same sandbox session updates to literal `deny-all`. Active and independent handles must report the same original `sbx_...` session and literal policy.
6. Ordinary HTTPS must fail with an attributable firewall signal (`EAI_AGAIN` or `EHOSTUNREACH`), not a timeout or refused endpoint.
7. The guest sends one fresh public A query with no secret and no retry. `datagramAcceptedByKernel` becomes true only after the zero-error UDP send callback (or a response). The controller polls the loopback receiver for a bounded five-second observation window. A kernel-accepted datagram with no ingress is `indeterminate`, never `pass`; a clean negative requires an attributable local firewall rejection and zero exact ingress.
8. Only after an exact post-arm deny-all public receipt, the controller creates a fresh random 16-byte value and a separate fresh 128-bit secret-case nonce, registers the keyed commitment in receiver memory, writes the value as a mode-`0600` file, and arms one final case.
9. The guest reads the file and encodes the value into one 59-byte DNS label. A High candidate requires the receiver to decode that exact label in memory, match the registered HMAC commitment, and return the expected opaque HMAC operation ID through its loopback admin API.
10. The controller stops/deletes the sandbox, confirms three independent 404s plus an exact prefix-list absence, then takes a final receiver snapshot before deleting receiver state and confirming three receiver-state 404s. The receiver commits sanitized ingress before attempting a UDP/TCP response and updates `authoritativeResponseSent` separately, so a send error or peer reset cannot erase boundary evidence.
11. Before any receiver or Sandbox mutation, the controller creates a mode-`0600`, fsynced recovery journal under an ownership-bound live lock. Every configure/create/stop/delete/receiver-delete/artifact transition is checkpointed. A response-lost create with no attributable session remains uncertain through the 45-second request deadline, 300-second non-persistent lifetime, and a 30-second terminal margin; only then can 16 exact-name absences over 30 seconds plus a prefix-list absence close it. The journal and lock are retained on all uncertainty. The private artifact is fsynced before the journal/lock release transaction commits.

No raw query name, reversible secret label, raw file secret, or unkeyed secret digest enters an artifact. The authoritative server does not log queries. It retains one sanitized receipt per expected case and a duplicate count only. The guest sends two DNS queries in a negative run or three in a positive run, with no retry. Controller DNS sends are spaced by at least 250 ms (at most four per second).

## Exact infrastructure blocker

Do not live-run this packet until all of the following are true:

- A Linux host you personally own or administer has a stable public IPv4 address.
- Its router/NAT and host firewall forward **both UDP 53 and TCP 53 directly** to the receiver. Cloudflare Tunnel, Tailscale Funnel, and an HTTP reverse proxy are not equivalent.
- No local resolver already owns port 53. A read-only preflight is:

  ```sh
  sudo ss -lunpt '( sport = :53 )'
  ```

- The owned Cloudflare parent zone contains DNS-only records equivalent to:

  ```text
  auth.sbx001.form-app.app.  NS  ns1.sbx001.form-app.app.
  ns1.sbx001.form-app.app.   A   <OWNED_LINUX_PUBLIC_IPV4>
  ```

  The NS target must resolve directly to that IPv4; do not proxy it. These records delegate only the temporary child zone used by the test.
  The child must have exactly that one NS, and the nameserver hostname must have exactly that one A record, no AAAA record, and no CNAME.
  The delegated child must have no DS record. This receiver is unsigned; a DS record would make validating resolvers correctly reject its answers. The parent zone itself may remain DNSSEC-signed.

- From outside the server, both of these work against the public IPv4:

  ```sh
  dig +norecurse @<OWNED_LINUX_PUBLIC_IPV4> auth.sbx001.form-app.app NS
  dig +tcp +norecurse @<OWNED_LINUX_PUBLIC_IPV4> auth.sbx001.form-app.app SOA
  ```

- An SSH local forward can reach the receiver's loopback-only admin port. The admin API must never be exposed publicly:

  ```sh
  ssh -N -L 43101:127.0.0.1:43101 <OWNED_LINUX_HOST>
  ```

The repository currently contains no evidence that a candidate Linux peer is personally owned, that its public address is stable, that inbound UDP/TCP 53 reaches it, or that the child-zone delegation exists. Those are the only live blockers. Local tests start loopback-only UDP/TCP listeners (and loopback Unbound when installed), but perform no SSH, public DNS lookup or mutation, firewall change, public listener, or Vercel request.

## Receiver

Generate two fresh strong values locally. Use the same values in the receiver and controller processes. Never paste them into chat or commit them:

```sh
openssl rand -hex 32  # SBX001_ADMIN_KEY
openssl rand -hex 32  # SBX001_PROOF_KEY
```

On the owned Linux host, from a private checkout with dependencies installed:

```sh
cd /path/to/vercel-security-challenge
export SBX001_ADMIN_KEY='<FRESH_ADMIN_HEX>'
export SBX001_PROOF_KEY='<FRESH_PROOF_HEX>'
export SBX001_AUTHORITATIVE_ZONE='auth.sbx001.form-app.app'
export SBX001_NAMESERVER_HOSTNAME='ns1.sbx001.form-app.app'
export SBX001_ANSWER_IPV4='192.0.2.1'
export SBX001_BIND_HOST='0.0.0.0'
export SBX001_DNS_PORT='53'
export SBX001_ADMIN_PORT='43101'
sudo --preserve-env=SBX001_ADMIN_KEY,SBX001_PROOF_KEY,SBX001_AUTHORITATIVE_ZONE,SBX001_NAMESERVER_HOSTNAME,SBX001_ANSWER_IPV4,SBX001_BIND_HOST,SBX001_DNS_PORT,SBX001_ADMIN_PORT \
  npx tsx pocs/SBX-001/authoritative-receiver.ts
```

Wait for:

```json
{"ready":true,"service":"sbx001-direct-authoritative","dnsPort":53,"adminPort":43101,"udp":true,"tcp":true,"rawQueryLogging":false}
```

The receiver is a terminal authoritative server. It does not recurse or open outbound connections. It serves authoritative apex NS and SOA records, includes SOA in negative answers, and gives only armed exact test names a TTL-zero `192.0.2.1` documentation answer. Other query types for an armed exact name receive authoritative NODATA plus SOA, so QNAME minimization cannot suppress the later A query; they create no receipt. Unexpected or pre-arm names receive authoritative NXDOMAIN and are not retained. For an armed exact A query, the receiver records only the sanitized case/operation/source/transport ingress before the response write and retains the response-write result as a separate boolean.

## Controller

With the SSH forward active, run from the local private checkout:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export VERCEL_TOKEN='<HACKERONE_ALIAS_TOKEN>'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export SBX001_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'
export SBX001_ADMIN_KEY='<SAME_FRESH_ADMIN_HEX>'
export SBX001_PROOF_KEY='<SAME_FRESH_PROOF_HEX>'
export SBX001_ADMIN_ORIGIN='http://127.0.0.1:43101'
export SBX001_AUTHORITATIVE_ZONE='auth.sbx001.form-app.app'
export SBX001_NAMESERVER_HOSTNAME='ns1.sbx001.form-app.app'
export SBX001_AUTHORITATIVE_IPV4='<OWNED_LINUX_PUBLIC_IPV4>'
export SBX001_HTTPS_CONTROL_ORIGIN='https://vsc-h3-action-swve.cyrus-206.workers.dev'
export SBX001_SCOPE_CONFIRMATION='I_CONTROL_THE_SBX001_AUTHORITATIVE_DNS_AND_HTTPS_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TESTING'
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/direct-run.ts
```

Interpret only the JSON `assessment` in the private artifact:

- `pass`: all controls worked and the deny-all public DNS query did not reach the authoritative receiver; no secret was generated.
- `candidate-medium`: the exact public canary reached the authoritative receiver under literal deny-all, but the independently gated file-secret proof did not complete.
- `candidate-high`: after the public signal, the exact fresh mode-`0600` file value reached the authoritative receiver and produced the expected opaque HMAC receipt.
- `indeterminate` or `error`: a control, attribution, retention, or cleanup gate failed. Do not report it as a bypass.

Stop after the first High candidate. Personally inspect and reproduce the private artifact before submitting anything.
The artifact records the alias-proof method, exact delegation/address sets, case-arm and receipt times, bounded receiver polling, controller/guest/SDK versions, guest-probe SHA-256, sandbox region/image/runtime, session creation time, command time ranges, and cleanup recovery state. It never records any case nonce or raw DNS name.

If a run retains `artifacts/SBX-001-direct-active.lock` and its recovery journal, do not delete either file manually and do not start another run. After the unknown-create settlement horizon (when applicable), use cleanup-only mode with the same eligible Vercel credentials and receiver admin forward:

```sh
export SBX001_RECOVERY_RUN_ID='<UUID_FROM_THE_RETAINED_JOURNAL_FILENAME>'
export VERCEL_TOKEN='<HACKERONE_ALIAS_TOKEN>'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export SBX001_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'
export SBX001_ADMIN_KEY='<SAME_FRESH_ADMIN_HEX>'
export SBX001_ADMIN_ORIGIN='http://127.0.0.1:43101'
export SBX001_SCOPE_CONFIRMATION='I_CONTROL_THE_SBX001_AUTHORITATIVE_DNS_AND_HTTPS_ENDPOINTS_AND_AUTHORIZE_BOUNDED_TESTING'
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/direct-run.ts
```

Cleanup-only mode never runs the experiment matrix and writes a distinct recovery artifact. Before the settlement horizon, `cleanup-incomplete` is expected and intentionally retains the journal and lock.

## Local verification

These commands do not contact Vercel, SSH, public DNS, or public endpoints. The focused test does exercise a loopback authoritative server and, when installed, a loopback Unbound process:

```sh
node --check guest/dns-authoritative-probe.mjs
npx vitest run test/sbx-001-direct.test.ts test/sbx-001-direct-safety.test.ts
npx tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext \
  --strict --noUncheckedIndexedAccess --exactOptionalPropertyTypes --esModuleInterop \
  --skipLibCheck --types node,vitest/globals \
  pocs/SBX-001/direct-shared.ts \
  pocs/SBX-001/direct-live-lock.ts \
  pocs/SBX-001/direct-safety.ts \
  pocs/SBX-001/authoritative-receiver.ts \
  pocs/SBX-001/direct-run.ts \
  test/sbx-001-direct.test.ts \
  test/sbx-001-direct-safety.test.ts
```
