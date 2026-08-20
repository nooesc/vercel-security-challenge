# SBX-001: deny-all raw-DNS exfiltration discriminator

This packet tests one narrow hypothesis: a sandbox with the literal network policy `deny-all` may still be able to send a raw UDP A query through its configured guest resolver. The owned authoritative DNS zone is the only remote observer. A public canary under deny-all is a policy-boundary signal; a fresh file secret recovered from an authoritative query under deny-all is the only High candidate.

This is a positive-only discovery detector. Cloudflare Free-zone `dnsAnalyticsAdaptive` is sampled (`sampleInterval` has been observed as 10), may ingest more than an hour late, and may omit individual queries forever. An absent row is therefore never a pass and never proves blocking.

## Safety and infrastructure prerequisites

- Use only the verified HackerOne alias, eligible Vercel team/project, and the owned `form-app.app` Cloudflare zone encoded in the packet.
- Before any sandbox run, manually create and verify a temporary **DNS-only** wildcard A record: `*.sbx001.form-app.app -> 192.0.2.1`. Random NXDOMAIN names have not appeared reliably in adaptive analytics; the wildcard makes each canary an ordinary authoritative positive answer. Do not proxy it and do not point it at a real service.
- Each probe sends exactly one raw UDP A query with no retry. HTTPS to the same owned zone/IP is a separate policy control.
- Remove the temporary wildcard after the bounded campaign. That DNS change is intentionally not automated here.
- Route 53 direct query logs, if placed under an independently owned test zone later, are a stronger observer than sampled Cloudflare analytics. Do not reinterpret Cloudflare absence as negative evidence.

The generated names use one wildcard-matching label:

- allow: `a<128-bit nonce>.sbx001.form-app.app`
- deny: `d<128-bit nonce>.sbx001.form-app.app`
- secret: `s<Base32(S XOR P)><128-bit nonce>.sbx001.form-app.app`

`S` and `P` are independently random 16-byte values. `S` is written as a mode-0600 file in the guest. `P` is sent to the guest once and never persisted. Cloudflare can retain only the random ciphertext `S XOR P`, not `S` or `P`.

## Required environment

Use `.env.local` or equivalent process-local values; never commit them:

```sh
export VERCEL_TOKEN='...'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export CLOUDFLARE_API_TOKEN='...'
export SBX001_PROOF_KEY='at-least-32-random-bytes-used-only-for-HMAC-receipts'
export SBX001_SCOPE_CONFIRMATION='I_CONTROL_FORM_APP_APP_AND_AUTHORIZE_BOUNDED_DNS_ANALYTICS_TESTING'
export SBX001_WILDCARD_CONFIRMATION='I_VERIFIED_SBX001_DNS_ONLY_WILDCARD_A_TO_192_0_2_1'
```

The Cloudflare token needs read-only GraphQL DNS analytics access to the owned zone. The controller uses zone-scoped `viewer.zones(filter: { zoneTag })`; it does not use account-scoped analytics.

## Gated runbook

Run from the repository root. Do not skip a gate.

1. Create one fresh allow-all sandbox and send the public allow control:

   ```sh
   DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/run.ts --stage allow-control
   ```

2. Wait at least one hour, then verify the pending artifact. Rerunning verification is safe because it sends no sandbox traffic:

   ```sh
   ALLOW_PENDING_PATH='artifacts/SBX-001-allow-control-REPLACE-pending-private.json'
   DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/verify.ts --pending "$ALLOW_PENDING_PATH"
   ```

   Continue only if an exact individual A row returns and the sidecar outcome is `allow-observed`.

3. Create a new literal-deny-all sandbox and send one public deny control using that signed sidecar:

   ```sh
   ALLOW_GATE_PATH='artifacts/SBX-001-allow-control-REPLACE-verification-REPLACE-private.json'
   DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/run.ts --stage deny-control --gate "$ALLOW_GATE_PATH"
   ```

4. Wait and verify its pending artifact. Continue only if the exact deny row returns and the outcome is `signal-medium`:

   ```sh
   DENY_PENDING_PATH='artifacts/SBX-001-deny-control-REPLACE-pending-private.json'
   DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/verify.ts --pending "$DENY_PENDING_PATH"
   ```

5. Launch the single-process secret phase with that signed deny sidecar:

   ```sh
   DENY_GATE_PATH='artifacts/SBX-001-deny-control-REPLACE-verification-REPLACE-private.json'
   DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-001/run.ts \
     --stage deny-secret \
     --gate "$DENY_GATE_PATH" \
     --analytics-wait-minutes 90 \
     --analytics-poll-seconds 300
   ```

   The sandbox is stopped, deleted, and checked absent immediately after its one query. The controller then retains `S` and `P` only in memory while it polls for the bounded window. Closing the process loses the ability to recover the secret; the phase cannot be resumed from disk by design.

## Proof bar

Every stage requires an exact eligible identity, fresh non-persistent sandbox, exact active and independent session-policy readbacks before and after the query, the owned same-IP HTTPS control, a historical pre-send collision search, one raw UDP A attempt, and stop/delete plus three independent absence checks.

Classification is deliberately asymmetric:

- `allow-observed`: exact allow row; authorizes the deny-control stage only.
- `signal-medium`: exact public row from literal deny-all; plausible policy violation and authorizes one secret stage.
- `candidate-high`: an exact secret-stage row whose ciphertext decodes and recovers the in-memory 16-byte file secret with the random in-memory pad.
- `no-candidate-observed` / `indeterminate`: no exact positive row, sampling ambiguity, failed controls, or cleanup failure. These never authorize another stage and are never called a pass.

Private artifacts store hashes/HMAC receipts, booleans, timestamps, policy evidence, and sanitized analytics metadata. They never store a raw query name, secret, one-time pad, reversible secret encoding, API token, or Vercel token. Manually validate any candidate against the HackerOne policy before drafting a report.
