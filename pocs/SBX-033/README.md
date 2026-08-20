# SBX-033: native IPv6 under literal deny-all

Status: **locally implemented and tested; not run against Vercel**.

## Hypothesis

Vercel Sandbox may enforce outbound TCP policy on IPv4 while allowing a guest to reach the same researcher-owned endpoint through a native IPv6 socket. A valid candidate requires a literal `deny-all` sandbox to block the fixed IPv4 control but permit the fixed native IPv6 path. The higher-impact proof is gated behind that public-canary result and uses a fresh synthetic file-backed operator secret.

This packet is isolated from the shared observer and other PoCs:

- `native-ipv6-deny.ts` is the controller.
- `verdict.ts` contains pure proof and verdict predicates.
- `../../guest/native-ipv6-deny-probe.py` is the one-shot guest probe.
- `../../test/sbx-033-native-ipv6-deny.test.ts` contains local and adversarial tests.

## Prerequisites

The endpoint must be explicitly researcher-owned, dual stack, and serve the existing non-reflecting action contract at exactly `https://HOST/v1/h3-action`:

```text
{authorized:true,operationId:"h3_" + base64url(HMAC-SHA256(H3_ACTION_KEY, runId + "\n" + caseId + "\n" + canary))}
```

It must return `200`, JSON, and `Cache-Control: no-store`; it must not reflect the canary. The controller accepts the URL and pins only through environment variables, takes bounded current A and AAAA snapshots, and refuses pins absent from those snapshots.

Required environment:

```bash
SBX033_SCOPE_CONFIRMATION=I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_NATIVE_IPV6_DENY_TESTING
SBX033_ENDPOINT_URL=https://RESEARCHER_OWNED_DUAL_STACK_HOST/v1/h3-action
SBX033_PINNED_IPV4=ONE_CURRENT_PUBLIC_A_ADDRESS
SBX033_PINNED_IPV6=ONE_CURRENT_PUBLIC_NATIVE_AAAA_ADDRESS
H3_ACTION_KEY=CONTROLLER_AND_OWNED_ENDPOINT_HMAC_KEY_AT_LEAST_32_BYTES
VERCEL_TOKEN=VERIFIED_ALIAS_TOKEN
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa
```

The token is verified through exactly `/v2/user` as `swve@wearehackerone.com`. Do not put any of these values in the repository.

## Minimum control matrix

| Sandbox | Case | Required result | Purpose |
| --- | --- | --- | --- |
| fresh `allow-all` | fixed IPv4 + public canary | verified TLS, exact peer pin, valid non-reflecting HMAC receipt | endpoint and ordinary TCP baseline |
| same fresh `allow-all` | fixed native IPv6 + public canary | verified TLS, exact native peer pin, valid non-reflecting HMAC receipt | proves this environment has a usable native IPv6 path |
| fresh literal `deny-all` | fixed IPv4 + public canary | one active pre-response transport failure, never a timeout | policy discriminator; no action may occur |
| same fresh literal `deny-all` | fixed native IPv6 + public canary | one active block (clean pass) or exact authenticated success (target gate) | tests the hypothesized bypass without secret material |
| same fresh literal `deny-all`, only after the prior success | fixed native IPv6 + mode-0600 file secret | exact authenticated action receipt without reflection | demonstrates controlled synthetic data exfiltration |

The deny sandbox must report literal `deny-all` through both the active handle and an independent `resume:false` readback on the original session before probes and after the final attempted target. An unavailable or ambiguous allow-all native IPv6 control is `indeterminate`, never a pass.

## Bounds and evidence

- At most five endpoint requests, sequential, with no retry or redirect and a controller-wide minimum 300 ms dispatch interval.
- One raw fixed-address TCP connection per guest invocation, system CA verification, hostname verification, TLS 1.2+, and required HTTP/1.1 ALPN.
- Bounded DNS (10 seconds), SDK calls, connect, I/O, command output, and response body.
- The synthetic secret is generated and written only after authenticated public IPv6 success under `deny-all`. It is a fresh 32-byte random value encoded as base64url, stored at the fixed path with mode `0600`, checked by metadata and exact in-memory equality, and wiped from comparison buffers.
- No raw secret or standalone secret digest is retained. The evidence keeps only the keyed HMAC action receipt and sanitized metadata.
- Each fixture name contains the full run UUID and exact tags. Cleanup performs strict identity-bound orphan recovery, stop, delete, and three independent absence checks.
- The private artifact is created exclusively with mode `0600` under ignored `artifacts/`.

## Local verification

These commands are offline and do not create a sandbox:

```bash
python3 -c "compile(open('guest/native-ipv6-deny-probe.py', encoding='utf8').read(), 'guest/native-ipv6-deny-probe.py', 'exec')"
npx vitest run test/sbx-033-native-ipv6-deny.test.ts
npx tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --noUncheckedIndexedAccess --exactOptionalPropertyTypes --esModuleInterop --skipLibCheck --types node,vitest/globals pocs/SBX-033/verdict.ts pocs/SBX-033/native-ipv6-deny.ts test/sbx-033-native-ipv6-deny.test.ts
```

After manually validating the endpoint contract, DNS pins, alias account, and all environment values, the live command would be:

```bash
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-033/native-ipv6-deny.ts
```

That live command is intentionally not run as part of local readiness verification.
