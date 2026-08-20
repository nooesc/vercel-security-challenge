# SBX-031 ECH domain-allowlist semantics probe

This deterministic PoC asks whether TLS Encrypted Client Hello (ECH) can hide a denied researcher-owned hostname behind an allowed outer `public_name`. The current Vercel Sandbox firewall documentation says domain rules identify HTTPS traffic from the SNI at the start of the TLS handshake. Cloudflare documents that ECH-enabled traffic exposes `cloudflare-ech.com` as the outer SNI while encrypting the actual hostname in the inner ClientHello. Because Vercel documents SNI-based enforcement but does not explicitly state how manually supplied ECH configurations should be handled, a successful run is a candidate signal that still needs program confirmation of intended policy semantics.

The impact target is a domain-allowlist bypass with synthetic operator-data exfiltration, not mere reachability. The endpoint is an owned Cloudflare Worker and returns only a keyed opaque operation ID. It never reflects the canary or HMAC key.

## Four-request proof matrix

One fresh nonpersistent alias-owned sandbox starts at literal `allow-all` so the controller can install the pinned ECH-capable client. Every application request uses a new connection, verified TLS, controller-pinned IPv4, HTTP/2 over TCP, no redirect, no retry, and the same owned Worker action route.

1. `allow-plain-control`: ordinary inner SNI reaches the owned action and returns the exact HMAC operation ID. A bounded libcurl debug callback attests one TLS-framed outgoing ClientHello whose outer SNI is the owned hostname and which has no `encrypted_client_hello` extension.
2. `allow-ech-control`: the same endpoint succeeds with the controller-fetched DNS HTTPS `ech=` configuration. The same callback must attest exactly one TLS-framed outgoing ClientHello whose outer SNI is `cloudflare-ech.com` and which contains `encrypted_client_hello` extension `0xfe0d`, proving ECH is actually emitted before enforcement is tested. A verified response for the distinct inner hostname on that one-ClientHello connection also rules out a cleartext retry or outer-name certificate fallback.
3. The controller installs and independently reads back an exact user-defined policy whose only allow entry is `cloudflare-ech.com`. Both readbacks must address the original active SDK session ID and use `currentSession().networkPolicy`; there are no subnet rules, wildcard domains, transforms, or forwarding rules.
4. `restricted-plain-negative`: ordinary TLS to the pinned inner endpoint must be rejected before any HTTP response.
5. `restricted-ech-target`: only after that barrier, a fresh ECH request reads a random mode-`0600` operator-secret file and sends it to the same owned action. A candidate requires the attested outer `cloudflare-ech.com` ClientHello with `encrypted_client_hello`, actual HTTP/2, the exact pinned address, verified TLS, and the controller-computed HMAC operation ID for that unknown-to-configuration secret.

Although the numbered sequence has five steps, it makes exactly four endpoint requests. Policy update/readback calls are controller operations, not endpoint requests.

The controller obtains the endpoint's current ECHConfigList from Cloudflare's DNS-over-HTTPS JSON endpoint before sandbox creation, parses the binary structure, and requires every config to use the documented `cloudflare-ech.com` public name. Evidence stores only its SHA-256, length, TTL, and parsed public name. The raw ECHConfigList is public DNS data and enters the guest configuration; the HMAC key and operator secret do not. For the on-wire attestation, the callback ignores plaintext debug events and retains only the outer hostname, ECH-extension boolean, sizes, counts, and SHA-256 of the TLS record; it never retains raw ClientHello or application data.

DNS suppression alone is not a complete mitigation. An ECH-capable client and the public ECHConfig can be preloaded in the sandbox image before a restrictive policy is applied, or the public ECHConfig can be retained from the documented initial `allow-all` setup phase and used after the live policy update. The ECHConfig is public configuration, not secret material.

## Endpoint contract

The existing owned Worker route at `/v1/h3-action` is protocol-independent and is reused over HTTP/2. For query parameters `run`, `case`, and `canary`, it returns:

```json
{"authorized":true,"operationId":"h3_<base64url digest>"}
```

The digest is `HMAC-SHA256(H3_ACTION_KEY, run + "\n" + case + "\n" + canary)`. The response must use `Cache-Control: no-store` and an `application/json` content type.

## Required environment

```sh
export SBX031_SCOPE_CONFIRMATION=I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_ECH_TESTING
export SBX031_ENDPOINT_URL=https://vsc-h3-action-swve.cyrus-206.workers.dev/v1/h3-action
export H3_ACTION_KEY='<same controller-only secret configured on the owned Worker>'
npx sandbox login  # HackerOne-alias Vercel account
npx tsx pocs/SBX-031/ech-domain-allowlist.ts
```

Alternatively, provide `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together for the same eligible account.

## Verdicts

- `candidate`: both pre-policy controls pass, the exact cover-only policy is acknowledged and independently read back for the same session, ordinary inner SNI is blocked, and an on-wire-attested ECH request exfiltrates the synthetic operator secret with an exact non-reflecting HMAC proof. Treat this as potentially High only if Vercel confirms the domain policy is intended to bind the effective inner hostname; otherwise it may be the documented consequence of SNI-only enforcement and not eligible.
- `pass`: all controls pass and the ECH target is rejected by the firewall before an HTTP response.
- `indeterminate`: the ECH config is rejected or stale, a control fails, policy readback differs, or the final failure cannot be attributed to the firewall.
- `error`: controller execution or cleanup fails.

A candidate intentionally exits nonzero. Every outcome writes body-free private evidence mode `0600`, then stops and deletes the owned sandbox.

## Local validation only

```sh
npx vitest run test/ech-domain-probe.test.ts
npx tsc --noEmit -p tsconfig.poc.json
```

Primary references:

- Vercel Sandbox firewall: <https://vercel.com/docs/sandbox/concepts/firewall>
- Cloudflare ECH protocol: <https://developers.cloudflare.com/ssl/edge-certificates/ech/>
- libcurl `CURLOPT_ECH`: <https://curl.se/libcurl/c/CURLOPT_ECH.html>
