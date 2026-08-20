# Encrypted ClientHello permits exfiltration to a denied inner hostname through an allowed outer SNI

> **Submission gate — clarification first.** This draft is technically complete, but it is not ready for direct vulnerability submission. The challenge policy instructs researchers to open a clarification when documentation is unclear or absent. Vercel documents SNI-based filtering, while neither the public docs nor the private policy define ECH semantics. Send the ready-to-paste clarification below, obtain Vercel's intent, and personally verify one live run before submitting a vulnerability report.

> **Current disposition:** independently reproduced twice with exact secret-receipt evidence. It remains a technical finding on clarification hold, not an accepted or bounty-awarded report.

## Submission metadata

- Asset: Vercel Sandbox network firewall
- Vulnerability class: **Networking and Firewall**
- Suggested severity: **High, contingent on Vercel confirming that a domain allowlist is intended to constrain the effective inner destination when ECH is used**
- Suggested weakness, if a CWE is required: [CWE-863 — Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html) (primary). [CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html) is a possible secondary communication-endpoint mapping, but the demonstrated root cause is an authorization decision made against a different hostname identity from the one ultimately served.
- HackerOne-alias Vercel account: `swve@wearehackerone.com`
- Vercel Team ID: `team_n98ERpVwV7HqmWRudAyK8sXQ`
- Vercel Project ID: `prj_CyyVykdN06Nrkla6KidZcecLgbCa`
- Reproduced SDK session IDs: `sbx_0g6A6C3VY4ds4WDqPeG5zuUnAzbz`, `sbx_5ACC7TZy92kdYQ6d4zuFCTy7xuLF`
- Test environment: `@vercel/sandbox@3.0.0`; `curl_cffi==0.13.0`; libcurl `8.15.0-IMPERSONATE` with BoringSSL; Vercel region `iad1`
- Submission state: **DRAFT / HOLD** — two clean live reproductions exist, but the submitting researcher must personally run and verify the PoC before submission, and the program asks researchers to seek clarification where documented semantics are unclear.
- Severity acknowledgement: I understand the program's severity-inflation bounty penalty. I am requesting High only because the live PoC sends a fresh synthetic operator secret to an inner hostname absent from the allowlist. I am not claiming Critical impact.

## Summary

A hostile process in Vercel Sandbox can use TLS Encrypted ClientHello (ECH) to place the allowed name `cloudflare-ech.com` in the plaintext outer ClientHello while encrypting a different destination hostname in the inner ClientHello. In the live differential, the connection passed when that visible outer SNI was allowed, completed verified TLS for the distinct inner hostname, and reached the researcher-owned inner service. This proves that the provider accepted the encrypted inner identity and served that hostname. Cloudflare's internal decrypt-and-route steps are a protocol-consistent inference, not something the PoC directly observes.

In two fresh, researcher-owned sandboxes, I set the exact user-defined policy to:

```json
{ "allow": ["cloudflare-ech.com"] }
```

An ordinary TLS request to the researcher-owned inner hostname was blocked before any HTTP response. The same destination then succeeded over a fresh ECH connection whose only visible outer SNI was `cloudflare-ech.com`. The ECH request read a fresh mode-`0600` synthetic operator-secret file and sent it to the inner hostname. A researcher-owned endpoint returned an exact keyed HMAC operation ID, proving receipt without reflecting the secret or exposing the HMAC key to the guest.

This is a domain-allowlist bypass if `allow` is intended to authorize the effective destination hostname. There is an important semantics caveat: Vercel's public documentation says HTTPS domain filtering uses SNI at the start of the TLS handshake, but it does not say whether ECH is rejected, supported, or whether allowing an ECH `public_name` intentionally authorizes every hidden inner name behind it. The program policy says to open a clarification discussion when guidance is unclear or absent. I therefore recommend confirming that intent before filing this as an unconditional High-severity report.

## Security expectation and documentation ambiguity

The [Vercel Sandbox firewall documentation](https://vercel.com/docs/sandbox/concepts/firewall) describes the firewall as a control for preventing data exfiltration. It says user-defined policies deny by default and allow specific domains, and that HTTPS traffic is matched through the SNI extension at the start of the TLS handshake. It documents several SNI and CIDR limitations, but as of the page's `2026-08-04` update it does not mention ECH, `ClientHelloOuter`, `ClientHelloInner`, or the authorization scope of an ECH public name.

[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) specifies that ECH protects the true SNI by sending a public `ClientHelloOuter` containing an encrypted `ClientHelloInner`. [Cloudflare's ECH documentation](https://developers.cloudflare.com/ssl/edge-certificates/ech/) states that `cloudflare-ech.com` is the common outer SNI while the actual server name is encrypted in the inner ClientHello. Cloudflare also warns that SNI-dependent network filtering may no longer operate as expected and recommends disabling ECH at the resolver when such filtering is required.

The security question is therefore precise:

> Does `{ "allow": ["cloudflare-ech.com"] }` authorize only that named destination, or every ECH inner hostname that a compatible client can hide behind that public name?

If the former is intended, the observed result is a firewall authorization bypass. If the latter is the intended contract, this behavior may be a documented-design clarification rather than an eligible vulnerability; the documentation should state that consequence explicitly.

Suggested program-clarification text:

> Under a user-defined Sandbox network policy containing only `allow: ["cloudflare-ech.com"]`, is the firewall intended to permit TLS ECH connections whose encrypted inner SNI names a different, non-allowlisted Cloudflare hostname, or should that connection be blocked? I have a bounded two-run live PoC against only my own Vercel account and Worker endpoint and can share it if this behavior is unexpected.

## Probable root cause

The live differential, combined with Vercel's documented SNI design, is consistent with the authorization decision and effective routing decision using different identities:

1. The Sandbox firewall observes and authorizes the plaintext `ClientHelloOuter` SNI, `cloudflare-ech.com`.
2. The `encrypted_client_hello` extension carries the encrypted `ClientHelloInner`.
3. The connection completes verified TLS for the distinct inner hostname, `vsc-h3-action-swve.cyrus-206.workers.dev`, and returns the expected owned-service response. This proves that Cloudflare accepted the encrypted inner identity and served that hostname; the internal decryption and routing steps are inferred from the protocol and result rather than directly observed.
4. That inner hostname is not present in the Sandbox network policy.

The PoC supplies the endpoint's current DNS HTTPS-record ECHConfigList directly to libcurl. This is supported by libcurl's [`CURLOPT_ECH`](https://curl.se/libcurl/c/CURLOPT_ECH.html) `ecl:<base64-value>` form. Consequently, merely removing ECH parameters from the sandbox's default DNS responses would not close the bypass. Hostile code can either preload an ECH-capable client and the public ECHConfig in the sandbox image before a restrictive policy is applied, or retain the public ECHConfig obtained during the documented initial `allow-all` setup phase and use it after the live policy update. The ECHConfig is public configuration, not secret material.

## Tested stronger variant: alternate ordinary cover name is non-viable

I also tested whether the prerequisite to allow Cloudflare's advertised ECH public name could be removed. This was a fully controlled provider-side experiment, not an additional Vercel Sandbox claim. I kept Cloudflare's ECHConfig byte-for-byte unchanged and used OpenSSL `4.0.0` through `SSL_ech_set1_outer_server_name` / `s_client -ech_outer_sni` to vary only the plaintext outer SNI.

- With outer SNI `cloudflare-ech.com`, the control verified TLS/ECH and the owned Worker returned `200 {"ok":true}`.
- With outer SNI changed only to the owned, Cloudflare-proxied `form-app.app`, the captured ClientHello contained `encrypted_client_hello` (`0xfe0d`) and outer SNI `form-app.app`, but Cloudflare returned fatal `handshake_failure(40)` before any certificate or application request.
- `form-app.app` published the identical ECHConfig, and plain SNI pinned to the same Worker IP succeeded, ruling out a simple address, route, or certificate-control failure.
- A separate serialized-config `public_name` byte rewrite correctly failed with `CURLE_ECH_REQUIRED` / `ECH_REJECTED`, because the ECHConfig bytes are bound to the HPKE setup and cannot be repurposed by editing the name.

The stronger arbitrary-cover-name variant is therefore non-viable against this provider: the result is consistent with Cloudflare enforcing the advertised `public_name` or an equivalent server-side check. The demonstrated finding still requires an operator policy that allows `cloudflare-ech.com`; I do not claim a bypass for an arbitrary ordinary allowed domain.

## Expected versus actual behavior

Every endpoint request used a fresh TCP/TLS connection, verified TLS, one controller-pinned IPv4 address, HTTP/2, no redirect, no retry, and no environment proxy. The libcurl debug callback retained only a bounded parsed attestation from TLS-framed outbound ClientHello records; it required exactly one ClientHello and recorded the outer SNI and presence or absence of extension `0xfe0d`.

| Stage | On-wire identity | Expected | Actual in both runs |
| --- | --- | --- | --- |
| `allow-plain-control` under `allow-all` | Outer SNI = inner Worker hostname; no `encrypted_client_hello` | Owned endpoint is reachable | `200`, verified TLS, exact HMAC operation ID |
| `allow-ech-control` under `allow-all` | Outer SNI = `cloudflare-ech.com`; `encrypted_client_hello` present | ECH is proven functional before enforcement test | `200`, verified TLS, exact HMAC operation ID |
| Policy update and independent readback | Exact same SDK session; `{ "allow": ["cloudflare-ech.com"] }` | Cover-only policy is active | Active and independent handles returned the exact policy and original SDK session ID |
| `restricted-plain-negative` | Outer SNI = inner Worker hostname; no `encrypted_client_hello` | Blocked because inner Worker hostname is absent | Blocked with curl error `35`; status `0`; zero response bytes |
| `restricted-ech-target` | Outer SNI = `cloudflare-ech.com`; `encrypted_client_hello` present; encrypted inner name = Worker hostname | **Blocked if policy binds the effective destination** | `200`, verified TLS, exact HMAC operation ID for the fresh file-backed operator secret |

The artifact's `actualHttpVersion` value `3` is libcurl/curl_cffi's enum value for HTTP/2 (`CurlHttpVersion.V2_0`), not HTTP/3. The endpoint's historical route name does not affect the test.

## Why the HMAC response proves data exfiltration

Before applying the restrictive policy, the controller writes a random 32-byte base64url value to `/tmp/sbx-031/operator-secret` with mode `0600` and verifies only its SHA-256. The value is not placed in guest source, guest configuration, command arguments, or controller output.

Only the final ECH probe reads that file and sends the value to the researcher-owned action endpoint. The endpoint returns:

```text
h3_<base64url(HMAC-SHA256(H3_ACTION_KEY, runId + "\n" + caseId + "\n" + canary))>
```

`H3_ACTION_KEY` remains controller/endpoint-only. The controller independently computes the expected operation ID. A candidate verdict requires an exact match, so the guest cannot fabricate success from the public run and case identifiers. The endpoint never echoes the secret and sends `Cache-Control: no-store`.

## Live evidence

Both runs used the HackerOne-alias Vercel account and the same researcher-owned Cloudflare Worker. Each used a fresh non-persistent sandbox and a different random operator secret.

| Run ID | SDK session ID | Started (UTC) | Pinned IPv4 | Operator-secret SHA-256 | Result |
| --- | --- | --- | --- | --- | --- |
| `7fc8a05f-5fef-475f-986a-4e97e6d94067` | `sbx_0g6A6C3VY4ds4WDqPeG5zuUnAzbz` | `2026-08-19T01:03:30.207Z` | `104.21.61.182` | `a6f82601f9c9ee2622b0760947f060a7d58355faeb983f3cb267064da27211f6` | Candidate; every control passed; plain denied; ECH exfiltration authenticated |
| `211e69f4-a86a-4bb8-8e72-b47b7692002a` | `sbx_5ACC7TZy92kdYQ6d4zuFCTy7xuLF` | `2026-08-19T01:05:23.386Z` | `104.21.61.182` | `0d5ac3bbb0985798c26fb1dfec28650f629296fbe67bd40528b50d8ca09f5567` | Independent fresh reproduction with the same differential |

In both artifacts:

- the current DNS HTTPS record produced one 71-byte ECH config with `public_name = cloudflare-ech.com` and SHA-256 `4b48789546656be6a20047a74149b2e519161ba8f55d9593de6eeb6d6893d058`;
- the policy-update acknowledgment and independent readback referred to the original SDK session ID and returned only the cover-name allow entry;
- each probe captured exactly one TLS-framed outbound ClientHello;
- the restricted plain request produced no HTTP response;
- the restricted ECH request returned `200` from the exact pinned address with verified TLS and an operation ID equal to the controller's expected HMAC;
- all guest-material guards were false; and
- automatic cleanup stopped and deleted the owned sandbox with no errors.

The `sbx_*` values above are the SDK's `currentSession().sessionId` values. They are recorded as SDK session IDs and are not interpreted as host identifiers.

## Reproduction

### 1. Install the controller dependencies

Use Node.js 20.18 or newer from the attached PoC bundle:

```sh
npm ci
```

### 2. Deploy the bounded endpoint in a Cloudflare account you own

The bundle includes `infra/h3-action-worker`. Authenticate Wrangler, generate a temporary key, configure it as a Worker secret, and deploy:

```sh
cd infra/h3-action-worker
npm ci
npx wrangler login
npm run types
npm run check
export H3_ACTION_KEY="$(openssl rand -base64 48 | tr -d '\n')"
printf '%s' "$H3_ACTION_KEY" | npx wrangler secret put H3_ACTION_KEY
npx wrangler deploy
```

Record the resulting `https://<owned-worker>.workers.dev` URL. The Worker accepts only bounded `GET /v1/h3-action` requests and returns a non-reflecting HMAC operation ID.

### 3. Authenticate to a Vercel account you own

Return to the bundle root and log in. Challenge researchers should use their HackerOne-alias account:

```sh
cd ../..
npx sandbox login
```

Alternatively, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together for the same owned account.

### 4. Run the four-request proof matrix

Use the same temporary `H3_ACTION_KEY` configured on the Worker:

```sh
export H3_ACTION_KEY='<same temporary controller/Worker key configured in step 2>'
export SBX031_SCOPE_CONFIRMATION='I_CONTROL_THE_ENDPOINT_AND_AUTHORIZE_BOUNDED_ECH_TESTING'
export SBX031_ENDPOINT_URL='https://<owned-worker>.workers.dev/v1/h3-action'
npx tsx pocs/SBX-031/ech-domain-allowlist.ts
```

A reproduced candidate intentionally exits with status `1` so it cannot be mistaken for a passing firewall test. Expected terminal fields are:

```json
{
  "testId": "SBX-031",
  "verdict": "candidate",
  "candidate": true,
  "controls": {
    "setupPassed": true,
    "allowPlainControlPassed": true,
    "allowEchControlPassed": true,
    "restrictedUpdateAcknowledged": true,
    "restrictedReadbackPassed": true,
    "restrictedPlainBlocked": true,
    "restrictedEchSucceeded": true,
    "restrictedEchBlocked": false
  },
  "cleanup": {
    "stopped": true,
    "deleted": true,
    "errors": []
  }
}
```

The complete body-free evidence is written mode `0600` under `artifacts/SBX-031-poc-<run-id>-private.json`. The script automatically stops and deletes the sandbox for every verdict.

### 5. Delete the temporary endpoint

After capturing the artifact:

```sh
cd infra/h3-action-worker
npx wrangler delete --name vsc-h3-action-swve
unset H3_ACTION_KEY
```

## Prerequisites and nonclaims

The demonstrated attack requires:

- hostile code that can use an ECH-capable TLS 1.3 client;
- an operator policy that allows an ECH public name, here `cloudflare-ech.com`;
- a denied inner hostname hosted behind the same compatible ECH provider; and
- operator data accessible to the hostile sandbox process.

The PoC installs the ECH client and obtains the public ECHConfig while the sandbox is in documented `allow-all` setup mode, retains both, and then uses the live-update feature to lock the sandbox before running the negative and exploit cases. This models downloading dependencies before starting an untrusted process. A second concrete path is to preload the ECH-capable client and a current public ECHConfig in the sandbox image before the restrictive policy is applied. The configuration is public and attacker-supplied; neither path requires secret material from the operator or provider.

This report does **not** claim:

- a Firecracker microVM escape, EC2 host access, or any container-namespace result;
- cross-tenant access or interaction with any account, sandbox, data, or endpoint not owned by the researcher;
- credential-brokering secret disclosure;
- bypass of literal `deny-all` or a CIDR deny rule;
- that every ECH provider or TLS implementation is exploitable in the same way; or
- that Vercel can decrypt the inner ClientHello without provider cooperation.

## Impact and severity rationale

If domain allowlists are intended to constrain effective destination hostnames, the PoC meets the challenge's stated High category: it defeats a domain allowlist and exfiltrates operator data to a destination the operator did not authorize. The impact is not theoretical reachability; the exact HMAC response authenticates receipt of a fresh file-backed secret at the denied inner hostname.

High remains conditional because the public docs explicitly describe SNI-based enforcement. The missing point is whether the authorized SNI means the true requested server name or merely the plaintext outer ECH cover name. If Vercel confirms that allowing a public name intentionally authorizes its full ECH anonymity set, I would withdraw the High claim and treat this as a documentation/design clarification. Critical is not appropriate because there is no host escape, host compromise, or cross-tenant data access.

## Suggested remediation

The safest default for a user-defined domain policy is to fail closed when the initial ClientHello contains any `encrypted_client_hello` extension (type `0xfe0d`) and the firewall cannot verify the inner destination:

1. Reject TLS connections containing `encrypted_client_hello` under domain allowlists unless the operator explicitly opts into provider/public-name semantics.
2. If ECH is supported, add a policy primitive that makes the broad authorization explicit, for example an `allowECHPublicName` or provider-anonymity-set rule distinct from ordinary domain entries.
3. Do not rely only on suppressing HTTPS/SVCB DNS records. A hostile client can supply an ECHConfigList directly, as this PoC does.
4. Warn or reject when a known ECH public name is entered as an ordinary allowed domain, and document that its scope may encompass many hidden inner hostnames.
5. Add regression coverage with an allowed outer SNI, a denied inner SNI, and an `encrypted_client_hello` extension. Test both concrete acquisition paths: an ECH client/config preloaded before a restrictive policy is applied, and a public ECHConfig retained from the documented initial `allow-all` phase across a live policy update.

If Vercel's intended contract is that `allow` always authorizes only the observable outer SNI, the remediation is instead to document prominently that allowing an ECH public name authorizes any compatible inner destination behind that name. That warning should appear in both the firewall documentation and policy-configuration surface because it materially changes the data-exfiltration boundary.

## Attachment checklist

Do not submit until every required item is checked:

- [ ] **Researcher-personally-verified run:** execute the PoC once, review the live output, and replace or supplement the primary evidence row with that SDK session ID, UTC timestamp, and artifact hash. The program expressly rejects AI-generated reports that were not personally verified.
- [ ] **Program clarification:** confirm whether a domain allowlist is intended to constrain the effective ECH inner hostname. If Vercel says outer-SNI scope is intentional, do not submit this as an unconditional High.
- [ ] **Working PoC ZIP:** include the root `package.json` and lockfile, `tsconfig.json`, `tsconfig.poc.json`, `pocs/SBX-031/`, `guest/ech-domain-probe.py`, and the complete `infra/h3-action-worker/` directory. Test extraction and reproduction from a clean directory before upload.
- [ ] **Primary live artifact:** `SBX-031-poc-7fc8a05f-5fef-475f-986a-4e97e6d94067-private.json`, SHA-256 `db730f9f7fb8bd4e1c46422f89c8ac9ee889a9753e0b683a9a7db40e35c7c4c8`.
- [ ] **Independent reproduction artifact:** `SBX-031-poc-211e69f4-a86a-4bb8-8e72-b47b7692002a-private.json`, SHA-256 `9cff3e172c53aa0c4730bdad07b73118665bb90aaf0cda619ad12302977d4dce`.
- [ ] **Personal-run transcript or screenshot:** include the compact terminal result showing `candidate`, the exact policy controls, SDK session ID, cleanup, and artifact path. Do not expose Vercel tokens, the raw operator secret, or `H3_ACTION_KEY`.
- [ ] **Endpoint cleanup confirmation:** delete the temporary Worker after the personal reproduction, and confirm no Vercel sandbox remains active.

The two current evidence files contain no raw HMAC key or raw operator secret, but they should still be uploaded confidentially through HackerOne and kept out of any public disclosure.

## Primary technical references

- Vercel, [Sandbox firewall](https://vercel.com/docs/sandbox/concepts/firewall) — user-defined policy, SNI-based HTTPS filtering, live updates, and the stated data-exfiltration security purpose.
- IETF, [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html) — standards-track definition of `ClientHelloOuter`, encrypted `ClientHelloInner`, and ECH deployment implications.
- Cloudflare, [ECH Protocol](https://developers.cloudflare.com/ssl/edge-certificates/ech/) — Cloudflare's common outer SNI `cloudflare-ech.com`, hidden inner server name, and enterprise filtering guidance.
- curl project, [`CURLOPT_ECH`](https://curl.se/libcurl/c/CURLOPT_ECH.html) — direct `ECHConfigList` support through the `ecl:` option used by the PoC.
- MITRE, [CWE-863](https://cwe.mitre.org/data/definitions/863.html) and [CWE-923](https://cwe.mitre.org/data/definitions/923.html) — reviewed class-level mappings; CWE-863 is primary because the policy authorizes one hostname identity while a different hostname is served, with CWE-923 retained only as a possible secondary endpoint-communication mapping.
