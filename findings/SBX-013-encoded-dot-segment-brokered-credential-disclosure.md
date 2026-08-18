# Credential-brokering `path.startsWith` matches before encoded dot-segment canonicalization, applying credentials to a route outside the configured credential scope

## Submission metadata

- Asset: Vercel Sandbox network firewall / credentials brokering
- Vulnerability class: Networking and Firewall
- HackerOne-alias Vercel account: `swve@wearehackerone.com`
- Vercel Team ID: `team_n98ERpVwV7HqmWRudAyK8sXQ`
- Vercel Project ID: `prj_CyyVykdN06Nrkla6KidZcecLgbCa`
- Suggested severity: Medium; impact can be higher when the outside route performs a sensitive operation
- Primary weakness: [CWE-647 — Use of Non-Canonical URL Paths for Authorization Decisions](https://cwe.mitre.org/data/definitions/647.html)
- Related weakness: [CWE-551 — Authorization Before Parsing and Canonicalization](https://cwe.mitre.org/data/definitions/551.html)
- Test environment: `@vercel/sandbox@3.0.0`, controller Node.js `v25.6.0`, controlled Node.js HTTP observer, Vercel region `iad1`
- Severity acknowledgement: I understand the program's severity-inflation bounty penalty and am requesting Medium based only on the demonstrated authenticated transform-scope violation.

## Summary

Vercel Sandbox applies a path-scoped credential transform to the raw request target `/matched/%2e%2e/outside`. A standards-based parser at the downstream origin canonicalizes that same request to `/outside`, where the injected credential can authorize an operation that is outside the operator-configured `/matched/` prefix.

The live PoC uses a fresh synthetic credential known only to the controller, configured host-side transform, and controlled observer. The guest receives neither the credential nor its hash. The controlled `/outside` route never reflects the credential: it returns only an opaque operation ID after successful authentication.

The result is a path-authorization mismatch within an allowed origin. This report does **not** claim a hostname allowlist bypass.

## Security expectation

Vercel documents that matchers restrict credential transforms to matching requests and describes credentials brokering as keeping secrets out of the sandbox. A credential scoped to `/matched/` should therefore not authenticate a canonical `/outside` handler.

Relevant Vercel documentation:

- <https://vercel.com/docs/sandbox/concepts/firewall#credentials-brokering>
- <https://vercel.com/docs/sandbox/concepts/firewall#matchers>
- <https://vercel.com/changelog/vercel-sandbox-firewall-now-supports-request-proxying-and-filtering>

## Root cause and exact differential

The firewall decides whether to inject the credential before the downstream origin parses and canonicalizes the path. The raw target does literally begin with the configured prefix, but the authorization layer and origin router consume different path representations. The [WHATWG URL Standard](https://url.spec.whatwg.org/#url-path-segment-string) directly treats `%2e%2e` as a double-dot segment and shortens the path during parsing. [RFC 3986 sections 5.2.4 and 6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986) provide the related dot-segment removal and percent-encoding normalization rules.

The controlled observer derives its route from the same incoming request without redirecting or issuing another request:

```ts
const url = new URL(request.url ?? "/", "http://observer.invalid");
const normalizedPath = url.pathname;

if (normalizedPath === `/v1/probe/${runId}/outside`) {
  // Authenticate the outside action with x-sbx-harness-canary.
}
```

There is one HTTP request. Its raw request target remains `/matched/%2e%2e/outside`, while Node's WHATWG parser routes it as `/outside`.

## Prerequisites and scope

The demonstrated attack requires:

- hostile code running inside a sandbox;
- an operator-defined credential transform scoped to a path prefix;
- a same-origin HTTP server that canonicalizes encoded dot segments before routing; and
- an out-of-prefix route where the credential authorizes a sensitive or attacker-observable action.

This does not reach a different hostname. It bypasses the credential transform's path scope on the configured host. Real-world impact depends on the origin's routing behavior and the authority of the brokered credential.

## Live result

The controller configures this policy shape:

```ts
networkPolicy: {
  allow: {
    [controlledObserverHost]: [{
      match: { path: { startsWith: allowedPrefix } },
      transform: [{
        headers: { "x-sbx-harness-canary": controllerOnlySyntheticSecret }
      }]
    }]
  }
}
```

The controller registers the synthetic value with the controlled outside action, then sends the guest only the observer origin, request path, and a separate non-secret correlation value. A runtime guard rejects the proof if the guest configuration contains the brokered value.

| Guest request target | Canonical origin route | Brokered header observed | Result |
| --- | --- | --- | --- |
| `/matched/control` | `/matched/control` | Present | `204`; positive transform control |
| `/outside` | `/outside` | Absent | `401`; outside action unauthorized |
| `/matched/%2e%2e/outside` | `/outside` | Present | `200`; outside action authorized once, opaque operation ID returned |

For the encoded case, the controller-generated credential hash and the credential observed at the outside route are identical. The guest response does not contain the credential.

## Reproduction

The attached reproduction bundle contains:

- `pocs/SBX-013/encoded-dot-segment.ts`;
- `guest/http-probe.mjs`;
- `src/observer-server.ts` and `src/observer-cli.ts`;
- `src/contracts.ts`;
- `package.json`, `package-lock.json`, `tsconfig.json`, and `tsconfig.poc.json`.

Prepared bundle: `SBX-013-working-poc.zip`, SHA-256 `1eebc10cb1c0b562513ac0a786a72a3c37b57cdf0e6c506a47904721ee9001b5`.

With Node.js 20.18 or newer:

```sh
npm ci
export OBSERVER_ADMIN_KEY="$(openssl rand -hex 32)"
export OBSERVER_PORT=8787
npm run observer
```

Expose `127.0.0.1:8787` at a researcher-controlled HTTPS URL. In another terminal:

```sh
export OBSERVER_ADMIN_KEY="<same-random-value>"
export OBSERVER_BASE_URL="https://<controlled-observer-host>"
npx sandbox login
npx tsx pocs/SBX-013/encoded-dot-segment.ts
```

Alternatively, supply `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together for non-interactive authentication.

Successful output includes:

```json
{
  "outOfScopeActionAuthorized": true,
  "controlsPassed": true,
  "guestConfigurationContainsBrokeredSecret": false,
  "guestResponseContainsBrokeredSecret": false,
  "outsideControl": { "statusCode": 401, "actionAuthorized": false },
  "encodedDotdot": { "statusCode": 200, "actionAuthorized": true },
  "cleanup": { "stopped": true, "deleted": true, "errors": [] }
}
```

## Correlatable evidence

The hardened authenticated-action proof reproduced on two fresh, non-persistent Vercel sandboxes using the required HackerOne-alias account, team `team_n98ERpVwV7HqmWRudAyK8sXQ`, and project `prj_CyyVykdN06Nrkla6KidZcecLgbCa`:

| Harness correlation ID | Sandbox name | Vercel sandbox/session ID | Started (UTC) | Result |
| --- | --- | --- | --- | --- |
| `010c5a62-8f01-47dc-9ae3-dd3376c117fd` | `sbx-013-poc-010c5a62` | `sbx_W1TMO10InoRL4LZAukEc8uty6Hqu` | `2026-08-18T22:52:05.875Z` | Controls passed; direct outside action denied; encoded case authorized exactly one outside action |
| `4f79bbba-ef9b-42b0-b94a-40b13d4f86c0` | `sbx-013-poc-4f79bbba` | `sbx_qqvILzmYtGd9z5t9AF5qON4GX6e5` | `2026-08-18T22:52:21.561Z` | Controls passed; direct outside action denied; encoded case authorized exactly one outside action |

Both sandboxes stopped and deleted successfully, and both observer action configurations were deleted. The proposed confidential attachments are:

- `SBX-013-poc-010c5a62-8f01-47dc-9ae3-dd3376c117fd.json` — redacted controller evidence, SHA-256 `d018e0843685e8f3599036da01c0aab809d5a372c4142ecfd12bc156b41c9fc5`;
- `SBX-013-poc-010c5a62-8f01-47dc-9ae3-dd3376c117fd-private.json` — exact three-event observer evidence and fresh synthetic secret, SHA-256 `ccc7b4476951c5ab3bf9def4455309bf5dfd462290bc94c4f824a55a536941a4`;
- `SBX-013-poc-4f79bbba-ef9b-42b0-b94a-40b13d4f86c0.json` — redacted independent reproduction, SHA-256 `ad48135412b269ae5b58d1ae9cbbe036e4c47570e3199607ba972ab596b28ec8`;
- `SBX-013-poc-4f79bbba-ef9b-42b0-b94a-40b13d4f86c0-private.json` — exact independent observer evidence and fresh synthetic secret, SHA-256 `79831ad24178231368f8a1c759cc974adfade62b23bb24dbf4bba34fbad7cd27`.

The private files contain only per-run synthetic research credentials, but they should remain confidential and be uploaded directly to HackerOne with the source bundle.

## Impact

Hostile sandbox code can cause a path-scoped brokered credential to be used on a different canonical route at the same allowed origin. Depending on the application, that route could perform an authenticated mutation, disclose protected data, or expose the credential. The PoC demonstrates the mutation case without requiring credential reflection.

## Suggested remediation

Canonicalize the request path before evaluating authorization matchers and forward the same canonical representation used for that decision. Alternatively, reject ambiguous percent-encoded dot segments and separators before applying transforms. The firewall and downstream origin must make the path-scope decision on the same representation.
