# Credential-brokering `path.startsWith` matches before encoded dot-segment canonicalization, applying credentials to a route outside the configured credential scope

## Submission metadata

- Asset: Vercel Sandbox network firewall / credentials brokering
- Suggested severity: Medium; impact can be higher when the outside route performs a sensitive operation
- Primary weakness: [CWE-647 — Use of Non-Canonical URL Paths for Authorization Decisions](https://cwe.mitre.org/data/definitions/647.html)
- Related weakness: [CWE-551 — Authorization Before Parsing and Canonicalization](https://cwe.mitre.org/data/definitions/551.html)
- Test environment: `@vercel/sandbox@3.0.0`, controller Node.js `v25.6.0`, controlled Node.js HTTP observer, Vercel region `iad1`

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

The hardened authenticated-action proof reproduced on two fresh, non-persistent Vercel sandboxes:

| Harness correlation ID | Sandbox name | Vercel session ID | Started (UTC) | Result |
| --- | --- | --- | --- | --- |
| `639e6a5a-d7e3-45f7-ba90-2f2e28ede5ac` | `sbx-013-poc-639e6a5a` | `sbx_ug2PEC6gTcQWHXeHL1xJzOMk5XTJ` | `2026-08-18T20:39:58.271Z` | Controls passed; outside action authorized only by encoded case |
| `a1ef4cb0-eb8b-46ea-9178-8609953f7b50` | `sbx-013-poc-a1ef4cb0` | `sbx_CesMZpxXQi7SHiTw9uDSDg1ba2UY` | `2026-08-18T20:40:48.261Z` | Controls passed; outside action authorized only by encoded case |

Both sandboxes stopped and deleted successfully. The tracked redacted result is `pocs/SBX-013/evidence/standalone-action-run-a1ef4cb0.json`. The confidential attachment `SBX-013-poc-a1ef4cb0-eb8b-46ea-9178-8609953f7b50-private.json` contains the exact three-event observer excerpt and synthetic value for triage correlation.

## Impact

Hostile sandbox code can cause a path-scoped brokered credential to be used on a different canonical route at the same allowed origin. Depending on the application, that route could perform an authenticated mutation, disclose protected data, or expose the credential. The PoC demonstrates the mutation case without requiring credential reflection.

## Suggested remediation

Canonicalize the request path before evaluating authorization matchers and forward the same canonical representation used for that decision. Alternatively, reject ambiguous percent-encoded dot segments and separators before applying transforms. The firewall and downstream origin must make the path-scope decision on the same representation.
