# SBX-013 minimal live reproduction

This PoC demonstrates a raw-path versus canonical-route authorization mismatch in a researcher-owned Vercel Sandbox. A credential transform scoped to `/matched/` is applied to `/matched/%2e%2e/outside`; the controlled Node origin parses that same request target as `/outside` and uses the injected synthetic credential to authorize an outside action.

The outside endpoint returns only an opaque operation ID. It never reflects the credential. The canonical `/outside` control returns `401`; the encoded dot-segment request returns `200`, and the controller confirms the outside action occurred exactly once.

## Included components

- `pocs/SBX-013/encoded-dot-segment.ts`: controller and assertions;
- `guest/http-probe.mjs`: low-level guest HTTP client that preserves the request target;
- `src/observer-server.ts` and `src/observer-cli.ts`: controlled origin and evidence API;
- `src/contracts.ts` and `tsconfig.json`: observer types and base compiler configuration;
- `package.json` and `package-lock.json`: pinned dependencies, including `@vercel/sandbox@3.0.0`.

## Prerequisites

- Node.js 20.18 or newer;
- authenticated access to the HackerOne-alias Vercel Sandbox project required by the challenge policy;
- a temporary HTTPS URL forwarding to local port 8787 (Cloudflare Quick Tunnel or an equivalent researcher-controlled forwarder).

## Reproduce

Install the pinned packages:

```sh
npm ci
```

Generate a random observer admin key and keep it local:

```sh
export OBSERVER_ADMIN_KEY="$(openssl rand -hex 32)"
export OBSERVER_PORT=8787
```

Start the observer in terminal 1:

```sh
npm run observer
```

Expose port 8787 over a researcher-controlled HTTPS endpoint in terminal 2. For example, with `cloudflared` installed:

```sh
cloudflared tunnel --url http://127.0.0.1:8787
```

In terminal 3, set the printed HTTPS origin, authenticate, and run the PoC:

```sh
export OBSERVER_ADMIN_KEY="<same-random-value-from-terminal-1>"
export OBSERVER_BASE_URL="https://<temporary-controlled-host>"
npx sandbox login
npx tsx pocs/SBX-013/encoded-dot-segment.ts
```

Before relying on the result, confirm the Sandbox CLI authenticated the required `<username>@wearehackerone.com` account. The user who submits the report must personally execute and verify the live PoC; do not submit an unverified automated result.

If using explicit non-interactive credentials, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together instead of the device login.

Success requires:

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

The PoC writes a redacted evidence file and a separate ignored `-private.json` attachment containing the three raw observer events. The private attachment contains only a freshly generated synthetic credential, but it should be shared confidentially through HackerOne rather than committed. Cleanup failure makes the PoC exit nonzero.
