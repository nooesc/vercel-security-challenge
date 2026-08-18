# SBX-009 HTTP/2 authority-reuse discriminator

This bounded PoC tests whether Vercel's network firewall reevaluates HTTP/2 `:authority` on every stream of one verified TLS session. The sandbox policy allows only researcher-controlled origin A and injects a fresh controller-only synthetic credential on A requests. Controlled origin B is not allowed.

The controller configures a B-host action that requires that credential and returns only an opaque operation ID. It then runs:

1. a direct B negative control, which must fail without any observer event;
2. a fresh verified H2 A-authority control, which must receive the transformed credential;
3. a separate fresh verified H2 B-authority mismatch over TLS/SNI A, which must receive `403` without any observer event;
4. one verified HTTP/2 TLS session to A with an A → B → A `:authority` sequence.

The first and final A streams in the reused session must both reach A, receive the synthetic credential, and get `421` from the B-only action route. A clean pass requires the middle B stream to receive `403` with no event, followed by the successful final A stream. A reset, GOAWAY, ALPN failure, or connection close that prevents the final A control is indeterminate rather than a pass. A candidate requires the middle stream to reach B with A's credential and execute exactly one controller-confirmed action whose operation ID matches the guest response, followed by a successful final A control.

Interpretation:

- `candidate`: all controls pass and the second B-authority stream performs the single credential-gated B action;
- `pass`: all controls pass, the middle stream receives `403` without a B event or action, and the final A stream succeeds;
- `indeterminate`: a control, TLS/ALPN proof, evidence check, or cleanup step fails.

## Controlled prerequisites

- Node.js 20.18 or newer;
- authenticated access to a researcher-owned Vercel Sandbox project;
- two distinct researcher-controlled HTTPS origins running the repository observer;
- the same local `OBSERVER_ADMIN_KEY` configured on both observers.

```sh
npm ci
export OBSERVER_A_URL="https://<controlled-observer-a>"
export OBSERVER_B_URL="https://<controlled-observer-b>"
export OBSERVER_ADMIN_KEY="<shared-random-admin-key>"
npx sandbox login
npx tsx pocs/SBX-009/h2-authority-reuse.ts
```

For explicit noninteractive credentials, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together instead of running the device login.

## Evidence and cleanup

The run creates one fresh nonpersistent sandbox, always attempts stop and delete, and deletes temporary vhost configuration from both observers. Raw controlled events and actions are written to one ignored mode-`0600` artifact under `artifacts/`. The observer admin key and synthetic brokered credential never enter guest configuration, and TLS verification is never disabled.

Even a candidate should initially be treated as a likely SBX-008/SBX-010 authority-binding variant unless the live evidence shows the fresh H2 mismatch is rejected and enforcement differs specifically because the B `:authority` is sent on an already-authorized H2 session.
