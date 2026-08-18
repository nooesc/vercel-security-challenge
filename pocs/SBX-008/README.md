# SBX-008 SNI/Host policy-confusion probe

This standalone PoC tests whether a sandbox policy that allows only controlled origin A can reach a distinct controlled origin B by connecting with A's TCP destination and TLS SNI while sending B in the HTTP `Host` header.

It is deliberately conservative. Merely showing that a server received `Host: B` is normal HTTP behavior and is recorded only as a weak signal. In default `plain` mode, the PoC reports `candidate: true` only when direct B is blocked but the A/SNI-A/Host-B request executes a B-host-only action exactly once and its opaque operation ID matches the guest response. In optional `credential` mode, it additionally configures a fresh synthetic transform for A and requires the mismatched request to arrive at B with that controller-only value. The secret never enters guest configuration or response data.

## Cases

1. `positive-a`: destination A, SNI A, Host A; must receive A's synthetic transform and reach the observer but receive `421` from the B-host-only action route.
2. `direct-b-negative`: destination B, SNI B, Host B; must fail before reaching either observer.
3. `reverse-b-sni-host-a-negative`: destination B, SNI B, Host A; must also fail before reaching either observer.
4. `front-a-sni-host-b`: destination A, SNI A, Host B; the candidate case must receive A's transform and authorize B's credential-gated action.

The two observer URLs must be distinct researcher-controlled HTTPS hostnames. They may front separate observer processes or the same controlled vhost-aware observer, but must never target third-party infrastructure.

## Prerequisites

- Node.js 20.18 or newer;
- authenticated access to a researcher-owned Vercel Sandbox project;
- two researcher-controlled HTTPS observer origins running the repository's observer service;
- the same local `OBSERVER_ADMIN_KEY` configured on both observer services.

Install pinned dependencies:

```sh
npm ci
```

Set controlled origins and authenticate:

```sh
export OBSERVER_A_URL="https://<controlled-observer-a>"
export OBSERVER_B_URL="https://<controlled-observer-b>"
export OBSERVER_ADMIN_KEY="<shared-random-admin-key>"
npx sandbox login
```

Run the PoC:

```sh
npx tsx pocs/SBX-008/sni-host-confusion.ts
```

After a plain-mode signal, test whether Vercel's brokered-transform path also permits the authority mismatch:

```sh
SBX008_MODE=credential npx tsx pocs/SBX-008/sni-host-confusion.ts
```

If using explicit non-interactive credentials, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together instead of using the device login.

## Interpretation

- `candidate`: direct and reverse access to B were blocked, the A control worked, and the mismatched request executed the controller-confirmed B-host-only action exactly once.
- `no-confirmed-exploit`: controls passed, but no B-specific event occurred. A forwarded `Host: B` signal alone is not a boundary break.
- `indeterminate`: a control or execution step failed, so the authority result cannot be trusted.

The run creates exactly one nonpersistent sandbox and always attempts both stop and delete. It also deletes the temporary vhost configuration from both observers. It writes one ignored, mode-`0600` private JSON artifact containing raw controlled observer events and actions. Cleanup or execution failures make the command exit nonzero. The PoC never disables TLS verification and the observer admin key is never placed in guest configuration.
