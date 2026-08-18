# live deny-all update does not revoke some existing credential-transform TLS connections

> **NOT READY FOR SUBMISSION**
>
> This is a private draft based on a preliminary development-account reproduction. Do not submit until (1) the hardened three-socket PoC reproduces from a fresh HackerOne-alias Vercel account, (2) the researcher personally verifies the live PoC and impact, (3) the required alias-account Team, Project, and Sandbox IDs replace every placeholder below, and (4) the working PoC ZIP and alias-run evidence are attached.

## Submission metadata

- Asset: Vercel Sandbox network firewall / live network-policy updates / credential transforms
- Vulnerability class: Networking and Firewall; stale authorization after policy revocation
- Suggested weakness: CWE-284 (Improper Access Control). This label is secondary to the demonstrated network-policy differential.
- Suggested severity: **Medium only**
- HackerOne-alias account: `<researcher-alias@wearehackerone.com>`
- Vercel Team ID: `<team_REPLACE_FROM_ALIAS_RUN>`
- Vercel Project ID: `<prj_REPLACE_FROM_ALIAS_RUN>`
- Primary alias-run Sandbox ID: `<sbx_REPLACE_FROM_ALIAS_MULTI_SOCKET_RUN>`
- Additional cited alias-run Sandbox IDs: `<sbx_REPLACE_EACH_FRESH_REPRODUCTION>`
- Alias-run region: `<REPLACE>`
- Sandbox image/runtime: `<REPLACE_WITH_EXACT_ALIAS_RUN_IMAGE_AND_GUEST_RUNTIME>`
- SDK/controller runtime: `@vercel/sandbox@3.0.0`; `<REPLACE_WITH_EXACT_CONTROLLER_NODE_VERSION>`
- Submission state: **NOT READY — alias-account multi-socket reproduction and personal verification pending**

### Severity acknowledgement

I understand the program's severity-inflation bounty penalty. I am requesting **Medium**, not High or Critical, based only on the demonstrated post-revocation request and credential-transform use. The demonstrated request goes to the operator's originally intended origin, the guest does not retrieve the credential, the origin does not reflect it, and preliminary reproduction is timing-dependent.

## Summary

After `sandbox.updateNetworkPolicy("deny-all")` returned `"deny-all"`, one TLS connection opened under the prior allow-and-transform policy still carried a new HTTP request to the controlled origin. The observer received the request after the update acknowledgement and saw the synthetic credential that belonged to the removed transform. A fresh TLS connection to the exact same pinned IPv4 address was blocked with `EHOSTUNREACH`.

The post-update request reused the exact pre-update TLS socket: the guest recorded one handshake, the same derived socket ID before and after the update, `sameSocketAsPreUpdate: true`, and the same remote address and port. The response was `204`; it contained no credential. The observer recorded the credential only on its side and also returned an empty `204`, so this report does **not** claim credential retrieval or reflection.

This is a post-revocation authorization failure. The hostname was intentionally allowed before the update, but it was unauthorized after the acknowledged `deny-all` replacement.

## Security expectation

`updateNetworkPolicy("deny-all")` replaces the sandbox policy and returns the accepted policy. Once that awaited call completes, subsequent sandbox traffic should be governed by `deny-all`, including requests sent on connections established under the replaced policy. The removed credential transform should not continue to apply to later requests.

If Vercel intentionally defines live policy changes as applying only to newly created connections, please point to that contract. Such semantics would materially limit `deny-all` as an incident-response or credential-revocation control and should be made explicit. The differential here shows that a fresh connection is denied while at least one already-authorized flow can retain the removed authorization and transform state.

## Evidenced root cause

The evidence is consistent with stale per-flow policy and transform state: some authorization/transform decision associated with a connection opened under the old policy remained usable after the policy was replaced by `deny-all`.

I do not know whether this state is stored in a connection object, proxy, cache, host firewall entry, or another component, and this report does not assert any unobserved internal implementation. The externally demonstrated facts are:

1. one verified TLS connection and transform worked before the update;
2. the SDK acknowledged `deny-all`;
3. a new request on the same TLS connection reached the origin with the old synthetic transform value;
4. a new TLS connection to the same fixed IP was denied; and
5. four other fresh-sandbox attempts blocked the retained socket, showing that the stale behavior is intermittent rather than universal.

## Exact preliminary live differential

The cited preliminary candidate is private artifact `SBX-018-poc-07e87373-ecca-4f71-8568-482f1c15fa44-private.json` (SHA-256 `555567e3b9e4e55430f018757b224a3f4350383e6f9483b81186cfe9a5c066e5`). It used a development account that is **not** eligible submission metadata.

### Policy

The fresh nonpersistent sandbox started with this policy shape:

```ts
{
  allow: {
    [controlledObserverHost]: [{
      transform: [{
        headers: {
          "x-sbx-harness-canary": controllerOnlySyntheticCredential
        }
      }]
    }]
  }
}
```

The controller then awaited:

```ts
await sandbox.updateNetworkPolicy("deny-all");
```

The returned policy was exactly `"deny-all"`.

### Timing

| Event | UTC timestamp | Offset from completed update |
| --- | --- | ---: |
| Pre-update observer request | `2026-08-18T21:28:01.837Z` | — |
| Policy update requested | `2026-08-18T21:28:03.058Z` | — |
| `updateNetworkPolicy` completed and returned `deny-all` | `2026-08-18T21:28:03.545Z` | `0 ms` |
| Guest observed post-update trigger | `2026-08-18T21:28:03.834Z` | `+289 ms` |
| Observer received same-socket post-update request | `2026-08-18T21:28:03.860Z` | `+315 ms` |

The observer timestamp is later than the completed update, not merely later than the update request.

### Socket attribution

| Property | Recorded value |
| --- | --- |
| TLS authorization | `true` |
| Protocol | `TLSv1.3` |
| Handshake count | `1` before and after the update |
| Derived socket ID | `8aafdf701b8493643691274c3681dc180b0ca9ddbedb56b9187e591da55bb24b` |
| Same socket flag | `true` |
| Guest local endpoint | `100.64.24.28:58734` |
| Pinned remote endpoint | `104.16.230.132:443` |
| Peer certificate fingerprint | `CB:D9:CD:F7:7E:5C:EE:A2:80:1D:F3:14:29:95:E2:A6:27:84:8D:60:E1:A0:96:4E:EF:3E:06:1C:5C:94:7C:5D` |
| Pre-update response | `204`, empty body |
| Post-update reused-socket response | `204`, empty body |

The readiness record, primary TLS record, and post-update result all contain the same socket ID. No second TLS handshake was performed for the reused request.

### Same-IP fresh-connection control

Immediately after the reused-socket request, the same guest process attempted a new TLS connection to `104.16.230.132:443`. It failed with:

```text
connect EHOSTUNREACH 104.16.230.132:443
```

The observer recorded no fresh-connection event. This avoids treating DNS denial alone as the negative control.

The current three-socket PoC strengthens ordering further: it proves a fresh same-IP connection is blocked **before** triggering any retained socket. The preliminary candidate above did not contain that pre-trigger barrier, so this draft remains not ready until the hardened run reproduces.

### Credential handling

- The synthetic credential was generated by the controller and configured only in the host-side transform and controlled observer.
- Runtime guards verified it was absent from uploaded guest configuration and source.
- The guest response and persisted guest result did not contain the credential.
- The origin returned an empty `204`; it did not reflect the credential or any derivative.
- The controller credential SHA-256 and the post-update observer value SHA-256 were identical: `76dc197d8a7c09c722e8bedc1d1905ce26dae7eccf111bf7408db6db7f2c5ebb`.

This proves continued post-revocation use of the transform, not guest retrieval of the secret.

## Preliminary reproduction rate, including passes

Five fresh, nonpersistent development-account single-socket runs completed with their positive pre-update transform control, acknowledged `deny-all`, socket attribution/integrity controls for the current-schema runs, and successful stop/delete cleanup. One was a candidate and four were passes: **1/5 overall**.

| Correlation/run ID | Sandbox/session ID | Trigger after update completion | Fresh negative | Result |
| --- | --- | ---: | --- | --- |
| `b7bbab25-b529-4e91-a1e6-8c7e7184a8a9` | `sbx_PNs6bAs7RwkU3z8kH0jjJZXW3igw` | `+375 ms` | DNS `EAI_AGAIN` (older, weaker control) | Pass; retained socket timed out |
| `f975c3da-c71a-4193-ac64-e35a5f6c22bc` | `sbx_XDob2uqdRZNUMT01YYAQzrBVnegR` | `+104 ms` | Same IP `EHOSTUNREACH` | Pass; retained socket timed out |
| `07e87373-ecca-4f71-8568-482f1c15fa44` | `sbx_wvbHKSjjf003dITavRHpGfAcn8aY` | `+289 ms` | Same IP `EHOSTUNREACH` | **Candidate; retained socket returned 204 with old transform** |
| `366eb45f-819c-4fd0-a3c3-92e5a40ed249` | `sbx_SZG3jt2Q0iNIhFF0grogWoQqAYZk` | `+241 ms` | Same IP `EHOSTUNREACH` | Pass; retained socket timed out |
| `d3008b88-d02f-4349-a705-ab82351db9bb` | `sbx_P7l9rZ6YodHYCNan5x5e4EQrV3Iw` | `+5,413 ms` | Same IP `EHOSTUNREACH` | Pass; explicit 5-second settle delay |

The candidate rate among the four short-delay runs was `1/4`; the one explicit five-second-delay run passed. These are preliminary development-account results across evolving harness versions, not the final eligible reproduction rate. The intermittent result may indicate a short propagation or flow-state race, but the evidence does not identify the internal mechanism.

All five cited development sandboxes stopped and deleted successfully. Their identifiers are included only for private triage correlation and must not replace the required HackerOne-alias metadata.

## Hardened reproduction

The primary attachment should use `pocs/SBX-018/policy-update-existing-sockets.ts`, not only the preliminary single-socket controller. It:

1. resolves the controlled observer and pins one IPv4 endpoint;
2. creates one fresh, nonpersistent sandbox with the allow-and-transform policy;
3. opens three distinct, verified TLS sockets to that same IP with the controlled observer SNI/Host;
4. proves exactly one pre-update request and the controller-only synthetic transform on every socket;
5. awaits `updateNetworkPolicy("deny-all")` and records the completion timestamp;
6. performs a fresh, verified TLS request to the same pinned IP and requires it to fail with no observer event;
7. only after that barrier, triggers the retained sockets once each at `+250 ms`, `+750 ms`, and `+1,500 ms` from a recorded trigger epoch;
8. requires exact socket IDs, one handshake per retained connection, trigger/event timing after the barrier, command/result integrity, and no credential in guest responses;
9. records whether each retained socket crossed and reports `crossedCount`; and
10. stops and deletes the sandbox in all outcomes.

The trigger schedule remains below four observer requests per second and performs no retries.

### Prerequisites

- Node.js 20.18 or newer;
- the pinned repository dependencies, including `@vercel/sandbox@3.0.0`;
- a fresh Vercel project authenticated with the required `@wearehackerone.com` alias;
- a researcher-controlled HTTPS observer and its local admin key;
- no third-party endpoints, credentials, or data.

### Commands

```sh
npm ci
export OBSERVER_BASE_URL="https://<researcher-controlled-observer>"
export OBSERVER_ADMIN_KEY="<fresh-random-admin-key>"
npx sandbox logout
npx sandbox login

# Confirm this login is the required HackerOne alias before proceeding.
npx tsx pocs/SBX-018/policy-update-existing-sockets.ts
```

For noninteractive authentication, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together, using credentials for the HackerOne-alias project.

A candidate output must include all of the following:

```json
{
  "outcome": "candidate",
  "candidate": true,
  "crossedCount": 1,
  "controls": {
    "guestMaterialGuardPassed": true,
    "distinctSocketIds": true,
    "policyUpdateConfirmed": true,
    "freshBarrierPassed": true,
    "oldTriggersAfterBarrier": true,
    "commandAndSocketControlsPassed": true,
    "allBuiltInFreshAttemptsBlocked": true
  },
  "cleanup": {
    "stopped": true,
    "deleted": true,
    "errors": []
  }
}
```

`crossedCount` may be `1`, `2`, or `3`; at least one retained socket must cross. Do not classify timeout/reset/connection-close behavior as a candidate.

The single-socket controller remains useful as a secondary timing check:

```sh
npx tsx pocs/SBX-018/policy-update-existing-socket.ts
```

Its current form includes an explicit five-second post-acknowledgement delay and should not substitute for the pre-trigger same-IP barrier in the hardened run.

## Controls and false-positive exclusions

The hardened proof requires:

- a fresh sandbox and fresh synthetic credential;
- a controlled observer health check;
- a current DNS snapshot and one pinned remote IPv4 address;
- three different derived socket IDs and one verified TLS handshake per socket;
- one pre-update `204` request per socket with the exact synthetic transform value;
- an SDK return value of exactly `"deny-all"` and a recorded completion time;
- a fresh same-IP TLS connection blocked and checked for zero observer events before any retained socket trigger;
- unique non-secret correlation values for each retained socket;
- all trigger writes and guest trigger observations after the fresh-block barrier;
- stdout equal to the independently persisted guest result;
- zero credential occurrence in guest configuration, source, responses, and result;
- exactly one correlated post-update observer event for a crossing socket;
- the crossing event carrying the controller-only transform value;
- no retries and a bounded trigger schedule; and
- successful stop/delete cleanup.

The result is not inferred from a client error alone. It requires a post-update observer event with exact run, test, case, phase, host, path, timing, and credential correlation.

## Impact and limitations

A hostile workload can pre-open outbound TLS connections while a permissive credential-transform policy is active. If an operator later replaces that policy with `deny-all` to contain the workload or revoke brokered access, some retained flows may briefly continue sending requests and using the removed transform after the update is acknowledged.

This could permit a final authenticated mutation or exfiltration request to an origin the operator just revoked. The demonstrated scope is narrower:

- the destination is the same originally intended and researcher-controlled origin;
- no other tenant, host, or CIDR was reached;
- no credential was returned to or recovered by guest code;
- the origin did not reflect the credential;
- the PoC performed a harmless `GET` and received an empty `204`;
- the preliminary behavior reproduced only once in five single-socket runs; and
- no persistence beyond the life of the retained connection is demonstrated.

These constraints are why Medium is the maximum suggested severity.

## Suggested remediation

Treat a successful live policy replacement as a revocation barrier for existing as well as future traffic:

1. associate each authorized outbound flow and credential-transform context with a policy generation;
2. when a stricter policy is installed, close/reset existing flows authorized under an older generation, or reevaluate every subsequent request against the current policy before forwarding;
3. invalidate removed credential-transform state at the same atomic transition;
4. return success from `updateNetworkPolicy` only after the new generation is active for both new and existing flows; and
5. add regression tests for HTTP/1.1 keep-alive, HTTP/2, WebSocket, and raw TLS connections across allow/transform → `deny-all` transitions.

The generation language above is a remediation pattern, not a claim about Vercel's current implementation.

## Required alias-account verification before submission

- [ ] Researcher is authenticated with the required `@wearehackerone.com` alias.
- [ ] Exact `team_…` ID captured and inserted above.
- [ ] Exact `prj_…` ID captured and inserted above.
- [ ] Every cited fresh alias-run `sbx_…` ID captured and inserted above.
- [ ] Exact region, Sandbox image, guest runtime, SDK, and controller runtime recorded.
- [ ] Hardened three-socket PoC reproduced from a fresh nonpersistent sandbox.
- [ ] Fresh same-IP barrier passed before retained-socket triggers.
- [ ] At least one retained socket produced one exact credential-bearing post-update event.
- [ ] Researcher personally reviewed the observer event and confirmed the impact.
- [ ] All alias-run sandboxes stopped and deleted successfully.
- [ ] Program policy reread immediately before submission.

## Attachment checklist

- [ ] `SBX-018-working-poc.zip`, containing:
  - `pocs/SBX-018/policy-update-existing-sockets.ts`;
  - `pocs/SBX-018/policy-update-existing-socket.ts`;
  - `guest/policy-update-socket-probe.mjs`;
  - `guest/authority-probe.mjs`;
  - `src/observer-server.ts`, `src/observer-cli.ts`, `src/observer-client.ts`, and `src/contracts.ts`;
  - `package.json`, `package-lock.json`, `tsconfig.json`, and `tsconfig.poc.json`;
  - reproduction README.
- [ ] Fresh alias-account multi-socket private artifact: `<SBX-018-multi-poc-UUID-private.json>`.
- [ ] Fresh alias-account single-socket private artifact if cited: `<SBX-018-poc-UUID-private.json>`.
- [ ] Exact SHA-256 checksums for the final ZIP and every evidence attachment.
- [ ] Sanitized terminal transcript showing commands, alias verification, timestamps, output, and cleanup.
- [ ] Preliminary development artifact only if useful for triage context: `SBX-018-poc-07e87373-ecca-4f71-8568-482f1c15fa44-private.json`.

Do not attach unrelated artifacts, development-account credentials, observer admin keys, or raw Vercel tokens.
