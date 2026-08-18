# SBX-018 live policy-update socket test

This controlled PoC tests whether a completed `deny-all` live policy update applies to a TLS connection opened under a credential-transform rule.

The controller resolves the researcher-owned observer immediately before the run and pins one controlled edge IPv4 address. The guest opens one verified TLS socket to that address with the observer's SNI and Host, then sends a pre-update request. The controller requires observer proof that it received a fresh controller-only synthetic credential, waits for the guest's socket-readiness record, calls `updateNetworkPolicy("deny-all")`, and only then triggers:

1. after a fixed five-second post-acknowledgement delay, a new request on the exact pre-update TLS socket;
2. a new verified TLS connection to the same pinned address, avoiding a DNS-only negative control.

- `candidate`: either marked post-update request reaches the observer after the SDK confirms `deny-all`; observing the removed synthetic credential is a stronger signal.
- `pass`: both the existing socket and fresh connection are blocked and the observer sees neither post-update marker.
- `indeterminate`: the pre-update transform control, policy-update confirmation, probe coordination, or cleanup fails.

```sh
export OBSERVER_BASE_URL="https://<controlled-observer>"
export OBSERVER_ADMIN_KEY="<random-admin-key>"
npx sandbox login
npx tsx pocs/SBX-018/policy-update-existing-socket.ts
```

The sandbox is nonpersistent. Stop/delete are always attempted, and raw mode-`0600` evidence is written under the ignored `artifacts/` directory.

## Three-socket hardened reproduction

`policy-update-existing-sockets.ts` is the higher-confidence reproduction. It opens three independent verified TLS sockets to one pinned observer IPv4 address. Every socket has a unique case ID, non-secret correlation value, readiness/result/trigger files, and exactly one pre-update TLS handshake. Before lockdown, the controller requires one `204` observer event with the exact controller-only transform value for each socket.

Immediately after `updateNetworkPolicy("deny-all")` returns, the controller uses `guest/authority-probe.mjs` for a fresh, verified TLS request to the same pinned IPv4 address and SNI. That request must fail with no observer event. No retained socket is triggered until this fresh-block barrier has been independently checked, and the evidence records its elapsed time from the completed policy update.

The retained sockets are triggered once each at offsets `+250 ms`, `+750 ms`, and `+1500 ms` from a recorded trigger epoch. This remains below four observer requests per second. Each retained-socket probe also records its own final fresh same-IP connection attempt. There are no retries.

```sh
export OBSERVER_BASE_URL="https://<controlled-observer>"
export OBSERVER_ADMIN_KEY="<random-admin-key>"
npx sandbox login
npx tsx pocs/SBX-018/policy-update-existing-sockets.ts
```

The hardened controller reports `candidate` only when all readiness, pre-update transform, fresh-block barrier, command-integrity, same-socket, timestamp, and cleanup controls pass and at least one exact `post-reused` event arrives after the barrier carrying the removed synthetic credential. `crossedCount` states how many of the three retained sockets crossed. Raw evidence is private, mode `0600`, and the sandbox remains nonpersistent with stop/delete attempted in all outcomes.
