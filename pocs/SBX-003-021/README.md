# SBX-003/SBX-021 mixed-DNS explicit-deny discriminator

This controller tests whether a domain allow rule can route a new hostname connection to an explicitly denied IPv4 address. It never changes DNS. The researcher must control one hostname and exactly two IPv4 endpoints:

- `T`: the target address placed in `subnets.deny` as `T/32`;
- `S`: the non-denied edge control;
- both addresses must terminate HTTPS for the same hostname with a publicly trusted certificate and forward to the same controlled observer state.

The controller uses the existing guest `authority-probe.mjs`, which keeps certificate verification enabled and records DNS lookup, TLS certificate, and actual socket `remoteAddress` metadata.

## Deterministic sequence

1. A fresh nonpersistent `allow-all` sandbox sends fixed-destination HTTPS probes to T and S with the declared hostname as both TLS SNI and HTTP Host. Both must produce one matching observer event and one opaque vhost action.
2. After successful cleanup, a second fresh sandbox uses `allow: [hostname]` plus `subnets.deny: [T/32]`. A fixed T probe must fail with no event/action, while fixed S must reach the observer with verified TLS and one action.
3. Only then does the controller execute hostname probes. Before each probe, the controller polls DNS at no more than once per second and requires the A answer set to contain exactly the address declared by the current epoch. The default plan is `S,T,S`.
4. A DNS state that cannot be confirmed before the bounded deadline stops the sequence as `indeterminate`. A guest lookup/remote address that does not match the controller-confirmed epoch is also `indeterminate`.

Verdicts are deliberately conservative:

- `candidate`: all controls and cleanup pass, a controller-confirmed T epoch resolves to T inside the guest, the verified TLS socket's actual `remoteAddress` is T, and exactly one matching observer event and action occurs even though the fixed T control was blocked;
- `pass`: all S epochs reach S, every T epoch resolves to T but is blocked with no event/action, and all controls/cleanup pass;
- `indeterminate`: any baseline, DNS rotation, guest lookup, TLS, observer correlation, fixed deny, action, or cleanup proof is missing.

## Required environment

```sh
export SBX_MIXED_DNS_SCOPE_CONFIRMATION=I_CONTROL_THE_HOSTNAME_AND_BOTH_IPV4S
export SBX_MIXED_DNS_HOSTNAME=rotate.researcher.example
export SBX_MIXED_DNS_DENIED_IPV4=203.0.113.10
export SBX_MIXED_DNS_ALLOWED_IPV4=203.0.113.11
export OBSERVER_BASE_URL=https://rotate.researcher.example
export OBSERVER_ADMIN_KEY="$(openssl rand -hex 32)"
```

Optional bounds:

```sh
export SBX_MIXED_DNS_EPOCH_PLAN=S,T,S
export SBX_MIXED_DNS_EPOCH_TIMEOUT_MS=60000
export SBX_MIXED_DNS_POLL_INTERVAL_MS=1000
```

The combined epoch deadlines may reserve at most 180 seconds, keeping the deny phase inside its bounded sandbox lifetime even when a DNS transition never appears.

Start with the hostname publishing only S. Use separate researcher-controlled DNS automation, or manually change the record when the controller writes each waiting message to stderr, to publish only T and then only S. The controller has no DNS-provider integration and performs no DNS writes. If authoritative TTL/caching prevents the exact sequence from being observed, accept the `indeterminate` result rather than weakening the proof.

After the observer and external DNS schedule are ready:

```sh
npm ci
npx sandbox login
npx tsx pocs/SBX-003-021/mixed-dns-explicit-deny.ts
```

For noninteractive access, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together. Use only the required HackerOne-alias account.

The controller dispatches Vercel SDK calls at least 250 ms apart, runs probes sequentially, never retries a guest request, creates at most two sandboxes, and always attempts stop/delete. The vhost action configuration is also deleted. Private evidence is written beneath ignored `artifacts/` with mode `0600`.

Do not point T, S, or the hostname at third-party infrastructure. Do not run this proof if both endpoints do not share the same controlled observer state and valid certificate.
