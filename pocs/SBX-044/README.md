# SBX-044: executable refinement of SBX-005 wildcard label scope

**Status: one bounded live run completed; clean negative, no report.**

Vercel's current Sandbox firewall documentation says a wildcard replaces one
complete DNS label, permits wildcard labels anywhere in a domain pattern, and
shows `www.*.com` matching `www.example.com` but not
`www.api.example.com`. It separately says only a **leading** wildcard such as
`*.example.com` matches subdomains at arbitrary depth.

This packet asks one narrow question: does the user-defined rule
`s44a.*.form-app.app` accidentally match the deeper controlled hostname
`s44a.one.two.form-app.app`?

This is the narrowed executable form of the existing SBX-005 wildcard
label-boundary hypothesis. A positive result belongs in one SBX-005 report;
SBX-044 is not a second root cause or a second bounty claim.

The controlled topology is:

- documented positive A: `s44a.one.form-app.app`;
- denied deeper B: `s44a.one.two.form-app.app`;
- wildcard policy: `s44a.*.form-app.app`.

Cloudflare Custom Domains attach A and B to separate Worker deployments. Each
Worker returns only a role plus a keyed opaque operation ID. A per-run Durable
Object ledger is armed by the controller with exact case IDs and canaries before
traffic; it stores only role, case, boolean brokered-state, time, and the opaque
operation ID. The Worker never logs or reflects a brokered header and retains
no raw value or standalone/unkeyed digest; only the necessary keyed receipt is
kept. A guest cannot forge a receipt because the HMAC and ledger-admin keys
never enter the sandbox.

## Staged proof bar

1. Outside-sandbox health and keyed public receipts prove exact A/B routing.
2. A fresh allow-both sandbox proves both endpoints are reachable with strict
   TLS and no transform.
3. A fresh sandbox starts with exact `s44a.*.form-app.app` and no transform.
   A must return its keyed receipt. If B is blocked, this is a clean pass. If B
   returns its exact keyed receipt, the documented label boundary is violated
   and the maximum demonstrated impact is Medium.
4. Only after that public signal, a third fresh sandbox uses the same wildcard
   with a fresh controller-only `x-sbx044-brokered-secret` transform. A must
   prove injection. B's exact secret-dependent receipt is the only High
   candidate.
5. Each sandbox must have active and independent same-session policy readbacks,
   use one fresh connection per request, and stop/delete with repeated absence
   checks.

The raw credential, action key, response body, and TLS trust-path values must
never enter guest configuration, stdout, or artifacts. A candidate is expected
to exit nonzero and requires a fresh independent reproduction before reporting.

## Implemented controller bounds

`wildcard-label-scope.ts` requires the exact HackerOne-alias team/project, the
two fixed Custom Domains, four distinct strong Worker keys, and an explicit
owned-endpoint scope acknowledgement. It performs keyed outside pre/postflight,
three fresh nonpersistent sandboxes at most, active plus independent
same-session policy reads before and after each stage, one fresh TLS connection
per request, 350 ms spacing, strict cleanup, and a mode-0600 private artifact.
The mode-0600 live lock contains only the test ID, run UUID, and start time. If
the process is interrupted, do not remove it blindly: use that UUID to inspect
the deterministic `sbx-044-{stage}-{uuid-without-dashes}` names and the two
Worker ledgers, clean only exact matching resources, then remove the lock.

The secret stage cannot run unless the public stage has already produced the
exact B receipt. The exact platform denial signals `EHOSTUNREACH/connect/-113`
and `EAI_AGAIN/getaddrinfo/-3001` are clean blocks only with zero connection,
request, TLS, response, and B-ledger contact. Any other DNS error, reset,
refusal, timeout, malformed receipt, or observer ambiguity is indeterminate.

## Live result

Run `b5085200-7760-4b25-ba40-1caadb385a54` reproduced the documented behavior.
The exact wildcard policy reached A before and after the target request, while
deeper B was blocked pre-connect with `EAI_AGAIN/getaddrinfo/-3001` in 32 ms and
recorded no event. Baseline and outside A/B keyed controls, same-session policy
readbacks, stop/delete/absence checks, ledger cleanup, and postflight all
passed. No credential stage ran, and there is no reportable finding.

## Local validation

The Worker is under `infra/sbx044-wildcard-worker`. Its environments deliberately
use exact Cloudflare Custom Domains, not wildcard DNS or Quick Tunnels:

```sh
cd infra/sbx044-wildcard-worker
npm install
npm run check

cd ../..
node --check guest/wildcard-label-probe.mjs
npx vitest run \
  test/sbx-044-wildcard-label.test.ts \
  test/sbx-044-wildcard-guest.test.ts \
  test/sbx-044-worker-protocol.test.ts
```

Do not rerun this closed lane unchanged. A future materially different wildcard
grammar hypothesis would need its own documented contract and proof matrix.

Primary contract: <https://vercel.com/docs/sandbox/concepts/firewall>
