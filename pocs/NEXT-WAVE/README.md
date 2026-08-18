# Next-wave redirect probes

`cross-origin-redirect.ts` runs two isolated, controlled tests against fresh nonpersistent Vercel sandboxes. It never targets third-party infrastructure.

## Required setup

Run two instances of this repository's observer behind distinct HTTPS hostnames. Both observers must use the same admin key.

```bash
export OBSERVER_A_URL="https://observer-a.researcher.example"
export OBSERVER_B_URL="https://observer-b.researcher.example"
export OBSERVER_ADMIN_KEY="a-long-random-controller-only-value"
```

The two URLs must have distinct hostnames. The observer redirect API accepts only absolute HTTPS targets without embedded credentials or fragments.

Authentication can use an existing `npx sandbox login` session. To use explicit credentials instead, provide all three values together:

```bash
export VERCEL_TOKEN="..."
export VERCEL_TEAM_ID="..."
export VERCEL_PROJECT_ID="..."
```

Run from the repository root:

```bash
npx tsx pocs/NEXT-WAVE/cross-origin-redirect.ts
```

## Proof sequence

Each hypothesis gets a new run ID, its own redirect configuration, and a fresh sandbox. The controller uploads `guest/redirect-probe.mjs`; the controller-only observer key and synthetic brokered credential are rejected if either appears in a serialized guest payload.

### SBX-007: redirect to a disallowed origin

The policy allows only observer A.

1. A direct request to A must succeed and produce an A event.
2. A direct request to B must fail and produce no B event.
3. A request to A's controlled redirect route follows one hop toward B.

The result is a candidate only if both controls pass and B records the redirected case. Seeing only the A redirect event is a passing boundary result.

### SBX-011: cross-origin credential carryover

The policy allows observer A with a controller-only `x-sbx-harness-canary` transform and allows observer B with no transform.

1. A direct request to A must arrive with the exact synthetic credential.
2. A direct request to B must arrive without that header.
3. The redirect source at A must receive the exact credential.
4. The redirected request must reach B.

The result is a candidate only if B receives the exact controller-only credential. A redirect that reaches B without the header is a pass. A different unexpected header value is indeterminate, not a candidate.

## Evidence and cleanup

Raw observer events can contain the synthetic brokered credential, so each run writes a mode-`0600` private JSON artifact under `./artifacts` (or `HARNESS_ARTIFACTS_DIR`). Console output contains hashes, verdicts, cleanup status, and artifact paths, but never the raw credential.

The controller attempts sandbox stop, sandbox deletion, and observer redirect-configuration deletion even when setup or a probe fails. A cleanup error makes the process exit nonzero.
