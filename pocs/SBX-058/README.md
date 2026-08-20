# SBX-058 — header matcher entry binding

Status: **LOCAL-ONLY / DO NOT RUN WITHOUT A SEPARATE LIVE-SLOT COORDINATION**.

This bounded harness asks whether a record-form network-policy header matcher keeps
its exact key and exact value bound to the same original header entry.

The policy is one exact rule on researcher-owned origin A:

```json
{
  "allow": {
    "A": [{
      "match": {
        "headers": [{
          "key": { "exact": "x-sbx058-route" },
          "value": { "exact": "privileged" }
        }]
      },
      "forwardURL": "https://P/v1/sbx058/proxy/<run>"
    }]
  }
}
```

The one-sandbox sequence is fixed and non-overlapping:

1. Direct P pre-barrier: exact pre-request/pre-TLS network denial.
2. `exact-pair`: `x-sbx058-route: privileged` must reach P.
3. `key-half`: `x-sbx058-route: ordinary` must remain at A.
4. `value-half`: `x-sbx058-decoy: privileged` must remain at A.
5. `combined-halves`: both half headers on different entries; expected A.
6. Direct P post-barrier: the same exact denial class.

Every normal probe has a fresh patterned canary. A and P retain exactly four
ordered events with zero unexpected A, unexpected P, or unattributed ingress.
Active and independent same-session policy readbacks bracket the sequence.

A P-side result is not inferred from status or reachability. It requires the
installed official proxy helper, independent RS256 verification, exact
`aud=P`, exact team/project/session/name source claims, exact reconstructed A
URL/Host/forwarded metadata, and an opaque controller-keyed non-reflecting
receipt. The guest never receives the Vercel token or either controller key.

Classification:

- Exact combined P while exact-pair=P, both isolated halves=A, direct-P barriers,
  chronology, readbacks, retention, accounting, and cleanup all pass:
  **conditional High candidate, HOLD pending semantics clarification**.
- Exact combined A with every control exact: clean pass.
- Any secretless P reach, missing OIDC/source fact, matcher/readback hybrid,
  post-TLS/request-sent reset, extra ingress, cleanup uncertainty, or other shape:
  indeterminate/error, never a finding.

## Live prerequisites

- One verified eligible-alias Vercel PAT for the exact checked-in team/project.
- Two distinct fresh researcher-owned Quick Tunnel HTTPS origins:
  A -> local `43160`, P -> local `43161`.
- The receiver on loopback A/P ports with the admin endpoint reached directly at
  `http://127.0.0.1:43160`.
- Fresh distinct 32+ byte `SBX058_ADMIN_KEY` and `SBX058_ACTION_KEY`.
- No other live lane or repository-global live lock.
- Clean TLS/runtime override environment.

Start the receiver only after both tunnels exist:

```sh
env \
  SBX058_ADMIN_KEY="$SBX058_ADMIN_KEY" \
  SBX058_ACTION_KEY="$SBX058_ACTION_KEY" \
  SBX058_A_PUBLIC_ORIGIN="$SBX058_A_PUBLIC_ORIGIN" \
  SBX058_P_PUBLIC_ORIGIN="$SBX058_P_PUBLIC_ORIGIN" \
  SBX058_A_PORT=43160 \
  SBX058_P_PORT=43161 \
  npx tsx pocs/SBX-058/receiver.ts
```

After one explicit live-slot approval, run the controller exactly once:

```sh
env \
  VERCEL_TOKEN="$VERCEL_TOKEN" \
  VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
  VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
  SBX058_ALIAS_EMAIL_CONFIRMATION=swve@wearehackerone.com \
  SBX058_SCOPE_CONFIRMATION=I_CONTROL_BOTH_SBX058_ORIGINS_AND_AUTHORIZE_ONE_BOUNDED_HEADER_ENTRY_BINDING_TEST \
  SBX058_ADMIN_KEY="$SBX058_ADMIN_KEY" \
  SBX058_ACTION_KEY="$SBX058_ACTION_KEY" \
  SBX058_A_PUBLIC_ORIGIN="$SBX058_A_PUBLIC_ORIGIN" \
  SBX058_P_PUBLIC_ORIGIN="$SBX058_P_PUBLIC_ORIGIN" \
  SBX058_ADMIN_ORIGIN=http://127.0.0.1:43160 \
  npx tsx pocs/SBX-058/header-entry-binding.ts
```

If and only if a crash leaves the named mode-0600 recovery journal, use the
same environment plus the artifact run UUID:

```sh
SBX058_RECOVERY_RUN_ID='<uuid>' npx tsx pocs/SBX-058/header-entry-binding.ts
```

Recovery emits a distinct cleanup-only artifact and never an experiment pass or
candidate. Unknown create response loss remains fail-closed until the full
sandbox timeout plus create deadline and settlement margin have elapsed.

## Local verification

```sh
npx vitest run test/sbx-058-*.test.ts
node --check guest/sbx-058-header-binding-probe.mjs
npm run typecheck
git diff --check
```
