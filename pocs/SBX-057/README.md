# SBX-057 — wildcard-empty transform isolation

Status: **LIVE-CLOSED / clean negative.** The local packet remains frozen except for the
millisecond-resolution verdict correction documented below.

Live result (2026-08-19): run `7defaa51-7bad-4a0d-81d2-7b5b054e5129` is a clean negative. The
exact-domain comparator was clean; under the wildcard target, A received the exact transform and
B returned the exact no-header receipt. All four events, policy readbacks, and cleanup gates were
exact. The original frozen verdict reported indeterminate only because the target policy proof and
the causally later probe start serialized to the same millisecond; the narrow chronology fix below
accepts equality at that controller-ordered edge while still rejecting reversed order. No rerun is
warranted.

## Question

The installed `@vercel/sandbox@3.0.0` types document this canonical record policy shape:

```ts
{
  allow: {
    "ai-gateway.vercel.sh": [{ transform: [{ headers: { authorization: "Bearer ..." } }] }],
    "*": [],
  },
}
```

The same types say that an empty rule array allows the domain with no additional rules. The SDK
sends record policies directly after validation. On readback it rebuilds rules by joining
`allowedDomains` with server-returned `injectionRules` by each rule's exact domain.

SBX-057 asks one narrow question: can the empty `"*"` entry accidentally inherit or join the
exact A-domain transform, causing a fresh ordinary direct request to unrelated B to receive A's
controller-held credential?

This is distinct from redirect, forwarding, reused connections, Host/SNI confusion, and the
SBX-011 redirect negative. Repository history behaviorally covered exact `A transform + B []`,
but not the canonical `A transform + "*" []` target with a direct-B isolation comparator.

## Fixed matrix

The controller uses two sequential, fresh, nonpersistent Sandboxes. A and B are distinct
researcher-owned Quick Tunnel HTTPS origins terminating at separate local receiver ports.

| Sandbox | Exact policy | Probe 1 | Probe 2 | Required interpretation |
|---|---|---|---|---|
| comparator | `{A: [transform comparatorSecret], B: []}` | direct A | fresh direct B | A must prove its action; B must receive no header. If B gets the exact comparator secret, stop as a separate exact-domain root. |
| target | `{A: [transform targetSecret], "*": []}` | direct A | fresh direct B | A must prove its action. Exact target secret at B is the candidate; no header at B is the clean documented behavior. |

Every request uses one fresh Node HTTPS connection with exact B DNS target, SNI, and Host for the
B cases. There is no redirect, retry, proxy, `forwardURL`, connection reuse, custom CA, OIDC, or
guest-controlled transform header. The two 256-bit transform values never enter guest config,
environment, argv, source, staged files, stdout, result, or retained receiver evidence.

## Verdict bar

`candidate-high` requires all of the following:

- exact eligible alias, team, and project identity;
- distinct canonical A and B Quick Tunnel origins;
- exact active and independent same-session readbacks before and after both phases;
- exact top-level allowed-domain projection and exact session projection containing only A's one
  redacted transform rule plus the comparator B-empty or target wildcard-empty entry;
- exact in-memory comparison to the controller-held raw policy before sanitizing evidence;
- comparator A action and clean comparator B receipt;
- target A action and target B's exact target-secret HMAC commitment, keyed opaque receipt, and
  nonreflecting keyed action;
- exactly four sequential receiver events, zero extra/unexpected/unattributed ingress, and strict
  configured → policy-before → A → B → policy-after → snapshot chronology;
- three named Sandbox absence checks per created resource, two receiver-state absence checks, and
  durable mode-0600 artifact/journal/lock cleanup with no release transaction left behind.

`pass` requires the same controls with target B proving exact clean reachability and no transform
header. Bare HTTP output, a wrong/cross-stage credential, missing event, extra ingress, projection
drift, chronology overlap, or incomplete cleanup is indeterminate. An exact comparator-B leak is
`alternate-root` and stops before target creation.

An exact target-B controller-secret action is High-capable because it demonstrates disclosure of a
credential configured only for A to an ordinary unrelated direct destination B. B reachability
alone is expected and is not a finding.

## Local receiver and live prerequisites

Only one live lane may run at a time. Before any separately coordinated run, obtain:

- explicit eligible alias PAT, team, project, alias-email, and scope confirmations;
- two distinct fresh researcher-owned Quick Tunnel HTTPS origins;
- fresh distinct `SBX057_ADMIN_KEY` and `SBX057_ACTION_KEY` values (32–256 URL-safe bytes);
- a clean artifacts directory with no `SBX-057-live-active.lock` or pending recovery journal;
- confirmation that no other task is using Vercel, tunnels, DNS, or public receivers.

Start the receiver locally:

```sh
export SBX057_A_PUBLIC_ORIGIN='https://A.trycloudflare.com'
export SBX057_B_PUBLIC_ORIGIN='https://B.trycloudflare.com'
export SBX057_ADMIN_KEY='fresh_urlsafe_32_or_more_bytes'
export SBX057_ACTION_KEY='different_fresh_urlsafe_32_or_more_bytes'
export SBX057_A_PORT=43157
export SBX057_B_PORT=43158
export SBX057_ADMIN_PORT=43159
npx tsx pocs/SBX-057/receiver.ts
```

In separately owned terminal processes, point Quick Tunnel A to `http://127.0.0.1:43157` and B to
`http://127.0.0.1:43158`. Do not route both public names through one public frontend or reuse a
prior tunnel URL.

After explicit live-slot coordination only:

```sh
export VERCEL_TOKEN='explicit_eligible_alias_pat'
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export SBX057_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com'
export SBX057_SCOPE_CONFIRMATION='I_CONTROL_BOTH_SBX057_ORIGINS_AND_AUTHORIZE_ONE_BOUNDED_WILDCARD_TRANSFORM_ISOLATION_TEST'
export SBX057_ADMIN_ORIGIN='http://127.0.0.1:43159'
npx tsx pocs/SBX-057/wildcard-empty-isolation.ts
```

The run is bounded to at most two nonpersistent Sandboxes and four sequential guest requests. A
candidate exits 10. A pass exits 0. Any controller, evidence, or cleanup uncertainty exits nonzero
and retains the fixed lock plus recovery journal.

Cleanup-only recovery is a distinct mode and never emits an experiment verdict:

```sh
export SBX057_RECOVERY_RUN_ID='the-original-uuidv4'
npx tsx pocs/SBX-057/wildcard-empty-isolation.ts
```

Unknown create-response state is not released until the conservative create-request plus Sandbox
lifetime settlement horizon has elapsed and three delayed exact-name absences are observed.

## Local verification

```sh
npx vitest run test/sbx-057-*.test.ts
npx tsc --noEmit --strict --target ES2023 --module NodeNext --moduleResolution NodeNext --skipLibCheck \
  pocs/SBX-057/protocol.ts pocs/SBX-057/live-lock.ts pocs/SBX-057/safety.ts \
  pocs/SBX-057/receiver.ts pocs/SBX-057/verdict.ts pocs/SBX-057/wildcard-empty-isolation.ts \
  test/sbx-057-controller.test.ts test/sbx-057-guest.test.ts test/sbx-057-receiver.test.ts \
  test/sbx-057-safety.test.ts test/sbx-057-verdict.test.ts
node --check guest/sbx-057-wildcard-empty-probe.mjs
npm test
npm run typecheck
git diff --check -- guest/sbx-057-wildcard-empty-probe.mjs \
  guest/sbx-057-wildcard-empty-probe.d.mts pocs/SBX-057 test/sbx-057-*.test.ts
```
