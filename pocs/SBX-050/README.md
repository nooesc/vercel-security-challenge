# SBX-050: post-transform rule chaining

This bounded test asks one question: after a rule injects a hidden routing header, does the firewall incorrectly evaluate a later `forwardURL` rule against that newly injected header?

The controller uses one eligible-alias sandbox and two researcher-owned HTTPS origins:

- A is the ordinary destination.
- P is the controlled `forwardURL` proxy.
- Phase 1 proves a public trigger forwards A to P with exact Vercel OIDC.
- Phase 2 proves the hidden transform injects both controller-only values but terminates at A.
- Phase 3 installs transform then forward, in that order, and runs: plain A, direct-P block, decisive arm, direct-P block, plain A.

Only exact P receipt of both hidden values, independently verified `RS256` OIDC with `aud=P`, and exact team/project/session/sandbox identity is a conditional High candidate. Exact A receipt is a clean negative only when both final readbacks preserve both exact matchers. If Vercel returns its observed ordered two-rule matcherless/redacted projection, the controller may continue for the stronger behavioral P proof, but an A-side result remains indeterminate because it cannot prove which matchers were enforced. Anything else is indeterminate.

Every policy readback first writes and syncs a secret-free checkpoint to the exclusive mode-`0600` artifact. The checkpoint uses only a closed vocabulary for configured policy, active/independent sandbox and session projections, identity, selected projection mode, and the continuation decision; it never stores raw policies, hostnames, audiences, credentials, triggers, tokens, or digests. The matcherless exception is deliberately narrow: two rules in transform-then-forward order, both matchers absent, both injected values exactly platform-redacted, exact `forwardURL` audience, exact configured policy, exact sandbox top projections, and exact active/independent identity. Hybrids, extra rules/keys, reordered rules, a wrong audience, missing readbacks, or a final-before/final-after mode change abort.

## HOLD: semantics clarification required

Do not treat this packet as unconditionally report-ready. Before treating any positive as reportable or submitting it, ask Vercel:

> For multiple record-form rules on one domain, are all match predicates evaluated against the guest’s original request before any transform, or may a header injected by one rule satisfy a separate forwardURL rule? Do array order or injection-before-forward phases have defined semantics?

If sequential or phased transform-to-forward chaining is intended, close this lane. If rules are documented or confirmed as original-request-only/isolated, exact hidden-credential receipt at P is a credible conditional High. An ambiguous or undocumented result remains indeterminate until Vercel clarifies the boundary contract.

The HOLD applies only when the artifact assessment is `candidate-high`. A clean A-side result is closed/not reportable, and an indeterminate or error result is not reportable.

## Local checks

```sh
npx vitest run \
  test/sbx-050-controller.test.ts test/sbx-050-protocol.test.ts \
  test/sbx-050-guest.test.ts test/sbx-050-receiver.test.ts \
  test/sbx-050-proxy-helper.test.ts test/sbx-050-verdict.test.ts
npx tsc --noEmit --strict --skipLibCheck --module NodeNext --moduleResolution NodeNext --target ES2022 \
  pocs/SBX-050/action-chaining.ts pocs/SBX-050/protocol.ts pocs/SBX-050/verdict.ts pocs/SBX-050/receiver.ts
node --check guest/sbx-050-action-chain-probe.mjs
```

## One bounded live run

Do not overlap another live Sandbox test. Create two fresh Quick Tunnels in separate terminals:

```sh
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43150
```

```sh
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43151
```

Use their distinct lowercase origins as A and P. Generate keys locally and do not paste or commit them. In the receiver terminal:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX050_ADMIN_KEY='<FRESH_64_HEX_ADMIN_VALUE>'
export SBX050_ACTION_KEY='<DIFFERENT_FRESH_64_HEX_ACTION_VALUE>'
export SBX050_A_PUBLIC_ORIGIN='https://<A>.trycloudflare.com'
export SBX050_P_PUBLIC_ORIGIN='https://<P>.trycloudflare.com'
export SBX050_A_PORT=43150
export SBX050_P_PORT=43151
npx tsx pocs/SBX-050/receiver.ts
```

Generate each placeholder with `openssl rand -hex 32`. Wait for `{"ready":true,"aPort":43150,"pPort":43151}`. In the controller terminal, set the same two values and origins locally, without posting them anywhere, then run:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX050_ADMIN_KEY='<SAME_ADMIN_VALUE>'
export SBX050_ACTION_KEY='<SAME_ACTION_VALUE>'
export SBX050_A_PUBLIC_ORIGIN='https://<A>.trycloudflare.com'
export SBX050_P_PUBLIC_ORIGIN='https://<P>.trycloudflare.com'
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX050_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX050_SCOPE_CONFIRMATION='I_CONTROL_BOTH_SBX050_ORIGINS_AND_AUTHORIZE_BOUNDED_ACTION_CHAINING_TESTING' \
SBX050_ADMIN_KEY="$SBX050_ADMIN_KEY" \
SBX050_ACTION_KEY="$SBX050_ACTION_KEY" \
SBX050_A_PUBLIC_ORIGIN="$SBX050_A_PUBLIC_ORIGIN" \
SBX050_P_PUBLIC_ORIGIN="$SBX050_P_PUBLIC_ORIGIN" \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-050/action-chaining.ts
task_sbx050_status=$?
unset task_vercel_token SBX050_ADMIN_KEY SBX050_ACTION_KEY
printf 'SBX-050 exit status: %s\n' "$task_sbx050_status"
```

The controller writes one exclusive mode-`0600` private artifact and always attempts receiver run-state deletion plus sandbox stop/delete/delayed absence checks. Exit `10` means technical candidate on reportability HOLD, `0` means clean negative, and `1` means error or indeterminate. Trust the artifact assessment, reportability, and cleanup fields—not the exit code alone. `cleanup.receiver.deleted` means only the per-run receiver record was removed; it does not stop the receiver or tunnels.

After every run, press Ctrl-C in the receiver terminal and in both Quick Tunnel terminals. In the receiver shell, unset the retained local values, then verify neither receiver port is listening:

```sh
unset SBX050_ADMIN_KEY SBX050_ACTION_KEY SBX050_A_PUBLIC_ORIGIN SBX050_P_PUBLIC_ORIGIN
lsof -nP -iTCP:43150 -sTCP:LISTEN
lsof -nP -iTCP:43151 -sTCP:LISTEN
```

Both `lsof` commands must print nothing before considering manual receiver/tunnel cleanup complete.

If the artifact says either the recovery journal or live lock was retained, do not delete those files blindly. Read only that exact journal's `runId`, sandbox name, team/project, and ownership tags; use them to re-check, stop, and delete only the exact owned sandbox, delete only that run's receiver state, and obtain delayed absence checks for both. A create request that did not yield a provenance-validated sandbox handle and session stays uncertain even if an object is later recovered/deleted or the packet's short recovery checks are absent; wait through the configured 360-second sandbox lifetime/terminal horizon and re-check the exact owned name and tags. Remove only the exact journal and `SBX-050-live-active.lock` after those checks are clean. Until then, the retained lock intentionally prevents another live run.
