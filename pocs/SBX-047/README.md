# SBX-047 — explicit `fork()` network-policy override enforcement

Status: **local packet ready; no live run has been made**.

## Hypothesis

`Sandbox.fork()` copies the source sandbox configuration, while any field supplied to the
fork is documented as an override. This packet creates an owned source whose only network
rule is an exact A-host credential transform, proves that rule with a nonreflecting protected
action, then creates:

1. an inheritance control that deliberately omits `networkPolicy` and must copy A's rule;
2. a distinct target fork with the explicit SDK input `networkPolicy: "deny-all"`.

The target fork response, active handle, independent `Sandbox.get({ resume: false })`, and both
`currentSession().networkPolicy` views must all remain the same literal SDK value `deny-all`
before and after the request. The installed SDK 3.0.0 offline audit proves that this input is
sent to `POST /v2/sandboxes/:source/fork` as its exact wire representation
`{"mode":"deny-all"}`; the inheritance request omits the field.

For host-rule policies, the current API's top-level sandbox projection returns only the exact
allowed-host list while `currentSession().networkPolicy` retains the redacted transform. The
source and inheritance gates accept only that exact split projection and then require keyed
behavioral transform controls. The deny-all target is still required to return literal
`deny-all` at every sandbox and session projection.

This is distinct from SBX-025 (policy restoration across stop/resume) and SBX-045 (a fork
environment-variable override). It tests server-side enforcement of a fork-time network-policy
override.

## Conservative impact gates

- A target request is attempted once. One exact keyed observer event plus the matching guest
  receipt is a Medium policy-boundary signal.
- The protected target action is staged only after that public signal. It is attempted only if
  the observer independently saw the exact source-only transform commitment on the target
  request.
- High is emitted only when the target then executes the newly staged protected action and both
  observer and guest carry the exact secret proof and opaque operation ID.
- A clean negative requires the known pre-connect deny-all error tuple, zero target events,
  intact positive source/inheritance controls, and a healthy observer after the target attempt.
- Duplicate, reordered, unknown-case, or otherwise unexpected events are indeterminate.

The transform credential and staged secrets are generated in the controller. They never enter
the guest program, command arguments/environment, stdout, or artifact. The observer retains only
SHA-256/HMAC commitments and clears staged secret bytes. Raw guest output is parsed and discarded.

## Local verification

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
npx vitest run test/sbx-047-*.test.ts
npx tsc --noEmit
npx tsc --noEmit -p tsconfig.poc.json
npx tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --esModuleInterop --skipLibCheck pocs/SBX-047/*.ts
node --check guest/sbx-047-network-request.mjs
```

These checks are local-only. The SDK tests inject a fake `fetch` and never contact Vercel.

## One bounded live run

Use one fresh Quick Tunnel. Keep all three terminals open. Do not reuse an old tunnel URL or
admin key.

Tunnel terminal:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43147
```

Copy its exact lowercase `https://…trycloudflare.com` origin as `PUBLIC_ORIGIN`.

Receiver terminal:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_sbx047_admin_key=$(openssl rand -hex 32)
export SBX047_ADMIN_KEY="$task_sbx047_admin_key"
export SBX047_PUBLIC_ORIGIN='https://<FRESH-ID>.trycloudflare.com'
export SBX047_RECEIVER_PORT=43147
npx tsx pocs/SBX-047/receiver.ts
```

Wait for `{"ready":true,"testId":"SBX-047","host":"127.0.0.1","port":43147}`. Reuse the
same admin-key value in the controller terminal without printing or pasting it into chat.

Controller terminal:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_sbx047_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_sbx047_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX047_EXPECTED_ALIAS='swve@wearehackerone.com' \
SBX047_SCOPE_CONFIRMATION='I_RECHECKED_SBX047_SINGLE_ACCOUNT_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_FORK_POLICY_TEST' \
SBX047_ADMIN_KEY='<SAME_RECEIVER_ADMIN_KEY>' \
SBX047_PUBLIC_ORIGIN='https://<FRESH-ID>.trycloudflare.com' \
SBX047_ADMIN_ORIGIN='http://127.0.0.1:43147' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-047/fork-network-policy.ts
task_sbx047_status=$?
unset task_sbx047_vercel_token
printf 'SBX-047 exit status: %s\n' "$task_sbx047_status"
```

The controller makes no retries, serializes external starts at 250 ms or slower, uses fresh
UUID-tagged source/inheritance/target names, and stops/deletes/confirms absence for all three in
reverse order. It also deletes and confirms absence of the observer configuration. A candidate
uses exit status 10; read the JSON/artifact rather than interpreting a nonzero status alone.

If a process interruption leaves the recovery journal and lock, rerun the **full controller
command above** with this additional environment assignment in its prefix, using the exact run ID
from `artifacts/SBX-047-recovery-<RUN-ID>.json`:

```sh
export SBX047_RECOVERY_RUN_ID='<RUN-ID>'
# Then rerun the complete controller command block above unchanged.
```

Retain all other exact credential/origin/confirmation variables for recovery. Recovery validates
the eligible identity and exact journal provenance before touching any sandbox.
