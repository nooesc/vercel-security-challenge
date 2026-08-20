# SBX-051 — interactive WebSocket token/session binding

Status: **local-only packet; no live run has been made**.

## Hypothesis

The installed `@vercel/sandbox` 3.0.0 SDK requests an interactive credential from
`POST /api/v2/sandboxes/sessions/:sessionId/interactive`. The audited Sandbox CLI 4.0.0
then connects to the returned controller-hosted WebSocket URL with the returned token and sends
one `start` frame using `ws` 8.21.0. This packet asks one narrow question: can an ephemeral token
issued for one same-owner sandbox be interchanged with a fresh target URL issued for another?

The controller creates two fresh, nonpersistent, same-owner sandboxes A and B with
`__interactive: true`, literal `deny-all`, no operator-published ports, distinct UUID-tagged
names, and distinct mode-0600 random marker files. It requires exact active and independent
readback of both resources. It then runs:

1. missing-token and random-token requests to B, both of which must return exact HTTP 401 or 403
   before opening;
2. an A-issued token against A's URL, which must read only A's exact marker;
3. a B-issued token against B's URL, which must read only B's exact marker;
4. one newly minted, previously unused A token exactly once against a separately issued fresh B
   target URL. If this returns B's exact marker, the run stops the WebSocket matrix and never uses
   the B target token. If and only if it returns exact HTTP 401 or 403 before opening, the controller
   uses that exact same B target URL once with its own fresh B target token and requires B's exact
   marker and exit 0. This validates that the rejected target itself was live and correctly bound.

Every positive attempt sends one fixed `/bin/cat` command for that sandbox's known marker path.
The cross-session attempt sends exactly `/bin/cat <B-marker-path>`. There are no retries. External
request starts are serialized to 250 ms or slower (at most 4 requests per second).
Before and after the swap, owner readback also proves that each own marker is exact/mode 0600 and
that the other sandbox's marker path is absent. Sanitized timestamps record the non-overlapping
issuance/control/attack/readback/cleanup order.

The create response must expose exactly one canonical interactive route. A fresh named
`Sandbox.get({ resume:false, __interactive:true })` must independently reconstruct the same exact
session, interactive port, name, tags, deny-all policy, and marker state. The current named-GET
projection omits that private interactive route (`routes: []`), so evidence records and requires
an exact independent route count of zero instead of inventing a second route proof. The controller
aborts before issuing any interactive credential if this full two-sandbox preflight pair is not
exact.

## Evidence and impact boundary

A candidate requires the fresh A-issued attack token to open B's distinct controller URL and
return the exact B marker, with both positive controls, both negative controls, provenance
readbacks, and cleanup intact. An open socket, an error, a partial body, or any nonexact output is
indeterminate—not a finding.

A clean pass requires exact 401 or 403 for the A-token/B-target attempt followed by an exact B
marker read through the same target URL with its own B token. DNS, TCP, TLS, close-before-open,
redirect, 5xx, and other errors are indeterminate. The client disables redirects and retries,
retains no handshake headers/body, and constructs the query exactly like the audited CLI:
`${url}?token=${encodeURIComponent(token)}`.

This same-owner experiment can demonstrate a same-owner cross-sandbox read of one fixed known file
through the interactive command channel.
It does **not** by itself demonstrate cross-tenant impact, and it does not make an unconditional
authorization-bypass, RCE, High, or Critical claim. Because public material does not explicitly
state the intended same-owner token/session semantics, reportability of a positive requires program
clarification (or a separately authorized stronger isolation test). Any severity remains Vercel
triage's decision based on the maximum independently reproduced impact.

The installed SDK/CLI wire establishes that the API returns a `{url, token}` pair and the CLI
combines that exact pair. Public documentation does not explicitly promise session binding, so a
positive is framed only as observed same-owner token interchangeability, not as a contradiction of
a quoted scoping guarantee.

Raw marker values, raw interactive tokens, token digests, token-bearing query URLs, command output,
and WebSocket error text are never written to evidence. Durable evidence contains only bounded
counts, exact-match booleans, sanitized endpoint roles, provenance, and cleanup results. The Vercel
PAT remains controller-local and is never placed in either sandbox.

Before any Vercel request, the controller acquires the fixed repository lock through an exclusive
same-directory transaction sentinel. Every mode-0600 lock has a fresh 256-bit lease, owner PID,
run UUID, and mode. Cleanup-only can replace only the exact same-run lock after `kill(pid, 0)`
returns `ESRCH`; a live or uncertain owner, another run, malformed metadata, a symlink, or a stale
transaction fails closed. Takeover uses a non-replacing hard-link install while the transaction is
held. Release verifies the still-open file descriptor, device/inode, full metadata, and lease before
atomically claiming and removing the pathname, so it cannot unlink a replacement lock.

## Local verification

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
npx vitest run test/sbx-051-*.test.ts
npx tsc --noEmit
npx tsc --noEmit -p tsconfig.poc.json
npx tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --esModuleInterop --skipLibCheck pocs/SBX-051/*.ts
git diff --check -- pocs/SBX-051 test/sbx-051-*.test.ts
```

These checks are offline. The SDK audit injects a fake `fetch`; it cannot contact Vercel.

## Exactly one bounded live run

Coordinate before starting. Do not run in parallel with another live Sandbox experiment. No
tunnel, receiver, DNS setup, deployment, or second account is required.

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_sbx051_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_sbx051_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX051_EXPECTED_ALIAS='swve@wearehackerone.com' \
SBX051_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX051_SCOPE_CONFIRMATION='I_AUTHORIZE_ONE_BOUNDED_SBX051_INTERACTIVE_TOKEN_SESSION_BINDING_TEST' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-051/interactive-token-binding.ts
task_sbx051_status=$?
unset task_sbx051_vercel_token
printf 'SBX-051 exit status: %s\n' "$task_sbx051_status"
```

Read the final JSON and private artifact; do not infer the verdict from a nonzero exit status
alone. The normal path stops and deletes B then A, confirms each is absent through exact named GET
and exact prefix-list observations twice, releases and proves removal of the live lock, and only
then removes the private recovery journal. A create attempt whose session ID was not captured uses
2-second delayed named/list observations, but absence snapshots alone never resolve it: cleanup
remains indeterminate and preserves the journal and lock until an exact owned handle is observed
and its session ID is durably recorded for recovery.

## Cleanup-only recovery

If interruption leaves `artifacts/SBX-051-recovery-<RUN-ID>.json` and the fixed live lock, do not
start a new experiment. Rerun the same complete controller block once with the exact journal run ID
added. Recovery performs identity and journal-provenance checks, creates no sandbox, mints no
interactive token, opens no WebSocket, and only stops/deletes the recorded resources before two
absence checks. It writes a fresh mode-0600
`SBX-051-<RUN-ID>-recovery-<RECOVERY-ATTEMPT-ID>-private.json` with exclusive no-clobber
semantics; it never replaces the original experiment artifact:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_sbx051_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_sbx051_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX051_EXPECTED_ALIAS='swve@wearehackerone.com' \
SBX051_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX051_SCOPE_CONFIRMATION='I_AUTHORIZE_ONE_BOUNDED_SBX051_INTERACTIVE_TOKEN_SESSION_BINDING_TEST' \
SBX051_RECOVERY_RUN_ID='<EXACT-RUN-ID-FROM-JOURNAL>' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-051/interactive-token-binding.ts
task_sbx051_status=$?
unset task_sbx051_vercel_token
printf 'SBX-051 recovery exit status: %s\n' "$task_sbx051_status"
```

Never paste the PAT, an interactive token, a marker, or a token-bearing WebSocket URL into chat or
a report.
