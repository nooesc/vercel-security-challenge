# SBX-026 direct session/command authorization packet

Status: **locally implemented and disabled; no Vercel request was executed while building or testing it.**

This packet tests one narrowly selected server-side authorization seam in `@vercel/sandbox@3.0.0`. It does not scan, enumerate, fuzz, open an interactive session, stop or kill a foreign process, or mutate a foreign filesystem.

## Lanes

Each invocation accepts exactly one lane. There is intentionally no `--all` mode.

| Lane | Both-account owner controls | One cross-account action | Success proof |
| --- | --- | --- | --- |
| `session-read` | Each owner reads its own distinct synthetic marker from its own distinct exact path | Attacker token reads the victim's one known path once | Exact victim-marker bytes |
| `command-run` | Each owner runs direct `printf` with its own distinct synthetic marker | Attacker token runs the same harmless, nonpersistent `printf` with the victim marker in the victim session once | Victim session, coherent command envelopes, exact victim-marker stdout, empty stderr, exit `0` |

The attacker owner control runs first. The victim owner control is the final Vercel request immediately before the foreign action. Both controls must succeed, the account aliases, Vercel user IDs, bounded session IDs, markers, and known paths must be distinct, and the one-shot transport audit must show exactly one transport call for each raw operation. If any gate fails, the cross-account request is not sent.

The command lane invokes `printf` directly. It does not invoke a shell and does not write a file. The read lane performs at most one cross-account known-path read. Owner fixture setup and owner controls are counted separately.

## Required gates

Keep secrets in `.env.local`; never commit them. The values below are mandatory for a normal test. Leave `SBX026_RUN_ID` unset for a normal test:

```dotenv
SBX026_SCOPE_CONFIRMATION=I_OWN_BOTH_DISTINCT_PROGRAM_ELIGIBLE_VERCEL_ACCOUNTS
SBX026_OWNERSHIP_CONFIRMATION=I_PERSONALLY_OWN_AND_VERIFIED_BOTH_DISTINCT_VERCEL_ACCOUNTS
SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION=I_VERIFIED_NEITHER_ACCOUNT_IS_A_MEMBER_OF_THE_OTHER_ACCOUNT_TEAM
SBX026_SESSION_COMMAND_CONFIRMATION=I_CONFIRM_EXACTLY_ONE_BOUNDED_CROSS_ACCOUNT_SESSION_OR_COMMAND_REQUEST

SBX026_ATTACKER_TOKEN=...
SBX026_ATTACKER_TEAM_ID=team_...
SBX026_ATTACKER_PROJECT_ID=prj_...
SBX026_ATTACKER_EMAIL=first-alias@wearehackerone.com

SBX026_VICTIM_TOKEN=...
SBX026_VICTIM_TEAM_ID=team_...
SBX026_VICTIM_PROJECT_ID=prj_...
SBX026_VICTIM_EMAIL=second-alias@wearehackerone.com
```

Both tokens must resolve through Vercel's identity endpoint to their exact configured HackerOne alias and to different Vercel user IDs. Tokens, team IDs, project IDs, aliases, and user IDs must all represent the intended separate account scopes. Neither account may be a member of the other account's team.

Do not run until the current HackerOne/Vercel policy has been manually re-read and these exact two accounts and operations remain eligible.

## One-lane commands

These are operator commands, not commands executed during local verification:

```bash
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/session-command-cross-tenant.ts --lane=session-read
```

or, in a separate invocation:

```bash
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/session-command-cross-tenant.ts --lane=command-run
```

`--all`, multiple lane flags, unknown lanes, and `nested-command-log` are rejected. Interactive, command-log retrieval, stop, kill, and cross-account mutations remain deferred.

## Request and evidence controls

- Before the first Vercel request, every lane acquires the canonical shared SBX-026 safety lock `artifacts/SBX-026-live-active.lock` with mode `0600`. Its path is derived from the shared module URL, so changing the current directory or `HARNESS_ARTIFACTS_DIR` cannot create a second lock domain. Shared lock metadata records `testId: SBX-026`, `scope: session-command`, the exact selected lane, and the full run UUID. A normal run refuses every existing lock, including a lock belonging to another SBX-026 scope.
- The lock is held across identity verification, setup, controls, the sole foreign request, owner cleanup, absence confirmation, and release-neutral evidence writing. The durable artifact records only an `indeterminate` / `pending-live-lock-release` state while the lock exists. It is released only after both identities were verified, exact owner cleanup and absence checks passed, and the neutral evidence was written. Otherwise it remains for explicit recovery.
- A single global gate spaces every Vercel identity and Sandbox control-plane transport start by at least 250 ms (at most 4 starts/second).
- Because the one repo-wide lock permits only one live SBX-026 controller and the gate permits at most 4 starts/second inside it, parallel invocations cannot exceed the program-wide limit of 5 requests/second or issue concurrent cross probes.
- Setup and owner cleanup may use the SDK. Every raw owner control and the foreign action uses `oneShotSandboxRequest` directly, outside the SDK retry wrapper.
- The foreign request counter must equal one. In `session-read`, the cross-account known-path read counter must also equal one; in `command-run`, it must equal zero.
- The two owner fixtures use distinct markers and distinct paths. The sole foreign request always targets the victim session and validates only the victim marker.
- Response bodies are bounded, interpreted in memory, zeroed where buffers permit, and never stored. Evidence contains only status, bounded failure code, lengths, booleans, audit metadata, and the marker SHA-256. It contains no token, raw marker, raw request body, or raw response body.
- A `candidate` requires exact synthetic-marker confirmation. A conclusive `403`, `404`, or supported exact `422` rejection is a boundary `pass`. `401`, `410`, throttling, server errors, transport failures, malformed responses, contradictory success/rejection signals, or failed controls remain `indeterminate`.
- Once the single foreign response confirms the marker, no additional test operation is issued. Only owner-token cleanup and independent absence checks follow.
- No effective `pass`, `candidate`, or cleanup-complete outcome is persisted or printed before exact shared-lock release. After the neutral artifact is durable, the controller awaits `release()`, constructs the final assessment only on success, and then emits the final result to stdout. A release failure leaves the neutral artifact and produces no success/result stdout.

Private evidence is written with mode `0600` under `artifacts/` (or `HARNESS_ARTIFACTS_DIR`) using an exclusive filename. The file deliberately remains release-neutral even after a successful run; the post-release stdout record carries the effective final verdict and references that artifact. The evidence-directory override never changes the fixed safety-lock path.

## Cleanup and orphan recovery

Each account owns exactly one nonpersistent, deny-all fixture. Names and all ownership tags contain the full run UUID. Cleanup uses only the resource owner's token and requires exact name, tags, persistence, network policy, and (for a current random run) creation-window provenance before stop/delete. Absence requires two owner-token `Sandbox.get({ resume: false })` results of `404`, separated by a bounded delay of at least one second; `410` is not accepted as absence.

The random run UUID is printed before fixture creation. If the process is interrupted, rerun the same lane with that exact canonical UUID:

```dotenv
SBX026_RUN_ID=00000000-0000-4000-8000-000000000000
```

Supplying `SBX026_RUN_ID` always selects **cleanup-only mode**. The harness performs the two identity checks, checks both exact UUID-derived names, deletes only fixtures whose full tags and immutable safety properties match, obtains delayed double-`404` absence confirmation, writes a pending cleanup-only artifact, and exits. It never creates a fixture, runs an owner control, or dispatches a foreign request. `cleanup-complete` is constructed and printed only after successful shared-lock release. A completed UUID therefore cannot replay a test; start any later test with `SBX026_RUN_ID` unset so a new random UUID is generated. A provenance mismatch is left untouched and cleanup fails closed.

Cleanup-only mode requires an existing stale shared lock and may reclaim it only when its `scope: session-command`, lane, and run UUID all match exactly and the recorded owner PID is conclusively dead. It never removes a live, uncertain, mismatched, or another scope's lock. After reclamation, the lock is released only once both identities are verified, both exact deterministic fixtures have owner-token cleanup plus delayed absence confirmation, and cleanup-only evidence has been written. If any of those checks fails, the lock remains in place for explicit recovery.

## Local verification only

The local unit tests do not import-time execute the harness and do not contact Vercel:

```bash
npx vitest run test/sbx-026-session-command.test.ts test/sbx-026-shared.test.ts
```

They cover lane mutual exclusion, exact shared-lock scope/lane/mode binding, release-neutral evidence, injected release failure with no final stdout, post-release-only verdict construction, pending cleanup-only outcomes, distinct fixture markers/paths/session IDs, cleanup-only replay prevention, delayed double-absence confirmation, exact actor/target ordering, both-owner control requirements, verdict exclusivity, fixed request/read limits, retention/rate/cleanup failures, and exact command-stream confirmation. The shared tests cover the fixed cwd-independent lock path, mode-`0600` exclusivity, live-owner refusal, atomic stale-lock reclamation, other-scope preservation, and exact-lease release.

This harness demonstrates only control-plane behavior. Client-side SDK parsing/retry quirks without a server-side authorization impact are not findings and should not be reported.
