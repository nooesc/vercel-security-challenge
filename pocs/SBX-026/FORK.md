# SBX-026 server-side fork authorization packet

This packet tests one control-plane question: can Account A's bearer token and team scope fork a named sandbox whose exact project ID and source name belong to Account B?

It is local-only until every prerequisite below is satisfied. The implementation does not infer credentials, enumerate names or IDs, use another person's resources, retain response bodies, or retry the cross-account request. A supplied or reused run UUID is always cleanup-only and can never issue another cross-account request.

## Safety and policy gate

Both Vercel identities must be distinct accounts personally owned by the researcher. Both expected emails must be canonical `@wearehackerone.com` aliases, both token identities are checked through `/v2/user`, the returned Vercel user IDs must differ, the teams and projects must differ, and the operator must have verified that neither user is a member of the other account's team.

The controller refuses to start without all three exact confirmations:

```sh
export SBX026_SCOPE_CONFIRMATION=I_OWN_BOTH_DISTINCT_PROGRAM_ELIGIBLE_VERCEL_ACCOUNTS
export SBX026_OWNERSHIP_CONFIRMATION=I_PERSONALLY_OWN_AND_VERIFIED_BOTH_DISTINCT_VERCEL_ACCOUNTS
export SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION=I_VERIFIED_NEITHER_ACCOUNT_IS_A_MEMBER_OF_THE_OTHER_ACCOUNT_TEAM
```

Do not run with a normal-email second account unless Vercel has explicitly confirmed that it satisfies the challenge's alias requirement.

## Exact sequence

1. Verify both bearer tokens resolve to their exact expected HackerOne aliases and to different Vercel user IDs.
2. In the attacker account, create a UUID-named source containing only a random 32-byte file, snapshot it, fork it with the same owner credentials, and prove the fork contains the exact synthetic bytes.
3. Delete the attacker owner-control fork and independently prove the UUID name and any snapshots are absent.
4. Repeat the same source, snapshot, fork, file, deletion, and absence controls in the victim account.
5. With victim owner credentials, retrieve the victim source using `resume: false` and prove its exact name, UUID tags, snapshot, stopped state, persistence, and `deny-all` policy.
6. Make one raw, no-retry request:

   ```http
   POST /api/v2/sandboxes/{victimSourceName}/fork
       ?teamId={attackerTeamId}
       &projectId={victimProjectId}
   Authorization: Bearer {attackerToken}
   ```

   The fork body supplies a new full-UUID name, `persistent: false`, `deny-all`, an empty environment override, and exact run tags.
   The controller captures the exact global request-gate sequence assigned to this attacker-scoped send. Request auditing binds the foreign attempt to that sequence, because the earlier victim owner-control fork legitimately uses the same HTTP method and source pathname.
7. The next Vercel request is an independent victim-owner `resume: false` readback of the source. This prevents a transient, deleted, or mismatched source from being mistaken for an authorization result.
8. If the fork was rejected, do not perform a file read. Only a scoped 403/404 or a recognized authorization/not-found 422 is a conclusive clean rejection; 401, 410, rate limits, transport failures, and malformed responses are indeterminate.
9. If the fork was accepted and returned the exact target name, matching current/session IDs, exact full tags, the exact deny-all/nonpersistent configuration, a creation time inside the run window, and the victim source's exact current snapshot ID, make at most one raw attacker-token read of the one exact victim canary path. Never list a directory, try another path, run a command, inspect environment variables, or continue after the read.
10. Cleanup is identity- and dependency-gated. If either exact `/v2/user` alias check or the distinct-user check fails, cleanup-only makes no Sandbox API call at all and leaves the journal/lock for correction. Otherwise it operates only on plans with an attempted create or a known owned identifier: delete and confirm all derived forks first; direct-GET, delete, and independently direct-GET every known snapshot ID under its owner credentials; then, only after all known snapshots are directly confirmed missing/deleted, delete source sandboxes. A collection/list 404 never proves a known snapshot ID absent. If a create or fork was attempted but no trusted live handle returned, one immediate sandbox absence is insufficient: the controller waits one second and performs a second owner-scoped exact-name check, or fails cleanup.

The source/destination model is intentionally not weakened: the fork API has one `projectId`, used to identify the source project, while `teamId` supplies request scope. The cross request therefore uses the attacker token/team and the victim project/source exactly. The public fork response schema does not expose a project ID, so attribution uses the exact victim snapshot ID and cleanup treats placement as ambiguous: it checks the one exact target name under both owned accounts and never deletes a tag mismatch.

The attacker and victim source names, source-session IDs, snapshot IDs, and owner-control fork session IDs must all be distinct before the cross request. The two random canaries and paths must also differ. Only the exact victim canary at the exact victim path can produce a candidate verdict.

## Crash and reuse recovery

Before its first Vercel request, a fresh run acquires the shared repository-global `artifacts/SBX-026-live-active.lock` through the SBX-026 lock helper and atomically writes a private `artifacts/SBX-026-fork-recovery-<uuid>.json` journal. The helper derives the lock path from `shared.ts`'s `import.meta.url`, not the process working directory or an environment setting, so every SBX-026 packet shares one lock even when launched from different directories. The shared metadata records `testId: "SBX-026"`, `scope: "fork"`, the full run UUID, mode, owner PID, creation time, and an unguessable lease. The lease is never copied into evidence. A normal run refuses every existing shared lock. Cleanup-only requires an existing stale lock with the exact `scope: "fork"` and run UUID, and can never create a replacement for a missing lock or reclaim another scope, lane, or run.

The journal contains only owned account scopes, deterministic names/tags, and bounded session/snapshot IDs—never tokens or canary values. It is updated before the cross request is sent. Any unfinished fork journal blocks a new fresh run. The shared lock remains held across every identity/Sandbox request, dependency-ordered cleanup, and the durable evidence write. That durable artifact is deliberately release-neutral: its assessment is indeterminate/pending, it does not contain an effective `cleanupPassed`, pass, or candidate result, and it records that the final assessment was not retained. Only after the journal is removed, exact owned-resource cleanup succeeds, the pending artifact is durable, and live-lock release succeeds does the controller return and print the final assessment. A release failure therefore leaves only neutral evidence and no emitted pass/candidate. Any identity failure, unresolved resource, journal failure, evidence failure, or interrupted finalization leaves the lock in place so a new normal run cannot race recovery.

After a crash, copy the complete UUID from the recovery filename and rerun with:

```sh
export SBX026_FORK_RUN_ID='<complete recovery UUID>'
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/fork-cross-tenant.ts
```

Any supplied `SBX026_FORK_RUN_ID`, including one from an already finished run, selects cleanup-only mode. Cleanup-only first must reclaim the existing stale exact fork/run shared lock; a missing lock fails closed before any Vercel request. That mode then verifies both exact identities before any Sandbox request, performs only dependency-ordered owner-scoped cleanup and direct absence checks, and cannot create a source, create a control fork, send the cross request, or read a file. If either identity fails, it issues zero Sandbox requests and retains the recovery lock. The journal is removed and the exact shared lock is released only after sandbox and snapshot absence succeeds and evidence is durably written.

## Required credentials

```sh
export SBX026_ATTACKER_TOKEN='<attacker access token>'
export SBX026_ATTACKER_TEAM_ID='team_...'
export SBX026_ATTACKER_PROJECT_ID='prj_...'
export SBX026_ATTACKER_EMAIL='attacker-alias@wearehackerone.com'

export SBX026_VICTIM_TOKEN='<victim access token>'
export SBX026_VICTIM_TEAM_ID='team_...'
export SBX026_VICTIM_PROJECT_ID='prj_...'
export SBX026_VICTIM_EMAIL='different-victim-alias@wearehackerone.com'
```

Do not place real secrets in either sandbox. The packet sets `env: {}` on sources and forks and uses only random file canaries.

## Local validation

These commands do not call Vercel:

```sh
npx vitest run test/sbx-026-fork-cross-tenant.test.ts test/sbx-026-shared.test.ts
npx tsc --noEmit -p tsconfig.poc.json
```

The fresh live command must not be run until the two-account alias and no-cross-membership prerequisites have been verified. Ensure `SBX026_FORK_RUN_ID` is unset for a new run:

```sh
unset SBX026_FORK_RUN_ID
DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/fork-cross-tenant.ts
```

The private pending artifact is written under `artifacts/`. It contains owned resource IDs, canary hashes and lengths, bounded status/code fields, and the global request/cleanup audit, but no final pass/candidate verdict. The final verdict appears only in the returned/stdout record after successful lock release. Neither record contains bearer tokens, raw canaries, raw fork responses, or raw file responses.

No live or external request was made while this packet was implemented.
