# SBX-026 cross-account snapshot restore authorization

This is a disabled-by-default, no-enumeration controller for one root-cause hypothesis: `POST /v3/sandboxes` may accept a snapshot owned by a different Vercel account when the destination sandbox belongs to the caller.

Do not run it until two distinct Vercel accounts are personally verified as eligible for the challenge. The repository policy note currently documents only one verified alias account, so the packet is local-only until the second account, team, project, and alias are recorded and neither account belongs to the other account's team.

## Proof and safety sequence

1. Both explicit tokens are checked through Vercel's read-only `/v2/user` endpoint. The returned emails must exactly match two distinct `@wearehackerone.com` aliases, and the returned Vercel user IDs must be distinct.
2. The attacker account creates its own fresh `deny-all` source sandbox, writes one synthetic canary, snapshots it, restores it into an attacker-owned clone, and performs one exact-path read. The clone, snapshot, and source are deleted and independently absent before any cross-account request. This proves the exact restore capability under attacker credentials. Attacker/victim marker bytes, paths, snapshot IDs, and control session IDs must all be distinct.
3. The victim account repeats the source/snapshot/restore control with a different synthetic canary. The victim control clone is deleted and independently absent.
4. A victim-authenticated `Snapshot.get()` must return the exact requested snapshot ID and show the exact source session, `created` status, run-window timestamp, and at least five minutes of remaining lifetime immediately before the authorization test.
5. The attacker makes exactly one raw, non-retrying restore request for that victim snapshot. The shared transport spaces every Vercel request by at least 250 ms, including SDK retries used only for owned setup and cleanup.
6. If and only if the restore succeeds with the exact destination name, tags, source snapshot, `deny-all` policy, and session attribution, an independent attacker-authenticated destination readback must agree. The controller then makes exactly one raw, non-retrying read of the known synthetic victim path. It never lists files, tries another path, runs a command, or follows a redirect.
7. A second victim-authenticated `Snapshot.get()` must prove that the source snapshot remained valid after the test. `401`, generic `410`, transport errors, expiry, contradictory state, or failed controls are never counted as a clean authorization rejection. A retry, count above one, or logical-call/transport-count mismatch is a harness safety `error`.
8. `finally` cleanup uses full-entropy deterministic names and exact run tags. Ambiguous sandbox creates are recovered only by exact owned name, tags, expected source snapshot, session when known, and creation window. A timed-out sandbox or snapshot create with no returned handle/ID requires two clean collection-absence observations separated by a bounded delay; one immediate `404`, one empty list, or a vacuously empty direct-ID loop is insufficient. Restore-derived sandboxes are confirmed absent before snapshots. Every known or safely discovered snapshot ID is then checked directly with owner credentials and must be `deleted` or exact `404` before its source sandbox is removed. Any mismatch is left untouched and reported for manual inspection.

A candidate requires one transport-level restore attempt, one transport-level known-path read, exact canary equality, exact source attribution, independent destination readback, both same-account controls, a valid pre/post victim snapshot, and complete cleanup. A clean `pass` requires one conclusive `403`, privacy-preserving `404`, or documented authorization-style `422`, no destination clone, no cross-account read, the same controls, and complete cleanup.

The recovery manifest is atomically persisted and directory-synced as a bounded mode-`0600` file before every create attempt, including before the single cross-account restore. It contains only the two exact owned scopes, full-UUID deterministic names/tags, verified user-ID hashes, and bounded cleanup identifiers. An exclusive mode-`0600` lock at the fixed repository path `artifacts/SBX-026-live-active.lock` is shared with the other SBX-026 packets; its parent directory must be current-user-owned mode `0700`. Its location does not change with the current working directory or `HARNESS_ARTIFACTS_DIR`. A normal run refuses every existing lock. Cleanup-only requires an existing exact snapshot-scope/run lock whose recorded local owner process is definitively dead. The shared lock serializes stale reclamation with atomic same-directory claims, verifies the retained inode/lease before release, and restores or preserves any unexpected claim rather than deleting another packet's lock.

An unset `SBX026_RUN_ID` creates a fresh test UUID. Supplying one canonical UUID always selects cleanup-only mode: it can never recreate controls, issue another cross-account restore, read a path, or run a command. Cleanup-only verifies both exact alias emails and distinct Vercel user IDs before reading or hydrating the corresponding bounded mode-`0600` manifest. Identity failure, a foreign/malformed manifest, or a mismatched owner/resource binding results in zero Sandbox cleanup requests and leaves recovery state for inspection. Normal mode likewise cannot remove its recovery descriptor unless both exact identities were verified as distinct. If the very first journal write fails before any Vercel request, the controller durably records an error and either removes only the invalid exact journal files before releasing the zero-state lock, or restores a valid zero-attempt cleanup descriptor and retains the lock. A valid manifest authorizes only owner-scoped cleanup of its exact resources in dependency order: cross/restore destinations, snapshots, then sources. The recovery file and the exact owned lock are removed only after cleanup/absence proof and private evidence staging succeed.

Normal-run evidence is fully staged, atomically published at its exact final path, and directory-synced while the canonical lock is still held. A would-be `pass` or `candidate` is stored there only as `pending-lock-release`; the controller emits the final verdict to stdout after exact shared-lock release succeeds. Rename, directory-sync, or release failure therefore cannot leave a persisted `pass`/`candidate`; before retaining the lock the controller restores the exact recovery descriptor when it had already been removed, and attempts to replace the pending record with `error`. Private evidence never contains either token, raw canary, or response body; it stores canary digests/lengths, bounded status/code fields, sanitized resource attribution, exact counters, the request audit, and cleanup state.

## Required environment

Do not place real values in shell history. Load them from a private ignored environment file or an already-open shell.

```sh
export SBX026_SCOPE_CONFIRMATION=I_OWN_BOTH_DISTINCT_PROGRAM_ELIGIBLE_VERCEL_ACCOUNTS
export SBX026_OWNERSHIP_CONFIRMATION=I_PERSONALLY_OWN_AND_VERIFIED_BOTH_DISTINCT_VERCEL_ACCOUNTS
export SBX026_NO_CROSS_MEMBERSHIP_CONFIRMATION=I_VERIFIED_NEITHER_ACCOUNT_IS_A_MEMBER_OF_THE_OTHER_ACCOUNT_TEAM

export SBX026_ATTACKER_TOKEN='<attacker account token>'
export SBX026_ATTACKER_TEAM_ID='team_...'
export SBX026_ATTACKER_PROJECT_ID='prj_...'
export SBX026_ATTACKER_EMAIL='<attacker-alias>@wearehackerone.com'

export SBX026_VICTIM_TOKEN='<victim account token>'
export SBX026_VICTIM_TEAM_ID='team_...'
export SBX026_VICTIM_PROJECT_ID='prj_...'
export SBX026_VICTIM_EMAIL='<victim-alias>@wearehackerone.com'

DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/snapshot-cross-tenant.ts
```

For a normal test, leave `SBX026_RUN_ID` unset. If the controller reports an unfinished manifest named `artifacts/SBX-026-snapshot-recovery-<uuid>.json`, do not start another test. Run exact cleanup-only recovery with that UUID:

```sh
SBX026_RUN_ID='<uuid-from-the-exact-snapshot-manifest>' \
  DOTENV_CONFIG_PATH=.env.local npx tsx pocs/SBX-026/snapshot-cross-tenant.ts
```

That command cannot replay the authorization test. After reclaiming only the exact stale snapshot/run lock, it performs the two identity checks, validates the exact manifest, and then performs owner-only cleanup. It will not reclaim a foreign/different-run lock or a lock whose recorded process is live or uncertain. If an unexpected reclaim/release claim or an unreclaimable lock remains after a crashed cleanup process, stop for manual inspection; never delete it merely to make a new live run proceed.

The controller does not use cached or inferred credentials. The three confirmation values are factual attestations, not substitutes for manually checking the current HackerOne policy, testing window, reward-pool status, account ownership, team membership, and private-repository state immediately before any live run.

## Local validation

```sh
npx vitest run test/sbx-026-shared.test.ts test/sbx-026-snapshot-cross-tenant.test.ts
npx tsc --noEmit -p tsconfig.poc.json
```

No live or external request was performed while hardening this packet.
