# SBX-055: stale interactive capability after persistent-session resume

Status: **LOCAL-ONLY CANDIDATE PACKET. No Vercel, public endpoint, tunnel, DNS, or deployment
call has been made.** This packet is not authorization to run. A positive remains
same-owner and clarification-gated; do not submit without program confirmation that an interactive
capability is expected to be bound to the exact session that minted it.

## Question and boundary

The installed `@vercel/sandbox@3.0.0` SDK asks the control plane for an interactive WebSocket
URL/token pair for the sandbox's current session. A persistent named sandbox can later stop,
snapshot, and resume into a distinct session. SBX-055 asks one narrow server-side lifecycle
question: **can a fresh, previously unused capability minted by session S1 authenticate after the
same named sandbox resumes as distinct session S2?**

This is distinct from closed SBX-051. SBX-051 tried to bind tokens to two different simultaneously
running sandboxes, but the service returned a generic equal base URL and the token itself selected
the session, making a URL swap scientifically meaningless. SBX-055 never swaps URL components and
never requires URLs to differ. It preserves one exact unused S1 URL/token pair in memory, stops S1,
resumes the same persistent name once, then uses that unchanged pair once before requesting any S2
capability.

The security boundary is session revocation, not sandbox-name isolation. A positive demonstrates
that a capability minted by a terminated VM session can reach data created only by its successor
session. The conservative impact is **Medium** (stale same-owner session capability). Any report is
held for clarification because public documentation describes the URL/token wire but does not
state the token's lifecycle or revocation contract.

## Fixed lifecycle matrix

The controller creates one full-UUID named sandbox with:

- `persistent: true`;
- literal `deny-all`;
- `ports: []` (no user-published service port) and only the SDK-created interactive route;
- a 240-second session timeout and five-minute snapshot expiration;
- exact `harness=vsc`, test, and run tags;
- interactive mode enabled only through the installed SDK's private `__interactive` field.

It generates two unrelated 32-byte base64url markers in controller memory. Marker values, hashes,
WebSocket tokens, query-bearing URLs, output bytes, and error strings are forbidden from evidence.
Only fixed paths and lengths are durable. Files are written mode `0600`.

The sequence is intentionally one-way:

1. Create S1 and prove exact active plus independent `resume:false` provenance.
2. Write M1 in S1 and independently read exact M1.
3. Mint one S1 owner-control pair. Against that same issued URL, missing-token and random-token
   attempts must receive exact 401/403, then a consumed S1 token must read exact M1 and no M2.
4. Re-prove the future M2 path absent after the consumed owner control, then mint a separate fresh
   S1 pair **last** and keep it unused in memory. Persist only a boolean issuance record, never the
   URL/token or a digest.
5. Stop S1. The returned snapshot must be `created`, name S1 as its source session, and have one
   canonical snapshot ID. No other interactive call is permitted before resume.
6. Resume the same name exactly once with `Sandbox.get({resume:true,__interactive:true})`. Active,
   independent `resume:false`, and exact one-item prefix-list observations must agree on distinct S2,
   the same name/tags/configuration, the source snapshot, and `deny-all`. The active response must
   expose exactly one canonical interactive route. A fresh non-resuming readback may use only the
   previously observed closed projection that preserves the exact session and interactive port
   while omitting that route; an arbitrary mismatch remains indeterminate.
7. Re-prove M1 persistence, then create/read M2 mode `0600` only in S2.
8. Use the unchanged unused S1 pair exactly once, requesting only fixed `/bin/cat <M2-path>`.
9. If it opens and returns exactly M2 (one binary marker frame, one exit frame, no M1), short-circuit
   as a candidate and never mint an S2 token. If and only if it receives exact sanitized 401/403,
   mint one S2 pair and require that pair to read exact M2 as the rejection control. DNS/TCP/TLS,
   redirects, 404/429/5xx, timeouts, protocol errors, extra frames, or other statuses are
   indeterminate, never a pass.

The request audit requires one request per fresh WebSocket, no redirects or retry, sequential
starts at no more than four requests per second, an exact purpose order, and a dynamic count that
differs only by the post-rejection S2 control.

The controller enforces two live barriers rather than relying on the final classifier. It refuses
to mint the stale S1 pair unless the exact S1 readback, mode/read controls, both 401/403 negatives,
the consumed M1 owner read, and M2 absence are already true. It refuses the stale post-resume
attempt unless the exact S2 readback, persisted M1 proof, and new mode-0600 M2 proof are already
true. A later indeterminate verdict therefore cannot conceal an attack that ran after a failed
prerequisite.

## Verdicts

- `candidate`: every identity, S1, snapshot, S2, marker, chronology, audit, retention, and cleanup
  control passes; the stale S1 capability is used once after resume and reads exact S2-only M2;
  M1/cross-marker data is absent; no S2 capability was minted. Maximum claimed impact is Medium and
  reportability remains clarification-gated.
- `pass`: the same exact matrix passes, the stale capability receives exact 401/403, and a freshly
  minted S2 capability then reads exact M2. This is a clean revocation negative for this one bounded
  lifecycle.
- `indeterminate`: any other outcome, including setup/projection/snapshot ambiguity, an unsupported
  or malformed WebSocket response, missing cleanup, or incomplete evidence.

## Cleanup and crash recovery

Cleanup runs in reverse order even after a candidate. A stop is issued at most once per durable
intent: recovery never repeats an unresolved S1 lifecycle stop or S2 cleanup stop. It first requires
a fresh exact `stopped` observation and exactly one newly attributed `created` snapshot; otherwise
the journal and lock remain in place. Likewise, `resumeAttempted:true` without a durably captured,
distinct, snapshot-attributed S2 handle blocks every stop, delete, and release action.

1. stop S2 if it is running;
2. exhaustively list snapshots and merge them with every stop-returned snapshot ID;
3. delete the exact attributed named sandbox;
4. require three delayed exact named-GET absences and an exact empty prefix list;
5. delete each canonical attributed snapshot and require
   two exact absence observations for every ID;
6. commit cleanup state, atomically remove the mode-0600 journal and ownership-bound live lock.

Snapshot cleanup uses the union of exhaustive list results and every ID returned directly by a
successful stop. A just-created cleanup snapshot that is temporarily absent from the list is still
fetched and deleted by its known ID; if that ID is not yet observable, cleanup remains unresolved
and retains the journal/lock rather than orphaning a snapshot. Before each snapshot DELETE the
controller durably records an ID-bound delete intent, then checkpoints completion immediately after
DELETE. A later exact 404 is accepted only for an observed ID with that durable intent, closing the
crash-after-DELETE window without treating a never-observed snapshot as deleted.

The fixed live lock uses an O_EXCL transaction, 256-bit lease, no-follow and inode/owner/mode
validation, dead-owner-only exact-run recovery, and ownership-bound release. The mode-0600 journal
is written before create and before every irreversible lifecycle transition. A cleanup-only run
writes a unique no-clobber artifact and can never emit experiment verdict fields. A genuinely
pre-create journal (`createAttemptedAt` absent and no lifecycle state) takes a zero-external-state
release branch and makes no Vercel request. A response-lost create or resume remains indeterminate;
absence observations do not fabricate an authoritative handle.

Acquire recovery covers every durable transaction phase. Under exact metadata and dead-owner proof,
it removes a normal-run partial acquisition, rolls a cleanup takeover back to its exact stale source
while that source exists, or completes an already-installed cleanup lease only after the source has
been removed. Deterministic `.next-*` and `.stale-*` paths are validated and cleared before the fixed
transaction is released; mismatched bytes or uncertain owner liveness retain all state.
If recovery itself dies after linking the exact stale source back to the canonical path, the next
process accepts the two names only when they are the same inode with byte-identical metadata, removes
only that verified stale alias, and continues. A different alias is never treated as recoverable.

Every dead transaction recovery is serialized by a fixed transaction-finalizer claim bound to the
exact transaction run, PID, lease, operation, and mode. Dead-finalizer takeover creates a unique
replacement and wins through a generation-keyed, non-replacing hard-link election before atomically
installing that replacement. The `.finalizer.next-*` and `.finalizer.election-*` phases are fully
discoverable: a crash before or after installation is settled from exact inode and metadata proof,
and an election path for an older generation can never name a later one. While any finalizer or
sidecar exists, new transactions fail closed. This prevents concurrent recovery from deleting a
replacement transaction after another recovery has linearized completion.

Canonical and transaction deletion first rename the exact owned inode to a deterministic
`.remove-<pid>-<lease>` generation claim. These claims are enumerated before recovery dispatch and
before any new transaction: a dead exact-run claim is completed, while a live owner, malformed
claim, multiple claims, or a different fixed-path replacement is preserved and rejected. Thus a
death immediately after either rename remains attributable and recoverable; no random removal
sidecar can become invisible. If precommit rollback removes its release transaction and then dies
before releasing the finalizer, the exact dead dangling finalizer is settled while the canonical
lock and journal remain untouched, after which cleanup takeover can proceed normally.

The recovery CLI first dispatches on the exact pending transaction operation and mode. A dead
release transaction whose journal was already removed is finalized locally and emits one unique
mode-0600, recovery-only completion artifact with zero external requests. A dead normal acquisition
with no journal is rolled back as zero external state and emits the same structurally disjoint class
of evidence. The immediately later pre-journal window is also recoverable, but only for an exact-run,
dead-owner, normal-mode canonical lock with no acquisition sidecars. Recovery first installs a
release transaction bound to the orphan's exact PID and lease; canonical removal and every crash
phase then converge through the same finalizer protocol. Live, foreign, cleanup-mode, or uncertain
locks are preserved. A cleanup-takeover
acquisition with no journal is never settled: its transaction and
lock state are retained because remote cleanup provenance has been lost.

## Offline checks

```sh
./node_modules/.bin/vitest run \
  test/sbx-055-controller.test.ts \
  test/sbx-055-protocol.test.ts \
  test/sbx-055-verdict.test.ts \
  test/sbx-055-safety.test.ts \
  test/sbx-055-live-lock.test.ts

./node_modules/.bin/tsc --noEmit
./node_modules/.bin/tsc -p tsconfig.poc.json --noEmit
```

## Manual prerequisites for a later coordinated run

These are documentation, not authorization. The run uses no public receiver or second account.

```sh
export SBX055_SCOPE_CONFIRMATION="I_AUTHORIZE_ONE_BOUNDED_SBX055_STALE_INTERACTIVE_RESUME_TEST"
export SBX055_EXPECTED_ALIAS="swve@wearehackerone.com"
export SBX055_ALIAS_EMAIL_CONFIRMATION="swve@wearehackerone.com" # only for a scoped PAT whose /v2/user is 401/403
export VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ"
export VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa"
export VERCEL_TOKEN="<eligible opaque non-JWT Vercel PAT>"

./node_modules/.bin/tsx pocs/SBX-055/stale-interactive-resume.ts
```

Recovery, after confirming no experiment process remains:

```sh
export SBX055_RECOVERY_RUN_ID="<run UUIDv4 from the retained journal>"
./node_modules/.bin/tsx pocs/SBX-055/stale-interactive-resume.ts
```

Do not place an interactive token or URL on a command line and do not save terminal output from a
positive run without the same retention review applied to the private artifact.
