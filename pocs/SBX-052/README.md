# SBX-052: session file-API proc-context differential

Status: **LOCAL-ONLY STABLE/FROZEN for final independent re-review. No Vercel
or public-endpoint run has been made. Do not live-run before a separate peer
READY verdict and live-slot coordination.**

This packet tests one narrow server-side question: does the session-scoped
`POST /v2/sandboxes/sessions/:sessionId/fs/read` operation expose the same
proc/mount context visible to sandbox commands when it resolves an absolute path
and an owned absolute symlink?

The installed `@vercel/sandbox@3.0.0` client sends caller-controlled `path` and
`cwd` verbatim to that endpoint. The public SDK describes absolute paths as
sandbox filesystem operations. The production endpoint implementation is not
in this repository, so only a bounded live differential can answer where the
server resolves them.

## Why the comparison is attributable

The target is the non-sensitive Linux boot UUID at
`/proc/sys/kernel/random/boot_id`; the packet never reads process environments,
credentials, tenant data, memory, or writable platform paths.

This is a kernel-level discriminator, not an application identifier: upstream
Linux stores `boot_id` in one static kernel value and documents it as unchanging
after first retrieval. A stable mismatch would prove only that the file API and
sandbox commands saw different command-visible proc/mount contexts. It would not
identify either context. A platform-supplied bind mount, helper context, or other
intended implementation detail could explain it:

- [Linux random-driver source (`sysctl_bootid`)](https://github.com/torvalds/linux/blob/master/drivers/char/random.c#L1507-L1542)
- [Linux `/proc/sys/kernel/random/boot_id` documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#random)

One fresh owned nonpersistent sandbox, with `deny-all` and no published ports,
performs one sequential SDK invocation for each step in this matrix:

Before and after the matrix, active and independent same-session readbacks must
retain the exact sandbox identity, deny-all policy, zero routes, and the actual
`Sandbox.timeout` and `currentSession().timeout` values must both be 240 seconds.

1. A fixed local-only guest script creates a random owned canary, a relative
   symlink to that canary, and an absolute symlink to the boot-ID path, all under
   one full-UUID `/tmp/sbx-052-*` directory.
2. The guest reads its boot ID directly and through the absolute symlink.
3. `Session.readFile` reads the owned file and relative symlink; both must return
   the exact random owned canary. This proves the server file route is bound to
   the intended session filesystem and follows symlinks.
4. `Session.readFile` reads the boot-ID path directly.
5. The guest re-reads its direct and linked boot ID. It must be unchanged.
6. `Session.readFile` reads the owned absolute symlink to the boot-ID path.
7. The guest reads both forms a third time. All six guest values must match.

The installed SDK controls its own underlying HTTP behavior. The evidence
therefore records `sdkInvocations: 1` and
`transportAttemptsObserved: false` for each operation; it makes no assertion
about transport-level retry counts.

The controller keeps raw values only in process memory long enough to compare
them. The private artifact retains no boot ID, boot-ID digest, random canary,
canary digest, guest stdout/stderr, or API response body.

Verdicts are deliberately strict:

- `pass`: the direct and symlinked server reads both equal the stable boot ID
  visible to sandbox commands for the entire bracketed matrix.
- `candidate-proc-context-differential`: the direct and symlinked server reads are
  canonical boot IDs and equal each other, while both differ from the guest ID
  bracketed before, between, and after them. This establishes a different
  command-visible proc/mount context only. It does not identify the context,
  establish a sandbox escape, or demonstrate access to security-sensitive data.
- `indeterminate`: any unstable guest ID, direct/symlink disagreement, failed
  owned-canary control, wrong session/readback, malformed result, retention
  failure, or cleanup uncertainty.

This packet is a research diagnostic, not a reportable vulnerability claim. Do
not describe a positive as host escape, credential access, cross-tenant access,
or any bounty severity. It needs platform clarification and a separate
security-impact proof before submission could be considered.

## Cleanup and recovery

The controller records a mode-`0600` recovery journal before create. Its one
fixed mode-`0600` live lock uses the hardened atomic PID/256-bit-lease model:
`O_NOFOLLOW`, current-user and inode/lease ownership checks, live-owner refusal,
and atomic same-run stale-owner recovery. Cross-process tests prove live-owner
rejection, one-winner recovery, mismatched-run preservation, and retry-safe
release under pathname replacement. Final release creates an exact transaction
blocker before touching the journal. The canonical lock remains until journal
unlink commits; an unlink failure leaves both journal and canonical blocker for
a fresh cleanup process. If a process dies with the transaction present, a
fresh process either rolls it back when the journal remains or completes the
authorized release when the journal is already absent. It therefore cannot
strand a fixed release `.transaction` or a journal without a recognized
release blocker.

Acquisition has a narrower guarantee: ordinary contention and stale-owner
replacement are atomic and fail closed, but a process death in the middle of
the local acquire replacement is not automatically resumed by this research
harness. An initial normal acquire occurs before any Vercel identity, list,
create, or sandbox request. Its interrupted local transaction therefore needs
manual inspection/recovery but cannot orphan newly created external state. If
a cleanup-only acquire is interrupted, the mode-`0600` journal and exact local
claims remain; do not delete them blindly. The sandbox is still nonpersistent
with the validated 240-second timeout, and a later cleanup attempt should wait
for deliberate local recovery. This packet does not claim crash-complete
acquisition.

The controller deletes the guest
directory/probe, stops/deletes the exact tagged sandbox, and proves three named
absences plus a prefix-list absence. It removes the journal only after the live
cleanup proof passes; the canonical lock is removed only after journal unlink
succeeds.

If a crash leaves the initial journal before `createAttemptedAt` exists,
recovery accepts a local-only success only when every later-state journal field
is still pristine. The real cleanup helper then records exact-name and prefix
absence with zero create, identity-verification, list/get, stop, delete, or guest
cleanup request attempts. It persists completion locally and safely removes the
exact journal/lock. Any contradictory later-state field keeps recovery
incomplete and preserves the state. A pristine pre-create journal whose local
cleanup proof was already persisted as complete is replayable after a crash
before journal unlink; it does not become a permanent cleanup blocker.

If sandbox creation times out without returning a session and the exact tagged
resource is not yet visible, the run remains indeterminate and intentionally
retains its lock/journal. It never calls an arbitrary four-second observation
window "clean." After the documented create deadline, 240-second nonpersistent
timeout, and a 30-second margin have elapsed, recovery can prove absence or
delete the exact tagged resource. Every recovery attempt gets a fresh UUIDv4
artifact path, so a failed attempt and a later successful attempt both survive
without overwriting each other or the experiment evidence. The attempt envelope
starts before lock acquisition and journal parsing: a live/missing lock or a
missing/malformed journal still produces its own mode-`0600`, token-redacted,
no-clobber recovery-failure artifact, while any reclaimed lock and any existing
journal are left in place for a later cleanup-only process. Retained-state file
descriptors are explicitly closed without unlinking that state.

Cleanup-only output is deliberately not an experiment assessment. Its top-level
shape is `recoveryOnly: true`, `mode: "cleanup-only"`, and an `outcome` of either
`cleanup-complete` or `cleanup-incomplete`; it never emits a vulnerability
`verdict`, `candidate`, or `controlsPassed` result without the full experiment
matrix. `recoveryPath` distinguishes pristine pre-create cleanup, ordinary
post-create cleanup, and local completion of an interrupted finalization.

## Local verification

These commands are local-only:

```sh
npx vitest run \
  test/sbx-052-live-lock.test.ts \
  test/sbx-052-guest.test.ts \
  test/sbx-052-controller.test.ts \
  test/sbx-052-safety.test.ts \
  test/sbx-052-sdk-audit.test.ts \
  test/sbx-052-verdict.test.ts

npx tsc --noEmit --strict --exactOptionalPropertyTypes --noUncheckedIndexedAccess \
  --target ES2022 --module NodeNext \
  --moduleResolution NodeNext --esModuleInterop --skipLibCheck --types node,vitest/globals \
  pocs/SBX-052/live-lock.ts pocs/SBX-052/verdict.ts pocs/SBX-052/safety.ts \
  pocs/SBX-052/fs-namespace.ts test/sbx-052-live-lock.test.ts \
  test/sbx-052-guest.test.ts test/sbx-052-controller.test.ts \
  test/sbx-052-safety.test.ts test/sbx-052-sdk-audit.test.ts test/sbx-052-verdict.test.ts

node --check guest/sbx-052-fs-namespace-probe.mjs
```

## Future bounded live command

Do not run until this packet is frozen, independently reviewed, and the shared
Vercel live slot is explicitly coordinated.

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

task_vercel_token=$(node --input-type=module -e \
  'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')

VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ" \
VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa" \
SBX052_ALIAS_EMAIL_CONFIRMATION="swve@wearehackerone.com" \
SBX052_SCOPE_CONFIRMATION="I_OWN_THIS_ALIAS_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_FS_NAMESPACE_TEST" \
npx tsx pocs/SBX-052/fs-namespace.ts

task_sbx052_status=$?
unset task_vercel_token
printf 'SBX-052 exit status: %s\n' "$task_sbx052_status"
```

A candidate experiment intentionally exits nonzero. Use its structured
assessment and cleanup fields, not process status alone. Cleanup-only runs have
no experiment assessment; use only their `mode` and `outcome` fields.

For a retained unknown-create journal, wait until the settlement horizon shown
above, then run the same command with the exact retained run ID:

```sh
task_vercel_token=$(node --input-type=module -e \
  'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')

SBX052_RECOVERY_RUN_ID="<RETAINED_UUID>" \
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ" \
VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa" \
SBX052_ALIAS_EMAIL_CONFIRMATION="swve@wearehackerone.com" \
SBX052_SCOPE_CONFIRMATION="I_OWN_THIS_ALIAS_SCOPE_AND_AUTHORIZE_ONE_BOUNDED_FS_NAMESPACE_TEST" \
npx tsx pocs/SBX-052/fs-namespace.ts

task_sbx052_recovery_status=$?
unset task_vercel_token
printf 'SBX-052 recovery exit status: %s\n' "$task_sbx052_recovery_status"
```
