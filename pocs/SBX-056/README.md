# SBX-056: project-scoped PAT versus a foreign-project session child route

Status: **LOCAL-ONLY / READY FOR REVIEW. Do not run without a fresh single-live-slot coordination message.**

This packet asks one server-side authorization question: can a Vercel PAT explicitly restricted to owned Project A read one exact synthetic file from an owned Project B sandbox when the request names Project B's fresh session ID but carries no project identifier?

The root hypothesis is missing resource-project binding on the installed wire
`POST https://vercel.com/api/v2/sandboxes/sessions/:sessionId/fs/read`. Installed
`@vercel/sandbox@3.0.0` sends only the session ID, `path`, and optional `cwd` to that route; the universal client adds `teamId`, not `projectId`. In contrast, named sandbox get/delete use `projectId`, and list uses `project`.

This is the **same root family as SBX-026** (authorization of session child routes). A positive should **consolidate** or replace the two-account SBX-026 session-read variant. It is **not a second report** and must not be presented as one.

## Why this is a real authority boundary

Both projects and all staged bytes belong to the researcher, under the exact eligible HackerOne alias and team. The actor token is nevertheless restricted by Vercel to Project A. Before creating a Sandbox, the controller proves:

1. the owner PAT returns the exact eligible alias at `/v2/user`;
2. the owner PAT reads the exact team and both exact project IDs;
3. the restricted PAT reads exact Project A;
4. the same restricted PAT gets a bounded JSON `403` or privacy-preserving `404` for exact Project B; and
5. the two opaque tokens differ and the operator repeats the exact project-scope attestation.

The restricted PAT is never required to support `/v2/user`; project-scoped tokens have returned `404` there in prior controlled setup. No identity claim is inferred from that endpoint.

## Minimal matrix

All Sandbox creation, write, named readback, stop, delete, and absence confirmation uses the full owner PAT.

1. Create one nonpersistent, no-port, `deny-all` Sandbox in Project A. Require exact active and independent named provenance.
2. Write one fixed-path, mode-`0644`, synthetic public marker. The marker is nonsecret and exists solely to prove the restricted PAT is live and usable on its allowed project.
3. Read that exact file once through the session child route using the Project-A PAT. Require exact bytes and `application/octet-stream`.
4. Only after that succeeds, create one nonpersistent, no-port, `deny-all` Sandbox in Project B and require the same provenance.
5. Write one fresh, fixed-path, mode-`0600` synthetic victim marker and read it once with the owner PAT.
6. Only after every authority, provenance, public-control, owner-control, distinct-project, and distinct-session gate passes, issue exactly one Project-A-PAT read to Project B's fresh session ID and exact fixed path.
7. Stop immediately and clean both fixtures in reverse order.

There is no guest program, command execution, interactive credential, public route, DNS, tunnel, deployment, enumeration, retry, alternate path, real secret, or second cross-project operation.

## Verdict

- **Conditional High-capable candidate:** status `200`, exact octet-stream bytes of the fresh Project-B marker, all controls and chronology exact, three read requests total, and strict cleanup. This proves file disclosure across an explicit project-scoped token boundary. Because both projects share one owned account/team, describe it narrowly and let Vercel assign severity; do not call it cross-tenant.
- **Pass / clean negative:** exact bounded JSON `403` or `404` for the cross read after both positive reads, followed by strict cleanup.
- **Indeterminate:** `401`, transport error, redirect, `5xx`, other `2xx`, wrong bytes/MIME, failed authority/provenance/control/chronology/retention gate, or incomplete cleanup.

The honest pre-run probability of a positive is **8–15%**. The route shape is credible, but the server may already rejoin the session record to the PAT's project scope.

## Durable safety

`safety.ts` uses the already-reviewed global SBX-026 atomic session-command lock with lane `project-scoped-read`. That intentional dependency prevents overlap with any SBX-026 child-route experiment while leaving every SBX-056 source/test/artifact isolated.

A mode-`0600` recovery journal exists before either create attempt and is fsynced after every external-state transition. If the process dies after atomic lock acquisition but before that journal is created, cleanup-only can prove the exact same-run/lane lock and recover that pre-journal window as zero external state; no create-capable code runs before the journal commit. A create response loss cannot be called clean until the 45-second client deadline, 180-second nonpersistent timeout, and 30-second margin have elapsed, followed by two delayed exact-name absences and an exact-prefix absence. Otherwise the lock and journal remain. Finalization writes a durable cleanup-complete checkpoint, releases the atomic live lock, writes one no-clobber private artifact, then removes checkpoint and journal. If the process dies after release, recovery may acquire a fresh finalization-only lock only when the exact completed journal is present and both the canonical shared lock and its transaction sentinel are absent; incomplete journals can never use that path. A crash after the experiment artifact write is recovered into a distinct no-clobber recovery artifact. Recovery output is explicitly cleanup-only and never emits an experiment `pass`.

Artifacts retain only fixed enums, booleans, counts, timestamps, public IDs, and sanitized attempt metadata. Raw PATs and marker bytes are recursively rejected. The synthetic public control marker is also excluded from the final artifact.

## Prerequisites

- No other Vercel/Sandbox live lane is active.
- The exact current HackerOne alias is `swve@wearehackerone.com`.
- `VERCEL_TEAM_ID` is the eligible alias-owned team.
- `SBX056_CONTROL_PROJECT_ID` and `SBX056_VICTIM_PROJECT_ID` are distinct, researcher-owned projects in that same team.
- `SBX056_OWNER_TOKEN` can read the team and both projects and manage disposable Sandboxes in both.
- `SBX056_PROJECT_SCOPED_TOKEN` is fresh, short-lived, and explicitly scoped **only** to the control project. Recheck this in Vercel immediately before the run.
- Both projects are disposable test scopes and contain no third-party data.

## One bounded run

Do not export these values into shell history on a shared machine. With a coordinated slot:

```bash
export SBX056_SCOPE_CONFIRMATION="I_RECHECKED_SBX056_SCOPE_AND_OWN_BOTH_PROJECTS_AND_THE_PROJECT_SCOPED_TOKEN"
export SBX056_EXPECTED_ALIAS="swve@wearehackerone.com"
export SBX056_ALIAS_EMAIL_CONFIRMATION="swve@wearehackerone.com"
export VERCEL_TEAM_ID="team_..."
export SBX056_CONTROL_PROJECT_ID="prj_..."
export SBX056_VICTIM_PROJECT_ID="prj_..."
export SBX056_OWNER_TOKEN="..."
export SBX056_PROJECT_SCOPED_TOKEN="..."
npx tsx pocs/SBX-056/project-scoped-session-read.ts
```

Exit `0` is a clean negative, `2` is a candidate that still requires private review, and `1` is indeterminate/error. Never rerun unchanged.

If cleanup retains state, wait until the documented unknown-create horizon when applicable, keep the exact same owner/team/project configuration, omit the scoped PAT, and run exactly:

```bash
export SBX056_RECOVERY_RUN_ID="the-printed-run-uuid"
npx tsx pocs/SBX-056/project-scoped-session-read.ts
```

Do not delete the lock or recovery journal manually. If recovery remains uncertain, preserve both and stop.

## Local verification

```bash
npx vitest run test/sbx-056-verdict.test.ts test/sbx-056-safety.test.ts test/sbx-056-controller.test.ts test/sbx-056-sdk-audit.test.ts
npx tsc --noEmit --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --noUncheckedIndexedAccess --exactOptionalPropertyTypes --esModuleInterop --skipLibCheck --types node pocs/SBX-026/shared.ts pocs/SBX-056/verdict.ts pocs/SBX-056/safety.ts pocs/SBX-056/project-scoped-session-read.ts test/sbx-056-verdict.test.ts test/sbx-056-safety.test.ts test/sbx-056-controller.test.ts test/sbx-056-sdk-audit.test.ts
git diff --check -- pocs/SBX-056 test/sbx-056-verdict.test.ts test/sbx-056-safety.test.ts test/sbx-056-controller.test.ts test/sbx-056-sdk-audit.test.ts
```
