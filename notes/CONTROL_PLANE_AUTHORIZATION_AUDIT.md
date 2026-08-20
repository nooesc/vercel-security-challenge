# Sandbox control-plane authorization audit

Date: 2026-08-18
Status: local harness implementation and independent review complete; live cross-account execution is blocked by account-eligibility prerequisites. No live cross-account request was performed.

## Scope and source material

This audit covers server-side authorization hypotheses for the REST API used by the installed `@vercel/sandbox@3.0.0` SDK and cached `sandbox@4.0.0` CLI. The installed SDK corresponds to upstream tag commit `bf2bc660`. The CLI delegates sandbox operations to the same SDK. Client-only defects are excluded by the HackerOne policy.

Primary local sources:

- `node_modules/@vercel/sandbox/dist/api-client/api-client.js`
- `node_modules/@vercel/sandbox/dist/sandbox.js`
- `node_modules/@vercel/sandbox/dist/session.js`
- `node_modules/@vercel/sandbox/dist/snapshot.js`
- cached `sandbox@4.0.0` CLI bundle and its bundled `@vercel/sandbox@3.0.0`

Current upstream corroboration:

- [Vercel Sandbox repository](https://github.com/vercel/sandbox)
- [Vercel Sandbox SDK/CLI skill reference](https://github.com/vercel/sandbox/blob/main/skills/sandbox/SKILL.md)
- [Vercel SDK Sandbox endpoint inventory](https://github.com/vercel/sdk/tree/main/src/funcs)
- [Vercel Sandbox changelog](https://github.com/vercel/sandbox/blob/main/packages/vercel-sandbox/CHANGELOG.md)

The policy explicitly includes broken authorization or IDOR in this control plane, but requires two researcher-owned accounts and a live minimal PoC. Everything below remains a hypothesis until reproduced that way.

## Authorization-relevant route shape

The critical invariant is server-side resource ownership. An opaque ID is not an authorization control.

| Resource family | Installed client routes | Caller-selected scope sent by client | Server binding that must hold |
| --- | --- | --- | --- |
| Named sandbox | `GET/PATCH/DELETE /v2/sandboxes/:name`, `POST /v2/sandboxes/:name/fork` | `teamId` plus `projectId` | Token may act for team; project belongs to team; name belongs to project |
| Session | `/v2/sandboxes/sessions/:sessionId` and child `cmd`, `interactive`, `fs`, `stop`, `network-policy`, `extend-timeout`, `snapshot` routes | `teamId`; no project on the resource route | Session and every child resource belong to the authenticated team/project |
| Snapshot | `GET/DELETE /v2/sandboxes/snapshots/:snapshotId`, `/snapshots/tree`, and snapshot source on create | `teamId`; list/tree also accept a project filter | Snapshot belongs to the caller's authorized project and every restore/rollback target is authorized |
| Collections | `/v2/sandboxes`, `/sessions`, `/snapshots` | `teamId` and caller-selected project/name/cursor filters | Filters and pagination cursors cannot switch or retain another authorization scope |

## Ranked shortlist

### 1. Snapshot reference authorization on restore or rollback

**Routes:** `POST /v3/sandboxes` with `source: { type: "snapshot", snapshotId }`; `PATCH /v2/sandboxes/:name` with `currentSnapshotId`.

**Why first:** a destination sandbox is unambiguously attacker-owned while its source is a separately addressed snapshot. This is a classic object-reference authorization seam, and snapshot rollback/source support is newer than the basic session surface. The current public REST schema explicitly says `currentSnapshotId` must belong to the same project, confirming the intended invariant.

**Minimal impact proof:** a disposable create/readback/delete control first proves the attacker token/team/project tuple is valid without victim data. The victim then writes one random synthetic file and snapshots; a same-account restore proves the snapshot; attacker credentials attempt one restore and, only if accepted, read that known path once. Exact canary disclosure is Critical cross-tenant read under the challenge table.

**Packet:** `pocs/SBX-026/snapshot-cross-tenant.ts`. It is credential-gated, performs no enumeration, journals every create/cross attempt before dispatch, and was not run during this audit.

### 2. Session-ID authorization across direct file, command, and interactive routes

**Routes:** `POST /sessions/:sessionId/fs/read`, `/fs/write`, `/cmd`, `/interactive`, plus stop/policy/timeout operations.

**Why high value:** these routes are globally addressed by `sessionId` and carry team context but no project ID. A missing resource-owner check on any handler gives direct file read/write, command execution, or an interactive token. The strongest safe first test would be one exact synthetic-file read using a victim session ID obtained through victim credentials; no guessing or listing.

**Potential impact:** Critical cross-tenant read/modification/RCE. Do not test multiple child routes after one succeeds; one synthetic-file confirmation is enough.

**Packet:** `pocs/SBX-026/session-command-cross-tenant.ts`. Each invocation selects exactly one lane: one known-path read or one harmless direct `printf` command. Both accounts must first pass the exact owner-side operation on distinct fixtures. There is no `--all` mode.

### 3. Server-side fork source authorization and encrypted environment copy

**Route:** `POST /v2/sandboxes/:name/fork`.

**Why plausible:** SDK `2.9.0` moved fork from client composition to a server endpoint and documents that it copies source configuration, filesystem state, image, and environment variables server-side. The server must authorize the source independently and bind the path name to the caller-selected team/project before copying anything.

**Potential impact:** Critical cross-tenant file/environment read or modification. Use only two owned accounts and a single synthetic file/env marker; avoid testing real secrets.

**Packet:** `pocs/SBX-026/fork-cross-tenant.ts`. It uses one raw, non-retrying cross-account fork request and at most one victim-only known-path read after both owner-fork controls and immediate source-validity checks.

## Implemented safety invariants

The snapshot, fork, session-read, and command-run packets share these fail-closed rules:

- two explicit tokens, team IDs, project IDs, and distinct `@wearehackerone.com` aliases;
- `/v2/user` responses must exactly match both configured aliases and distinct Vercel user IDs;
- the researcher must attest that neither account belongs to the other account's team;
- attacker and victim controls use distinct synthetic markers, paths, sessions, snapshots, and full-UUID names/tags;
- both accounts must successfully perform the exact selected operation on their own fixture before one foreign-token request;
- foreign operations use a raw one-shot transport outside the SDK retry wrapper and stop after one exact confirmation;
- no enumeration, scanning, interactive shell, foreign stop/kill, destructive mutation, or real secret is used;
- every Vercel request start is globally spaced by at least 250 ms;
- response bodies are bounded and erased where buffers permit; private evidence contains hashes and attribution metadata, not raw synthetic markers or tokens;
- uncertain creates require delayed repeated owner-token `404` observations, and cleanup requires exact provenance plus independent absence checks;
- recovery locks/journals or cleanup-only run modes prevent an interrupted/completed run ID from silently issuing another foreign request.

Focused SBX-026 verification currently passes 41 tests. Independent read-only reviews marked the session/command packet READY and found no remaining fork blocker; snapshot/fork final integration review is recorded separately. The complete offline repository suite also passes 175 tests, and both TypeScript configurations pass.

## Live prerequisite decision

Live execution is **NO-GO** at this stage.

The policy requires challenge traffic to use HackerOne-alias accounts and requires two researcher-owned accounts for cross-tenant testing. Only one verified alias-owned Vercel identity is documented locally. It is not yet established how a single HackerOne researcher should provision a second distinct Vercel user under a second eligible alias. The required `SBX026_ATTACKER_*` and `SBX026_VICTIM_*` credential sets are also not configured locally.

Do not work around this with a personal/non-alias email. Obtain written HackerOne/Vercel confirmation of the second-account alias arrangement, create two genuinely distinct Vercel users and teams with no cross-membership, then personally verify both tokens and scopes before considering one bounded lane. Do not place tokens in chat or commit them to the repository.

### 4. Named-sandbox team/project confused deputy

**Routes:** `GET/PATCH/DELETE /v2/sandboxes/:name` and fork.

**Why plausible:** the REST schema says explicit `projectId` takes precedence over OIDC project context, while `teamId` is also caller selected. Every handler must verify token-to-team, team-to-project, and project-to-name membership in one authorization decision. Mixed attacker token/team with an owned victim project ID is a bounded negative test.

**Potential impact:** Critical if read, mutation, resume, delete, or fork succeeds; metadata-only response without content/control may be Low.

### 5. Nested command parent/child binding

**Routes:** `GET/POST /sessions/:sessionId/cmd/:cmdId`, `/logs`, `/kill`.

**Why plausible:** both session and command are opaque identifiers. The backend must prove the command belongs to the session and that the session belongs to the caller. A handler that authorizes only one identifier can leak command output or let one tenant kill another tenant's process.

**Potential impact:** Critical for cross-tenant output/control. A safe test uses one owned victim command containing a synthetic marker and mixes only owned attacker/victim IDs.

### 6. Snapshot metadata/tree/delete authorization

**Routes:** `GET/DELETE /snapshots/:snapshotId`, `GET /snapshots/tree`.

**Why lower:** the identifiers are direct and tree traversal adds parent/sibling objects, but metadata-only disclosure is a lower-impact near miss. Delete would prove modification but is less informative and more destructive than the restore test. Run only if restore binding holds and preserve a fully synthetic victim snapshot.

### 7. Cross-scope pagination cursor replay

**Routes:** sandbox/session/snapshot collection endpoints.

**Why lower:** an opaque cursor may embed a continuation key without being rebound to the current team/project filter. Replaying a cursor created by the owned victim account under attacker credentials could reveal metadata or IDs. Alone this is likely Low; it becomes important only if it enables one of the resource-ID authorization failures above.

## Explicit non-findings / exclusions

- `APIClient.decodeUnverifiedToken()` reads JWT claims client-side to select a team/project. This is not a reportable bypass by itself; the server must still verify the token and authorize the selected scope.
- Workflow serialization can rehydrate a `Sandbox`, `Session`, or `Snapshot` object under different ambient credentials. That client behavior is not a vulnerability unless a server endpoint then accepts a resource owned by the other account.
- File-path normalization, local download paths, retry behavior, and error parsing in the SDK are client-package concerns and are out of scope unless they drive a live server-side sandbox boundary break.
- Vercel OIDC refresh, account/team/project administration, VCR, and build-phase endpoints are outside this challenge's Sandbox control-plane scope.
- Public REST `drive` endpoints were not consumed by the installed `@vercel/sandbox@3.0.0`/`sandbox@4.0.0` pair and were not promoted into this challenge shortlist.

## Safe next step

Ask the program privately how to provision the required second HackerOne-alias Vercel account. After written confirmation, configure both explicit account tuples in the ignored local environment, personally verify no cross-membership, re-read the current policy, and choose only one packet/lane. Retain the private cleanup evidence and stop immediately if the exact synthetic marker crosses the boundary.
