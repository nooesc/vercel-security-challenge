# SBX-045 server-side fork environment override probe

This is a **local-only, not-yet-run** harness for one narrow lifecycle hypothesis:

> A source sandbox has a synthetic environment key with value A. A fork request explicitly
> supplies the same key with a distinct synthetic value B. The target fork may incorrectly
> retain A instead of exposing B.

It uses one researcher-owned HackerOne-alias account, two fresh resource names containing
separate complete UUIDv4 values, separate server-issued sessions, literal `deny-all`, no ports,
no public observer, and no guest networking. An optional omitted-`env` inheritance fork adds a
third complete-UUID resource only when `SBX045_ENABLE_INHERITANCE_CONTROL=1`.

No live Vercel or public-network request was made while creating or testing this packet.

## SDK and policy audit

The repository pins `@vercel/sandbox@3.0.0`. Its distributed type documentation says the server
copies a source sandbox's environment and that every supplied fork field overrides the copied
value (`node_modules/@vercel/sandbox/dist/sandbox.d.ts`, `ForkSandboxParams` and `Sandbox.fork`).
The installed runtime passes `params.env` unchanged to the API client, which serializes it into
`POST /v2/sandboxes/:source/fork`.

The current local upstream Sandbox documentation is even more specific: a supplied `env` map
fully replaces the source map rather than merging it per key. Its mock server implements
`body.env ?? source.env`, and its same-key test expects `override`, not `source`:

- `targets/vercel-sandbox/skills/sandbox/SKILL.md`
- `targets/vercel-sandbox/packages/sandbox/docs/index.md`
- `targets/vercel-sandbox/packages/vercel-sandbox-mock/src/server/mock-server.ts`
- `targets/vercel-sandbox/packages/vercel-sandbox-mock/src/fork.test.ts`

`test/sbx-045-sdk-audit.test.ts` also captures the installed SDK with an offline fake fetch. It
confirms that v3.0.0 sends the exact B map to `/api/v2/sandboxes/:source/fork`, while the optional
inheritance control omits the `env` property entirely. Therefore:

| Fork input | Expected target environment |
|---|---|
| `env` omitted | inherited A |
| `env: { SAME_KEY: B }` | B; the supplied map replaces the copied map |
| `env: {}` | source environment cleared |

An observed A after the explicit B request cannot be explained by this client. It would conflict
with the documented server contract and require a server-side lifecycle investigation, not an
SDK-only report. **Report readiness: NOT READY.** The local program note still requires a live
Sandbox proof, and a stale same-account synthetic value alone may be treated as functional impact.
Do not submit SBX-045 without a separately authorized, concrete isolation or credential-boundary
impact (or explicit program confirmation that this trust boundary qualifies). This packet
deliberately does not add a public endpoint or broaden the proof.

## Fixed proof sequence

1. Generate two equal-length, high-entropy synthetic values in controller memory. Neither value
   is accepted from an environment variable, command line, file, or recovery journal.
2. Before the first create, atomically persist a mode-`0600` recovery journal containing only the
   eligible account binding, full UUID names/tags, creation-attempt state, and known session or
   snapshot IDs.
3. Create the persistent source with `SBX045_SYNTHETIC_ENV=A`, no ports, and literal `deny-all`.
4. Independently confirm the source handle/session, both sandbox-default and live-session
   `deny-all`, and zero routes before mutation. Write the SHA-256-pinned
   `guest/sbx-045-env-digest.mjs` through that pinned session. Run it without supplying the
   synthetic key at command level. SDK v3 serializes the omitted command env as an empty map; it
   does not add a same-key override. The source control must report exactly A's digest.
5. Snapshot and stop the source so the fixed guest file and source session have explicit lifecycle
   provenance. Two fresh `resume:false` handles must agree with the guest/snapshot source session
   on name, tags, session, persistence, sandbox and session `deny-all`, zero routes, and the exact
   successfully created snapshot ID.
6. If enabled, fork once with `env` omitted. Its independently attributed session must report A's
   exact digest. A failed optional control makes the run indeterminate and prevents a target test.
7. Fork the source to a distinct full-UUID target with the explicit same-name environment entry B.
   The target and an independent `resume:false` handle must agree on the target name, tags,
   distinct session, source snapshot, non-persistence, sandbox/session `deny-all`, and zero routes
   before the command runs.
8. Run the unchanged guest program in the target with no synthetic command-level key and stop at
   that one digest result. Cleanup follows immediately.

Every digest uses the already captured `Session.runCommand`, not `Sandbox.runCommand`. The latter
can transparently resume a stopped sandbox in SDK v3. The controller requires the fixed command's
pinned session ID to remain exactly the independently read session for source, optional
inheritance, and target.

The guest emits exactly one JSON line with these fields and nothing else:

```json
{
  "schemaVersion": 1,
  "testId": "SBX-045",
  "present": true,
  "length": 50,
  "sha256": "<64 lowercase hex characters>"
}
```

For an absent key, `present` is false, `length` is zero, and `sha256` is null. The controller
rejects extra fields, multiple lines, stderr, nonzero exit, an oversized result, inconsistent
absence metadata, or a noncanonical digest. Raw command output is parsed and discarded; it is not
stored in evidence.

## Verdict boundary

- `candidate`: every source, snapshot, fork, session, policy, fixed-command, and enabled optional
  control passes, and the target reports the exact source A length and SHA-256.
- `pass`: every required control passes, and the target reports the exact explicit B length and
  SHA-256.
- `indeterminate`: the target is unset, reports any third value, or any required control fails.
- `error`: cleanup or durable evidence finalization fails. An error is never promoted to a
  candidate.

Durable evidence files intentionally remain `candidate: false`, even for an exact-source signal.
They record `exact-source-observed`; the harness emits `candidate: true` only on final stdout after
cleanup, request-audit validation, lock release, journal removal, and the evidence write all
succeed. This prevents a post-rename filesystem-sync failure from leaving a self-declared durable
candidate while the process reports an error.

The candidate comparison uses length plus a constant-time comparison of canonical SHA-256
digests. A third value, a missing value, A/B ambiguity, name/session reuse, policy drift, or
unattributed snapshot cannot produce a candidate.

## Secret and request handling

- A and B exist only as controller-memory strings and as sandbox configuration sent to the owned
  control plane. JavaScript strings cannot be reliably zeroized, but references are dropped after
  evidence construction.
- Raw A, raw B, the Vercel token, guest stdout, and guest stderr are forbidden from stdout,
  artifacts, lock metadata, and recovery state. A final serialization guard checks the complete
  artifact before it is written.
- Evidence retains only presence, UTF-8 length, SHA-256, full owned UUID provenance, sanitized API
  status/code failures, and cleanup/audit facts.
- The Vercel token must be a non-JWT PAT. This prevents the SDK's OIDC refresh path from making a
  request outside the injected gate.
- The injected request gate permits only the Vercel identity endpoint and Sandbox control-plane
  paths, rejects redirects and all public origins, spaces every SDK attempt by at least 250 ms,
  and retains no request body or query values. SDK retries are counted by the same gate.

## Cleanup and orphan recovery

The normal run holds the fixed mode-`0600` `artifacts/SBX-045-live-active.lock`. Before each create,
the journal is durably updated with the exact deterministic resource name and full tags. This
allows recovery even if a create times out before returning a handle.

Cleanup is dependency ordered: target, optional inheritance fork, then source. For every attempted
resource it:

1. discovers by full-UUID name, then validates the exact name and full tags (a wrong-tag exact-name
   object is detected and refused rather than hidden by a tag filter);
2. validates tags, persistence, sandbox/session `deny-all`, zero routes, bounded creation time, and
   every known session before stop or delete;
3. discovers only exact-name snapshots, binds them to a known session or the exact create window,
   deletes each exact snapshot ID, and directly confirms that ID is missing/deleted;
4. deletes the sandbox; and
5. performs two exact-name absence observations separated by at least one second.

An ownership, tag, time, session, pagination, or snapshot-provenance mismatch is left untouched for
manual inspection. Cleanup failure retains both the journal and lock. A supplied canonical
`SBX045_RECOVERY_RUN_ID` can only enter cleanup-only mode; it cannot create a sandbox, fork, or run
a guest command. Stale-lock reclamation requires the exact run ID and a conclusively dead owner,
uses a hard-linked recovery claim, and release verifies the held inode and random lease. A fixed,
validated release tombstone makes interruption between lock release and local finalization
recoverable. An untrusted create response is marked for manual orphan inspection and can never
produce cleanup success.

## Local verification

These commands are local-only and make no Vercel or public-network calls:

```sh
./node_modules/.bin/vitest run \
  test/sbx-045-sdk-audit.test.ts \
  test/sbx-045-verdict.test.ts \
  test/sbx-045-safety.test.ts \
  test/sbx-045-guest.test.ts
```

The tests cover installed SDK serialization, exact candidate/pass/indeterminate exclusivity,
every candidate gate, strict guest parsing, raw-value rejection, complete UUID provenance,
foreign/secret-bearing recovery journals, explicit scope binding, request allowlisting/rate
spacing, mode-`0600` atomic state, exclusive locking, stale-run recovery, lease-safe release,
symlink refusal, and the fixed guest's present/absent output.

## Manual live prerequisites (do not run without re-review)

Immediately before any bounded live run, reread the private HackerOne policy, verify the reward
window and repository privacy, and confirm the exact alias/team/project remain eligible. Required
environment:

```sh
export SBX045_SCOPE_CONFIRMATION="I_RECHECKED_SBX045_SINGLE_ACCOUNT_SCOPE_AND_WILL_USE_ONLY_THE_ELIGIBLE_ALIAS"
export SBX045_EXPECTED_ALIAS="swve@wearehackerone.com"
export VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ"
export VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa"
export VERCEL_TOKEN="<eligible non-JWT PAT>"

# Optional; default is the two-resource source/target proof.
export SBX045_ENABLE_INHERITANCE_CONTROL=1

./node_modules/.bin/tsx pocs/SBX-045/fork-env-override.ts
```

If cleanup is retained, rerun with the emitted full UUID. Cleanup derives the optional-control
shape from the validated recovery journal:

```sh
SBX045_RECOVERY_RUN_ID="<full-run-uuid>" \
  ./node_modules/.bin/tsx pocs/SBX-045/fork-env-override.ts
```

Never infer a security report from the static audit or from a locally manufactured artifact. The
researcher must personally verify any live result and its security impact.
