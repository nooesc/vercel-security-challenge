# SBX-053: authenticated Git source credential retention

Status: **LOCAL-ONLY CANDIDATE PACKET. No Vercel, GitHub, or other network call has been made.**
Do not submit the static hypothesis or an HMAC-only retention signal. A report requires the exact
live installation-token HMAC plus the private orphan-ref impact proof below, successful cleanup, and manual review
of the current program scope immediately before the run.

## Hypothesis and conditional root cause

`Sandbox.create({ source: { type: "git", username, password } })` gives a private-repository
credential to Vercel's server-side source hydrator. The hypothesis is that hydration embeds the
credential in the clone URL, installs a persistent Git credential helper/askpass mechanism, or
leaves it in the guest-visible bootstrap process context, then exposes that state to untrusted
guest code without scrubbing it.

If the fixed guest recovers the exact credential, the root cause is a server-side lifetime and
trust-boundary error: a one-time controller-to-hydrator capability survives source initialization
inside the less-trusted guest filesystem or process namespace. The SDK only serializes the source
object to `POST /v3/sandboxes`; it does not create `.git/config`, a helper, an askpass script, or a
guest environment entry. The production source hydrator is not in this checkout, so static code
cannot identify which retention mechanism, if any, exists.

Estimated probability of a positive live result: **30–40%**. A naive
`git clone https://user:password@host/repo.git` commonly preserves the authenticated remote, but a
mature source service may already use a one-shot helper and sanitize the checkout. This estimate
is deliberately below even odds.

## Why the guest is not trusted with the source credential

The checked-in official Sandbox skill describes the product as a way to run untrusted code. Its
private-repository example passes a PAT separately in `source.password`, says that the repository
is used to initialize the environment, and then only lists repository contents. It does not say
the PAT becomes a guest secret, remains usable for later pulls, or is persisted in the checkout.
The API response validator omits the entire source object and all source credentials.

The separate long-lived-workspace example runs `git clone` *inside* the guest and later runs
`git pull`. That manual pattern is not the authenticated `source:` bootstrap contract. Nothing in
the local official docs or declarations promises credential retention for `source:`.

Giving the guest the selected source revision is expected. Giving it the reusable PAT is not. The
optional orphan-ref phase makes the difference concrete with one repository: it proves the guest
can read a commit that was absent from the requested shallow source checkout.

## Bounded guest surfaces

The fixed guest hashes candidates from only these targeted surfaces:

- `remote.origin.url` through the local Git command and `.git/config`;
- `.git/config.worktree` and local `credential.helper` configuration;
- fixed global configs under `/root`, `/vercel`, and the documented image home directories;
- the effective Git config reported with dynamic origin/scope metadata, including runtime
  `HOME`, `XDG_CONFIG_HOME`, `GIT_CONFIG_SYSTEM`, and `GIT_CONFIG_GLOBAL` paths;
- fixed `.git-credentials` and `.netrc` locations under those same directories;
- only `store` helper files explicitly declared by effective `credential.helper` configuration;
  a bare `store` checks both `$HOME/.git-credentials` and
  `${XDG_CONFIG_HOME:-$HOME/.config}/git/credentials` (an unsupported executable helper makes a
  negative scan incomplete and is never invoked);
- targeted Git/source credential environment names, including `GITHUB_TOKEN`, `GH_TOKEN`,
  `VERCEL_GIT_*`, and `GIT_CONFIG_PARAMETERS`;
- `/proc/self/{cmdline,environ}`, `/proc/1/{cmdline,environ}`, and at most eight exact
  `PPid` links discovered from `/proc/<pid>/status`; it never enumerates process IDs;
- askpass scripts named by the checked environment/config, with a 16 KiB read ceiling.

It does not enumerate `/proc`, scan the host filesystem, invoke a credential helper, inspect
memory, print URLs, or emit raw candidate values. Files are capped at 32 KiB, candidates at 128,
candidate values at 4096 bytes, environment entries at 256 per inspected process, command-line
arguments at 128 per inspected process, and referenced askpass scripts at 16. Any overflow or
unsupported executable helper makes only a negative result indeterminate; an exact positive
credential plus orphan-ref proof does not depend on finding every other possible copy.

For every candidate it emits only:

```json
{
  "surface": "repo-config",
  "length": 93,
  "hmacSha256": "<HMAC-SHA256(candidate-key, controller-nonce)>"
}
```

The controller knows the PAT and nonce and compares both the byte length and canonical HMAC. A
different credential, a merely usable remote, a third-party secret, or a heuristic token-looking
string cannot produce the exact retention signal, and retention alone cannot produce a reportable
candidate.

## Minimal safe live matrix

Use one researcher-owned disposable private GitHub repository and one one-hour GitHub App
installation token selected only for that repository, with Contents read permission and
push/admin/maintain false in the repository projection. No second Vercel/GitHub account, VPS, receiver,
custom DNS, public port, or callback service is needed.
The controller treats both classic and stateless `ghs_` installation tokens as bounded opaque
values; it does not parse their internal segments and rejects whitespace or control characters.

Prepare two unrelated histories in that repository:

1. `sbx053-source` contains only benign test material. Record its exact commit ID.
2. `sbx053-operator-sentinel` is an orphan branch whose exact commit and `.sbx053-sentinel` file
   are not reachable from the source branch. The file contains a fresh 32+ byte random value.
3. The controller independently authenticates the token to GitHub's fixed
   `/installation/repositories?per_page=2`, exact `/repos/<owner>/<repo>`, and exact
   `/repos/<owner>/<repo>/git/ref/heads/<source-revision>` endpoints. It requires exactly one
   accessible repository, `private: true`, false push/admin/maintain projections, three attributed
   GitHub request IDs, and an exact source-ref response whose object is the pinned source commit.
   GitHub's repository `permissions.pull` collaborator projection is recorded as a boolean but is
   not used as an App-token permission test; the exact pinned-ref read proves Contents read. The
   controller also requires the exact `expires_at` copied from the authenticated installation-token
   mint response, between five minutes and 3,700 seconds away. Authenticated GET expiry headers are
   optional because current classic and stateless tokens may omit them; any header that is present
   must exactly equal the mint response. Ambiguity aborts before create.
4. Independently verify neither the sentinel ref nor commit exists in a depth-one checkout of
   `sbx053-source`.

The controller performs this sequence:

1. Atomically acquire a current-user-owned mode-0600 live lock and write a no-clobber mode-0600,
   secret-free recovery journal before any create attempt. Verify the Vercel token belongs to the
   eligible HackerOne alias/team/project and complete the GitHub authority preflight above.
2. Create one fresh full-UUID sandbox with `persistent: false`, no ports, `depth: 1`, the exact
   source branch/commit, and literal `deny-all`. The Git PAT appears only in `source.password`; the
   explicit sandbox environment is empty.
3. Confirm the returned name, tags, session, no routes, `deny-all`, valid worktree, and exact source
   commit. A fresh `Sandbox.get({ resume: false })` must independently agree on the same session,
   tags, routes, and policy. Upload the SHA-256-pinned guest and run `scan` with only the repository
   path and nonce.
4. Stop on a complete negative result. It is a pass only for the listed surfaces, not proof that
   every possible server implementation is safe.
5. On an exact PAT HMAC match, optionally change the policy to exactly `{ allow: ["github.com"] }`.
   Both the active handle and a fresh non-resuming readback must confirm that exact policy. The same
   fixed guest rescans, selects only the exact matching candidate, confirms `HEAD^{commit}`
   succeeds as a present control, and requires exact exit 128 for the absent sentinel object. It
   also confirms the sentinel local and remote-tracking refs are absent. It first proves an
   explicitly credential-free fetch exits 128 with a curl trace attributable to GitHub HTTP
   401/404 (DNS, TLS, firewall, and policy failures do not count), then fetches only the exact sentinel ref with the
   recovered credential into a temporary namespace. It returns only the sentinel byte length and
   `HMAC-SHA256(sentinel-key, challenge)` and deletes the temporary ref.
6. Persist network-opening intent before the policy change. Restore literal `deny-all` in
   `finally`, confirm it through another fresh non-resuming readback, stop/delete the exact
   tagged sandbox, require three exact-name 404s and an exact tag/prefix list absence, then commit
   journal removal before releasing the live lock.
7. Write a uniquely named, no-clobber mode-0600 private artifact containing ordered phase
   chronology, HMAC-only observations, sanitized GitHub authority facts, cleanup evidence, and one
   shared credential nonce binding the authority token HMAC to the guest observation. Retain the
   exact team, project, sandbox, session, repository, source ref/commit, and—when used—sentinel
   ref/commit/path plus its challenge and expected HMAC proof. Never retain either raw secret or a
   standalone digest of one.
   Revoke the Git token and delete the disposable repository/ref after reviewing that artifact.

If create has an unknown outcome, normal mode leaves the lock and journal in place. Cleanup-only
mode accepts `SBX053_RECOVERY_RUN_ID`, needs no Git token or sentinel, and does not treat an
exact-name 404 as final until the 45-second create deadline plus the four-minute sandbox timeout
plus 30 seconds have elapsed. It then requires three exact-name 404s plus prefix-list absence.
Every cleanup attempt writes a unique recovery artifact and never overwrites experiment evidence.
The lock protocol also recovers crashes on either side of journal deletion and an acquisition
crash after the replacement lock becomes canonical but before the journal is committed, without
opening a new experiment.

The optional fetch supplies the recovered credential to a single `git fetch` through an ephemeral
Git config environment after the leak is already proved. It does not modify the remote, working
tree, or source config.

## Decisive proof and verdicts

- `pass`: every control and cleanup step passes, the scan is complete, and no observation equals
  the PAT's exact byte length and HMAC.
- `credential-retention-signal`: every control passes and a guest-visible surface equals the
  controller-only PAT's exact byte length and HMAC. This is deliberately **not report-ready** by
  itself because contract wording around initialization credentials could make residue ambiguous.
- `uncloned-ref-access-candidate`: the credential proof passes and the guest additionally returns
  the exact sentinel HMAC after the exact object/ref controls, transport-attributed anonymous
  denial, and authenticated fetch all succeed.
- `indeterminate`: attribution, source commit, guest digest, policy, bounds, parsing, or cleanup
  fails. A plausible-looking value is never promoted.

Likely severity is **Medium** only for the completed orphan-ref proof: reusable credential
disclosure plus access to private repository data outside the selected source revision. This
packet forbids broader repository/write authority, so **High is not a supported verdict**. A token limited to
the already-cloned revision with no reusable authority would not meet the report threshold.

## Distinct from SBX-001 through SBX-052

No earlier packet uses Git/tarball source authentication or tests `source.username/password`.
This is not SBX-013/049/050 network-transform credential handling, SBX-045 fork environment
semantics, SBX-048 proxy OIDC audience confusion, SBX-051 interactive-session capability binding,
or SBX-052 file-API namespace resolution. Its boundary is uniquely the create-time source
hydrator credential crossing into guest-visible state.

## Local verification

These commands are offline. The fake SDK transport does not contact Vercel, and the guest tests
use local temporary Git repositories only:

```sh
./node_modules/.bin/vitest run \
  test/sbx-053-guest.test.ts \
  test/sbx-053-verdict.test.ts \
  test/sbx-053-sdk-audit.test.ts \
  test/sbx-053-safety.test.ts \
  test/sbx-053-live-lock.test.ts \
  test/sbx-053-controller.test.ts
```

## Manual live prerequisites (not authorization to run)

Only after a fresh scope review and explicit live-run coordination:

```sh
export SBX053_SCOPE_CONFIRMATION="I_RECHECKED_SBX053_SCOPE_AND_WILL_USE_ONE_OWNED_DISPOSABLE_PRIVATE_REPO_AND_SHORT_LIVED_TOKEN"
export SBX053_EXPECTED_ALIAS="swve@wearehackerone.com"
export SBX053_MANUAL_ALIAS_CONFIRMATION="swve@wearehackerone.com"
export VERCEL_TEAM_ID="team_n98ERpVwV7HqmWRudAyK8sXQ"
export VERCEL_PROJECT_ID="prj_CyyVykdN06Nrkla6KidZcecLgbCa"
export VERCEL_TOKEN="<eligible non-JWT Vercel PAT>"

export SBX053_GIT_URL="https://github.com/<researcher>/<disposable-private>.git"
export SBX053_GIT_USERNAME="x-access-token"
export SBX053_GIT_TOKEN="<one-hour opaque ghs_ GitHub App installation token for exactly that repo>"
export SBX053_GIT_TOKEN_EXPIRES_AT="<exact expires_at from that authenticated mint response>"
export SBX053_SOURCE_REVISION="sbx053-source"
export SBX053_SOURCE_COMMIT="<exact source commit>"

# Default 0: exact credential-retention proof only, with deny-all throughout.
export SBX053_ENABLE_IMPACT=0

# Optional stronger proof, enabled only after the orphan histories are independently verified.
export SBX053_SENTINEL_BRANCH="sbx053-operator-sentinel"
export SBX053_SENTINEL_COMMIT="<exact orphan sentinel commit>"
export SBX053_SENTINEL_PATH=".sbx053-sentinel"
export SBX053_SENTINEL_VALUE="<exact fresh random sentinel file bytes>"
export SBX053_ENABLE_IMPACT=1

./node_modules/.bin/tsx pocs/SBX-053/git-source-credential-retention.ts

# Cleanup-only after a crash or unknown create. Omit every SBX053_GIT_* and sentinel variable.
export SBX053_RECOVERY_RUN_ID="<exact UUID printed in the journal/artifact filename>"
./node_modules/.bin/tsx pocs/SBX-053/git-source-credential-retention.ts
```

Do not put either token or the sentinel on a command line. Revoke/delete them even after a pass.
