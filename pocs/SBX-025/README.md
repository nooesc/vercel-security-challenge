# SBX-025 persistent lifecycle policy-restore probe

This deterministic PoC tests whether a credential transform removed before a persistent sandbox is stopped can reappear when that sandbox resumes from its automatic snapshot.

It uses only lifecycle operations supported by `@vercel/sandbox@3.0.0`:

- `Sandbox.create({ persistent: true, ... })` to create one named, researcher-owned sandbox;
- `sandbox.update({ networkPolicy: "deny-all" })` to remove the transform and tighten egress;
- `sandbox.stop()` to create the persistent sandbox's automatic snapshot;
- `Sandbox.get({ name, resume: true })` to resume into a new session;
- `sandbox.delete()` and `Snapshot.delete()` for cleanup.

The test does not use an inferred restart command, an unsupported restore API, or a fork. Forking can be evaluated separately if resume produces a credible signal.

## Proof sequence

The initial policy allows only the controlled observer and injects a fresh controller-only synthetic credential. The observer's `/outside` endpoint never reflects that credential. It performs a credential-gated action and returns only an opaque operation ID.

1. **Pre-change transform control:** a fresh request must reach the observer with the exact synthetic credential and authorize exactly one action.
2. **Tighten:** the controller awaits `sandbox.update({ networkPolicy: "deny-all" })`, then obtains an independent `Sandbox.get({ resume: false })` readback. Both handles must report `deny-all`.
3. **Same-session deny control:** a fresh request must fail with no observer event and no additional action.
4. **Lifecycle:** `sandbox.stop()` must produce an automatic snapshot. `Sandbox.get({ name, resume: true })` must return a different session ID attributed to that captured snapshot through session-source or current-snapshot metadata. Its policy, plus an independent readback, must still report `deny-all`.
5. **Post-resume probe:** a fresh request is attempted from the resumed session.
6. **Pass-only reachability control:** if the post-resume request was blocked, the controller installs a plain allow rule with no transform. The same resumed session must then reach the observer, receive `401`, carry no brokered header, and authorize no action.

Interpretation:

- `candidate`: every attribution control passes and the post-resume observer event contains the exact removed credential, authorizes exactly one post-resume action, and returns the matching opaque operation ID.
- `pass`: requests are blocked before and after resume under `deny-all`, the resumed policy readback is exact, and the same resumed session passes the final plain-allow/no-transform reachability control.
- `indeterminate`: a positive, readback, snapshot, new-session, observer, or reachability control fails. Credential-free reachability under `deny-all` is also indeterminate for this credential-restore hypothesis rather than being mislabeled as an SBX-025 candidate.
- `error`: setup, evidence collection, or cleanup fails.

The synthetic credential and observer admin key never enter the guest configuration. Raw observer events are retained only in a mode-`0600` private artifact, and console output includes only hashes and opaque identifiers.

## Run

Prerequisites:

- Node.js 20.18 or newer;
- a researcher-owned HTTPS observer running this repository's observer service;
- authenticated access to the eligible Vercel team/project;
- `OBSERVER_ADMIN_KEY` configured on the observer.

```sh
npm ci
export OBSERVER_BASE_URL="https://<controlled-observer>"
export OBSERVER_ADMIN_KEY="<random-controller-only-admin-key>"
npx sandbox login
npx tsx pocs/SBX-025/lifecycle-policy-restore.ts
```

For explicit credentials, set `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, and `VERCEL_PROJECT_ID` together instead of using the device login.

The run makes at most four guest requests, sequentially, and stops at the first credential-restoration signal. It always attempts to stop the named sandbox, enumerate its snapshots, delete the sandbox, delete every captured or enumerated automatic snapshot, and remove the observer action configuration. Vercel documents that snapshots survive sandbox deletion; a typed `404` or `snapshot_not_found` while deleting a captured snapshot is therefore recorded as successful prior absence. Any other cleanup failure overrides the security verdict with `error`.
