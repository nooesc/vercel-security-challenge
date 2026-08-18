# Deterministic Sandbox harness

This harness separates orchestration, execution, and observation so that a result does not depend on an agent's judgment or on guest-reported success.

## Architecture

```text
controller (trusted, local)
  |  creates a short-lived sandbox with one exact network policy
  |  uploads a fixed probe and runs declared cases sequentially
  v
guest probe (hostile side of the boundary)
  |  sends uniquely identified requests
  v
public observer (researcher-controlled, outside the microVM)
  |  records raw requests independently
  v
controller assessment + append-only JSONL evidence
```

The controller is the only component with Vercel credentials, the observer admin key, and the synthetic brokered secret. The guest receives a separate random, non-secret correlation canary but never receives the admin key or brokered secret. The observer's probe endpoint must be publicly reachable because a Vercel Sandbox cannot reach the controller's localhost. Its event-read API is protected by `OBSERVER_ADMIN_KEY`.

Each selected test gets a new run ID, correlation canary, brokered canary, sandbox, and policy. The controller copies `guest/http-probe.mjs` into the sandbox, runs each case, waits briefly for observer delivery, retrieves events, assesses them against declared expectations, appends evidence, and then attempts both `stop()` and `delete()` in cleanup.

## Install and inspect without credentials

Requires Node.js 20.18 or newer.

```sh
npm ci
npm test
npm run typecheck
npm run harness -- --list
npm run harness -- --all --dry-run
```

`--dry-run` does not contact Vercel or the observer and does not require any credential. It prints the policies and cases with redacted placeholder canaries. A configured `OBSERVER_BASE_URL` is used only to derive the observer hostname; otherwise the reserved placeholder `https://observer.example.invalid` is used.

Selections are explicit and case-insensitive. `--test` is repeatable, while `--all` and `--test` are intentionally mutually exclusive:

```sh
npm run harness -- --test SBX-013 --dry-run
npm run harness -- --test CONTROL-ALLOW --test CONTROL-DENY
```

Unknown IDs, conflicting modes, and a missing selection fail before any sandbox is created.

`CONTROL-DENY` has a required process-local dependency on a successful allow control. If it is selected alone, or appears before `CONTROL-ALLOW`, the CLI automatically schedules `CONTROL-ALLOW` first and reuses the same `HarnessRunner`. This makes the empty deny observation interpretable; calling the lower-level runner directly without the prior allow control yields an indeterminate result.

## Observer setup

Run the observer on a dedicated, researcher-controlled host or container with durable local storage. Configure a random admin key of at least 24 characters:

```sh
cp .env.example .env
openssl rand -hex 32
```

Put the generated value in `OBSERVER_ADMIN_KEY`, set `OBSERVER_DATA_FILE` to persistent storage, and start the service:

```sh
npm run observer
curl http://127.0.0.1:8787/healthz
```

For live Sandbox traffic, expose that service through a controlled HTTPS hostname and set `OBSERVER_BASE_URL` to its public origin, for example `https://sandbox-observer.research.example`. TLS should terminate on the observer host or a trusted reverse proxy under the researcher's control. The probe ingestion route must be public; do not expose or log the admin key, and restrict the event-read route to the controller wherever possible.

Keep these paths private and backed up during a research session:

- `observer-data/events.jsonl`: raw origin observations.
- `artifacts/*.jsonl`: controller evidence, policies, commands, assessment, and cleanup state.

Both directories and all `.env*` files except `.env.example` are ignored by Git.

## Vercel authentication

Prefer a development OIDC token in an ignored environment file. Link a researcher-owned Vercel project, pull its environment, then add the observer variables from `.env.example` to the same file:

```sh
npx vercel link
npx vercel env pull .env.local
DOTENV_CONFIG_PATH=.env.local npm run harness -- --test CONTROL-ALLOW --dry-run
```

For the actual live run, use the same `DOTENV_CONFIG_PATH` invocation without `--dry-run`. Development OIDC tokens expire, so pull a fresh one when the SDK reports expiration. Never paste the token into a command, finding, evidence file, or committed configuration.

If OIDC is unavailable, set all three explicit SDK variables in the ignored environment file:

```text
VERCEL_TEAM_ID=team_or_owner_id
VERCEL_PROJECT_ID=project_id
VERCEL_TOKEN=access_token_scoped_to_that_team
```

The adapter uses explicit credentials only when all three are present; otherwise the SDK uses `VERCEL_OIDC_TOKEN`. Do not commit either form.

## Safe live sequence

1. Confirm the observer's public `/healthz` responds from an external network.
2. Render the selected definitions with `--dry-run` and review the exact policy and cases.
3. Run `CONTROL-ALLOW`. Do not interpret any blocked-request result unless this positive control passes.
4. Run `CONTROL-DENY`. The CLI automatically schedules the allow dependency first even when deny is selected alone. Investigate an observer hit immediately; do not broaden the probe until it is reproduced.
5. Run one hypothesis ID at a time, starting with `SBX-012` through `SBX-015`.
6. Check the printed evidence path and cleanup fields after each run. Stop if cleanup reports an error.
7. Reproduce a candidate with a fresh run ID and the minimum request needed before preparing a report.

Example:

```sh
DOTENV_CONFIG_PATH=.env.local npm run harness -- --test CONTROL-ALLOW
DOTENV_CONFIG_PATH=.env.local npm run harness -- --test CONTROL-DENY
DOTENV_CONFIG_PATH=.env.local npm run harness -- --test SBX-013
```

Live tests run sequentially. The process exits nonzero for `candidate`, `indeterminate`, or `error`, which makes it suitable for scripted gating while preventing a broken positive control from appearing successful.

## Evidence and verdicts

Each JSONL record includes the test/run IDs, generated policy and probe cases, SHA-256 digests of both generated canaries, guest command output, independently recorded observer events, assessment signals, sandbox identity, and cleanup results. Observer events retain the raw, non-secret correlation canary and request URL. Credential tests use a separate synthetic brokered value that is never included in the guest probe configuration. The generic evidence writer redacts that exact synthetic value from the policy, guest output, and copied observer events before persistence; the observer's raw JSONL remains private. Never substitute a real credential or sensitive value for either marker.

| Verdict | Meaning | Next action |
| --- | --- | --- |
| `pass` | Positive controls arrived and no observation contradicted the declared policy. | Retain evidence and move to the next case. |
| `candidate` | An observer hit or canary injection contradicted the policy expectation. | Stop, review raw events, and reproduce minimally. |
| `indeterminate` | A required positive control did not arrive. | Fix observer/probe reliability; do not claim a boundary bypass. |
| `error` | Setup, SDK, observer, probe, or controller execution failed. | Resolve the operational failure and rerun fresh. |
| `skipped` | A future registry case determined it could not run safely. | Record the prerequisite and do not infer security impact. |

Guest stdout alone is never proof of egress. The observer event is the authoritative network signal, and a report still needs a clean live reproduction using `@vercel/sandbox` that meets the challenge's impact rules.

## Implemented coverage and backlog

The registry currently automates:

- `CONTROL-ALLOW`: allow-all observer reachability.
- `CONTROL-DENY`: deny-all HTTP egress baseline.
- `SBX-012`: brokered credential overwrite and duplicate values.
- `SBX-013`: matched-path normalization cases.
- `SBX-014`: exact-query ambiguity cases.
- `SBX-015`: POST-only method matching cases.

These are 4 of the 30 hypotheses in `notes/SANDBOX_HYPOTHESES.md`, plus two reliability controls. The matrix is the backlog, not a list of confirmed issues. DNS, CNAME/rebinding, multi-origin redirects, HTTP/2, WebSocket, UDP/QUIC, live-policy updates, lifecycle/ownership, published ports, and Firecracker/device testing need additional controlled infrastructure and dedicated probes before they should be added to the registry.
