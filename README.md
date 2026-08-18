# Vercel Security Challenge Research

Private, evidence-first tooling and research notes for authorized testing against Vercel's public security programs. The Sandbox harness is deliberately deterministic: a local controller creates one short-lived sandbox, a guest probe exercises a declared case, and a researcher-controlled observer records what actually crossed the network boundary.

## Programs

- **Vercel Sandbox challenge:** live isolation-boundary research submitted through `vercel_sandbox` on HackerOne.
- **Vercel OSS bug bounty:** source-level findings in explicitly in-scope Vercel open-source projects.

These programs have different scopes. Findings must be submitted to the matching program.

## Repository layout

```text
src/            Controller, registry, observer, and assessment code
guest/          Probe copied into each ephemeral sandbox
test/           Local unit and integration tests
artifacts/      Private JSONL evidence produced by runs (ignored)
observer-data/  Private observer event log (ignored)
findings/       Draft reports and supporting analysis
pocs/           Minimal, non-destructive reproductions
notes/          Scope, hypotheses, and operating instructions
targets/        Local target checkouts (ignored)
```

## Harness quick start

The controller needs Node.js 20.18 or newer. Install dependencies, inspect the implemented cases, and render every policy without creating a sandbox:

```sh
npm ci
npm run harness -- --list
npm run harness -- --all --dry-run
```

A live run also needs a publicly reachable, researcher-controlled HTTPS observer and Vercel SDK authentication. Copy `.env.example` to an ignored environment file, configure it, start the observer on the public host, and run the positive and negative controls first:

```sh
cp .env.example .env
npm run observer
npm run harness -- --test CONTROL-ALLOW --test CONTROL-DENY
```

Do not point `OBSERVER_BASE_URL` at localhost for a live Sandbox run: localhost inside the microVM is not this controller. Put TLS or a trusted HTTPS reverse proxy in front of the observer and keep `OBSERVER_ADMIN_KEY` private.

See [notes/HARNESS.md](notes/HARNESS.md) for architecture, authentication options, operating steps, verdict semantics, and the currently automated subset of the 30-case hypothesis matrix.

## Safety rules

- Test only targets and behaviors explicitly authorized by the applicable program.
- Prefer local reproduction or researcher-owned Sandbox instances.
- Use only researcher-controlled observer domains, endpoints, canaries, and paired resources.
- Never access, retain, or modify real customer data.
- Stop after demonstrating the minimum impact necessary for a report.
- Keep vulnerability details private until Vercel authorizes disclosure.

The harness creates non-persistent sandboxes and attempts both stop and delete cleanup after every run. Cleanup failure forces an error verdict, a nonzero exit, and stops subsequent live cases.

## Automated Sandbox cases

The current registry includes two controls plus four P0 credential-brokering matcher tests:

| ID | Purpose |
| --- | --- |
| `CONTROL-ALLOW` | Confirms ordinary observer reachability under `allow-all`. |
| `CONTROL-DENY` | Confirms ordinary HTTP egress is absent under `deny-all`. |
| `SBX-012` | Brokered-header overwrite and duplicate-value semantics. |
| `SBX-013` | L7 path normalization differences. |
| `SBX-014` | Query matcher ambiguity. |
| `SBX-015` | HTTP method matching and override-style inputs. |

The remaining cases in [notes/SANDBOX_HYPOTHESES.md](notes/SANDBOX_HYPOTHESES.md) are research hypotheses, not claims of vulnerabilities and not yet implemented in this harness.

Selecting `CONTROL-DENY` automatically schedules `CONTROL-ALLOW` first in the same controller process. That dependency prevents an unreachable observer from making an empty deny result look trustworthy.

## Current findings

| ID | Target | Program | Status |
| --- | --- | --- | --- |
| FLAGS-001 | `vercel/flags` | Vercel OSS | Reproduced; draft prepared |
| SBX-013 | Vercel Sandbox firewall | Sandbox challenge | Live reproduced; submission draft prepared |
