# Vercel Security Challenge Research

Public, evidence-first tooling and research notes from authorized testing against Vercel's public security programs. The Sandbox harness is deliberately deterministic: a local controller creates one short-lived sandbox, a guest probe exercises a declared case, and a researcher-controlled observer records what actually crossed the network boundary.

## New Sandbox findings

This release adds two independently reproduced Vercel Sandbox firewall findings. The repository now contains four technically reproduced reports across the Sandbox and OSS programs; the fifth report document is a historical signal that did not survive hardened reproduction. Each current report is intentionally narrow about demonstrated impact and includes a bounded reproduction bundle.

| ID | Finding | Demonstrated result | Disposition |
| --- | --- | --- | --- |
| `SBX-020` | [Literal `deny-all` permits authenticated MMDS access](findings/SBX-020-mmds-explicit-link-local-deny-bypass.md) | A same-session `deny-all` policy blocked an owned public endpoint while MMDSv2 token exchange and authenticated MMDS access returned `200`. | Vercel confirmed the Firecracker/MMDS root cause; report `#3952509` was closed as an exact duplicate of `#3951306`. |
| `SBX-031` | [ECH outer-SNI domain allowlist bypass](findings/SBX-031-ech-domain-allowlist-bypass.md) | An allowed ECH public name carried a denied inner hostname and exfiltrated a fresh synthetic file secret to the owned inner endpoint in two live reproductions. | Reproduced; disclosure remains clarification-gated because Vercel's documented ECH authorization semantics are ambiguous. |

See [findings/README.md](findings/README.md) for the complete findings index and status terminology. A duplicate resolution does not invalidate the technical result; it means the same root cause was reported earlier.

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
Before any live run or submission, also read [notes/HACKERONE_PROGRAM_POLICY.md](notes/HACKERONE_PROGRAM_POLICY.md). Final eligible evidence must come from the required HackerOne-alias Vercel account.

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

## Research status

The two new Sandbox findings above are the primary results of this research release. Earlier reports and negative or indeterminate investigations remain in [`findings/`](findings/) and [`pocs/`](pocs/) for reproducibility. A PoC directory is not itself a vulnerability claim; trust the status in its README and retained assessment.

| ID | Area | Status |
| --- | --- | --- |
| `FLAGS-001` | `vercel/flags` cross-group precompute replay | Reproduced OSS draft. |
| `SBX-013` | Encoded dot-segment credential-brokering scope | Reproduced on the eligible alias account; historical report retained. |
| `SBX-018` | Live policy update / stale transform | Historical signal; five hardened alias runs did not reproduce it. |
