# Vercel Sandbox HackerOne policy checklist

Source supplied from the private HackerOne posting on 2026-08-18. This note is an operating summary, not a replacement for rereading the program policy before every submission.

## Window and handling

- Eligible testing window: 2026-08-18 through 2026-09-01 23:59 UTC, unless the reward pool is exhausted earlier.
- Maximum stated award per report: USD 50,000; one root cause per report.
- Reports and working PoCs remain private. Do not publish reproduction details, logs, identifiers, or exploit code before the disclosure conditions are met.
- The repository must remain private with no outside collaborators. HackerOne is the submission channel.

Current account check (2026-08-18): the Sandbox CLI session used for initial research is **not** authenticated with a `@wearehackerone.com` alias. Do not perform final eligible reproductions or submit its account IDs as the final testing account. Re-authenticate with the research alias, then capture the new `team_…`, `prj_…`, and `sbx_…` values.

Repository check (2026-08-18): `nooesc/vercel-security-challenge` is private and lists only its owner as a collaborator. Preserve that state through the embargo.

## Required submission contents

- Working PoC zip in the initial report.
- Exact Vercel Team ID (`team_…`).
- Exact Vercel Project ID (`prj_…`), not only the project name or slug.
- Vercel Sandbox/session ID (`sbx_…`) for every cited reproduction.
- Vulnerability class and severity rationale tied to the program's bounty table.
- Explicit acknowledgement of the severity-inflation bounty penalty.
- Exact commands, sandbox policy/image/runtime, timestamps, controls, impact, and cleanup.
- Researcher must personally verify the live PoC and impact before submission; do not submit an unverified AI-generated report.

## Testing constraints

- Use only accounts, projects, sandboxes, endpoints, credentials, and data we own.
- Cross-tenant work requires two accounts we own. Stop at the first minimal confirmation.
- Never enumerate or retain third-party tenant data.
- Cap automated requests to Vercel-operated endpoints at five queries per second.
- No volumetric denial of service, persistence, backdoors, social engineering, or unrelated Vercel API testing.
- Static analysis is supporting material only; every report needs a working live Sandbox PoC.
- Reproduce from a fresh sandbox and always stop/delete owned test resources.

## Explicit known/duplicate classes to avoid

- Container-to-Firecracker-guest namespace escapes, including the published `core_pattern`, capabilities, `/dev`, seccomp/AF_VSOCK, `/dev/vda`, `modprobe`, and `uevent_helper` paths.
- The listed post-container-escape vsock 2050, outer socket, sibling-container, sysctl, metrics, and sandbox-init-key primitives unless chained to a materially new host/cross-tenant impact.
- Merely matching a deployed Firecracker/component version to a public CVE without a working live host or cross-tenant impact.
- Build-phase Containerfile/Dockerfile and Vercel Container Registry issues.
- Platform observability-header presence by itself. A report needs a Vercel-side exfiltration channel, not a third-party site reflecting headers.
- SDK/client-side defects. Only the server-side Sandbox control plane is in scope.

## Network and credential proof bar

- Blocking more than configured is not a security finding.
- A bypass must show traffic or credential use that the accepted operator policy should have prevented.
- Do not rely on a third-party origin reflecting a brokered header. Prefer an observer-side non-reflecting authenticated action and return only an opaque operation ID.
- Documented limitations/configuration guidance are intended behavior. Check current firewall docs immediately before submission.
- Record positive reachability/transform controls, negative policy controls, exact socket/session attribution, observer events, secret hashes, and cleanup.

## Current report mapping

- `SBX-013`: suggested Medium. It demonstrates authenticated transform use on a canonical route outside the configured path scope, with a non-reflecting controlled action.
- `SBX-018`: suggested Medium if hardened reproduction holds. It demonstrates stale network-policy/transform state after an acknowledged live `deny-all` update; do not claim guest credential retrieval.
- `SBX-008` plain SNI behavior: do not submit. Current documentation explains SNI-only enforcement for end-to-end TLS traffic.
