# Program scope notes

## Vercel Sandbox challenge

- Window: August 18 through September 1, 2026, or until the reward pool is exhausted.
- Submission: <https://hackerone.com/vercel_sandbox>
- Requires a live proof using `@vercel/sandbox`; static-analysis-only findings are not rewarded.
- In scope:
  - Firecracker microVM escape to the EC2 host.
  - Cross-tenant sandbox access, modification, execution, or crash.
  - Host-enforced network-policy bypass.
  - Unauthorized network destinations, data exfiltration, or retrieval of brokered credentials.
- Explicitly excluded by the announcement: a container namespace escape that reaches only the Firecracker guest OS.

## Vercel OSS bug bounty

- Submission: <https://hackerone.com/vercel-open-source>
- Covers Vercel's listed open-source projects, including `vercel/flags`.
- `FLAGS-001` belongs to this program, not the Sandbox isolation challenge.

