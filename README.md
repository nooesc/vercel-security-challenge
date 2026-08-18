# Vercel Security Challenge Research

Private working repository for authorized research against Vercel's public security programs.

## Programs

- **Vercel Sandbox challenge:** live isolation-boundary research submitted through `vercel_sandbox` on HackerOne.
- **Vercel OSS bug bounty:** source-level findings in explicitly in-scope Vercel open-source projects.

These programs have different scopes. Findings must be submitted to the matching program.

## Repository layout

```text
findings/       Draft reports and supporting analysis
pocs/           Minimal, non-destructive reproductions
notes/          Scope notes and research logs
targets/        Local target checkouts (ignored by Git)
```

## Safety rules

- Test only targets and behaviors explicitly authorized by the applicable program.
- Prefer local reproduction or researcher-owned Sandbox instances.
- Never access, retain, or modify real customer data.
- Stop after demonstrating the minimum impact necessary for a report.
- Keep vulnerability details private until Vercel authorizes disclosure.

## Current findings

| ID | Target | Program | Status |
| --- | --- | --- | --- |
| FLAGS-001 | `vercel/flags` | Vercel OSS | Reproduced; draft prepared |

