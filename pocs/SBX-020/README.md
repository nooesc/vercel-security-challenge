# SBX-020 Firecracker MMDS/link-local discriminator

## Preferred same-session `deny-all` differential

`deny-all-mmds-differential.ts` is the primary report PoC. It creates one fresh sandbox under literal `allow-all`, confirms a researcher-owned public health endpoint is reachable, updates that same session to literal `deny-all`, and requires exact active plus independently fetched `deny-all` readbacks for the original session ID. It then requires a fresh non-timeout public block before running the fixed MMDS probe. A Medium candidate requires MMDS token issuance and a later authenticated root response under that verified `deny-all` state; it does not require or claim a populated secret.

```sh
export VERCEL_TOKEN="<researcher-token>"
export VERCEL_TEAM_ID="<researcher-team-id>"
export VERCEL_PROJECT_ID="<researcher-project-id>"
npx tsx pocs/SBX-020/deny-all-mmds-differential.ts
```

The differential retains no public or MMDS response body, token value or digest, command output body, or sensitive response digest. It always attempts stop and delete. The public `EAI_AGAIN` result is a corroborating negative control; the core proof is the exact same-session `deny-all` readback followed by the token and authenticated MMDS responses.

## Explicit link-local CIDR variant

This packet asks whether a fresh Vercel Sandbox can reach Firecracker/AWS-style metadata at exactly `169.254.169.254` while a custom default-deny policy explicitly denies `169.254.0.0/16` and the common private/CGNAT ranges. The SDK represents this as an empty domain allowlist plus explicit `subnets.deny` entries; its literal `"deny-all"` sentinel cannot carry additional CIDR fields.

The guest never scans. It performs at most eight sequential HTTP requests to port 80, with a two-second timeout, a 16 KiB response cap, a minimum 200 ms inter-request delay, and no more than five requests per second:

1. One unauthenticated harmless index request to `/latest/meta-data/`.
2. One IMDSv2 `PUT /latest/api/token` with a fixed 60-second TTL header. Its response digest is not retained, and a syntactically valid token exists only in guest memory during this flow.
3. Authenticated GETs to the fixed instance-identity document and IAM role-index paths.
4. Only when the role index is one safe IAM role-name path segment, one final GET to `/latest/meta-data/iam/security-credentials/<encoded-role>`.
5. If the standard IAM flow produces no proof or unsafe response, one authenticated IMDS-format listing at `/`. The request deliberately omits `Accept`, which is Firecracker's documented selector for IMDS output; it does not send the unsupported `Accept: text/plain` spelling. The guest rejects JSON-object roots and unsafe listing syntax.
6. From that listing it follows at most one exact allowlisted secret namespace (`datadog`, `secrets`, `credentials`, or `tokens`) or the explicitly permitted `/latest/` index, and then one exact allowlisted API-key, credential, or token leaf. A direct allowlisted secret leaf at `/` uses only the final request.

The flow stops at the first credential proof. Directory and role-index requests omit `Accept`; the one exact selected secret leaf uses `Accept: application/json` so both JSON strings and structured objects can be validated. If an IMDS-compatible server ignores that header, the same parser accepts a plain scalar and rejects a directory-shaped response. Neither the token, role name, discovered scalar, nor any response body is emitted, persisted, or uploaded. Dynamic credential and discovery paths are represented only as templates. Directory evidence contains only a bounded child count and the single matched allowlisted namespace/leaf enum; arbitrary safe-looking lines and listing digests are never emitted. Secret evidence contains only length, SHA-256, content type, proof type, path template, and validated allowlisted object key names when applicable. Token and low-entropy role-index responses omit even their SHA-256. All transient token, role, listing, and scalar buffers are wiped after use. The controller rebuilds the guest result from an allowlist of fields, discards stderr content, and writes the private artifact mode `0600`.

The header behavior follows Firecracker's MMDS format contract: `Accept: application/json` selects JSON, while `Accept: plain/text` or no `Accept` selects IMDS. Header omission is used for listings because it is both documented and unambiguous. The guest emits a fixed request-format attestation, the controller allowlists it, and candidate classification fails if any expected format value differs. Evidence also binds that attestation to SHA-256 hashes of the exact guest probe and discovery-rules sources uploaded for the run. See the upstream [MMDS user guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-user-guide.md#mmds-formats).

Vercel currently canonicalizes the requested policy by omitting `allow: []`. Policy equivalence accepts exactly either the original object or that one canonical representation. It rejects a reordered/changed CIDR list, additional keys, a nonempty allowlist, and all other policy changes.

Interpretation:

- `candidate`: either the standard credential document has `Code === "Success"` plus nonempty scalar `AccessKeyId`, `SecretAccessKey`, `Token`, and parseable `Expiration` values, or one exact allowlisted discovery leaf returns a non-placeholder scalar or secret-like object with a nonempty validated secret field. Values are checked only in guest memory. Every policy, rate/bound, flow-attribution, body-free, proof-stop, and cleanup control must pass.
- `supporting-signal`: the MMDSv2 token, expected identity structure, safe role index, or safe text directory listing was reached without a credential proof. A token or listing alone is not a High finding.
- `pass`: the bounded flow reached a safe terminal state without identity/role/credential disclosure, and either the guest route check or an HTTP response supplied a suitable control. A rejected token request can therefore close the flow without unauthenticated follow-up requests.
- `indeterminate`: token/role syntax is unsafe, a directory is JSON-shaped or contains unsafe child syntax, a populated secret/credential response has an unexpected structure, timeouts/refusals lack a route/HTTP control, the policy differs beyond omission of empty `allow`, flow/rate bounds fail, or execution/cleanup is incomplete.

The controller reserves `candidate` for the program's High-impact MMDS secret-disclosure condition. A reproducible `supporting-signal` can still establish the separate Medium condition in the bounty table when it proves that an explicitly denied destination is reachable but exposes no secret. Severity therefore depends on the demonstrated impact, not the controller's internal label alone.

## Run manually

Do not run this packet casually. Confirm the current challenge policy first, then provide an explicit researcher-owned authorization context:

```sh
export VERCEL_TOKEN="<researcher-token>"
export VERCEL_TEAM_ID="<researcher-team-id>"
export VERCEL_PROJECT_ID="<researcher-project-id>"
npx tsx pocs/SBX-020/mmds-link-local.ts
```

The controller creates one fresh nonpersistent sandbox, uploads the fixed probe, runs it once, and always attempts both stop and delete. It prints only the assessment, sandbox/session metadata, cleanup state, and artifact path. The full body-free evidence is written under `artifacts/`, which is ignored by Git.

## Local validation only

```sh
npx vitest run test/sbx-020-deny-all-differential.test.ts test/mmds-link-local-probe.test.ts
npx tsc --noEmit
npx tsc --noEmit -p tsconfig.poc.json
```
