# Literal `deny-all` still permits authenticated access to MMDS at `169.254.169.254`

## Submission metadata

- Asset: Vercel Sandbox network firewall / MMDS
- Vulnerability class: **Networking and Firewall**
- Suggested severity: **Medium**
- Suggested weakness: [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- HackerOne-alias Vercel account: `swve@wearehackerone.com`
- Vercel Team ID: `team_n98ERpVwV7HqmWRudAyK8sXQ`
- Vercel Project ID: `prj_CyyVykdN06Nrkla6KidZcecLgbCa`
- Primary Sandbox ID: `sbx_VgoUgV3x73XRCmj73Eri7gXhuX73`
- Test environment: `@vercel/sandbox@3.0.0`, Vercel region `iad1`
- Submission state: **READY — same-session differential reproduced live on the required HackerOne-alias account**
- Severity acknowledgement: I understand the program's severity-inflation bounty penalty. I am requesting Medium only for the demonstrated firewall boundary violation. I am not claiming populated MMDS content, credential disclosure, host escape, or cross-tenant impact.

## Summary

Vercel Sandbox continues to route traffic to MMDS at `169.254.169.254` while the sandbox's active network policy is literal `deny-all`.

I demonstrated this in one fresh sandbox with a same-session differential:

1. Under `allow-all`, a fresh request to my public `/healthz` endpoint returned `200`.
2. I changed that sandbox to literal `deny-all`.
3. The active sandbox, its current session, and a separately fetched handle all returned `deny-all` for the original session ID.
4. A new request to the same public endpoint received no response and failed with `EAI_AGAIN` in 36 ms. This is a corroborating negative control, not the core proof.
5. With the exact `deny-all` readbacks still active, the sandbox sent `PUT /latest/api/token` to `169.254.169.254` and received `200`.
6. Using the fresh token only in guest memory, it sent authenticated `GET /` and again received `200`.

The exact same-session `deny-all` readbacks followed by the successful token and authenticated request are the core proof. The MMDS root was empty and no secret was found. The PoC retained no response bodies, token value or token digest, command output bodies, or sensitive response digests.

## Expected versus actual behavior

Literal `deny-all` should prevent hostile sandbox code from reaching network destinations, including link-local services. The challenge policy explicitly treats MMDS content reached under `deny-all` or CIDR deny as firewall impact.

Actual result on one Vercel session:

| Stage | Policy | Request or check | Result |
| --- | --- | --- | --- |
| Positive control | `allow-all` | `GET https://vsc-h3-action-swve.cyrus-206.workers.dev/healthz` | `200` in 112 ms |
| Policy transition | `deny-all` | Active and separately fetched policy/session readback | Four exact `deny-all` values; same session ID |
| Corroborating negative control | `deny-all` | Fresh request to the same owned `/healthz` endpoint | No response; `EAI_AGAIN` in 36 ms; not a timeout |
| MMDS token | `deny-all` | `PUT http://169.254.169.254/latest/api/token` | `200` |
| Authenticated MMDS | `deny-all` | Token-authenticated `GET http://169.254.169.254/` | `200` |

The public control and MMDS requests ran sequentially in one non-persistent sandbox. There was no resume, snapshot, second sandbox, retry loop, scan, or policy change between the exact `deny-all` readbacks and the successful MMDS exchange.

## Reproduction

The attached `SBX-020-reproduction.zip` contains the controller, fixed guest probes, discovery rules, focused tests, dependency lockfile, and body-free live evidence.

Use a fresh Vercel account you own. Challenge researchers should use the required HackerOne alias. The bundle allows Vercel triage to declare its own expected account identity without changing the probe:

```sh
unzip SBX-020-reproduction.zip
cd SBX-020-reproduction
npm ci

export VERCEL_TOKEN='<token for the owned test account>'
export VERCEL_TEAM_ID='<team_...>'
export VERCEL_PROJECT_ID='<prj_...>'
export SBX020_EXPECTED_ALIAS_EMAIL='<email on that Vercel account>'
export SBX020_EXPECTED_TEAM_ID="$VERCEL_TEAM_ID"
export SBX020_EXPECTED_PROJECT_ID="$VERCEL_PROJECT_ID"

npx tsx pocs/SBX-020/deny-all-mmds-differential.ts
```

The primary controller performs these actions once:

- creates a fresh non-persistent sandbox with literal `allow-all`;
- checks the owned public endpoint;
- updates the same sandbox to literal `deny-all`;
- verifies policy and session identity through active and separately fetched handles;
- requires a fresh, non-timeout block against the public endpoint;
- only then runs the fixed, bounded MMDS probe;
- stops and deletes the sandbox in `finally`; and
- writes a mode-`0600`, body-free evidence artifact.

A conclusive run ends with:

```json
{
  "assessment": {
    "outcome": "candidate",
    "candidate": true,
    "rationale": "literal deny-all blocked an owned public endpoint but allowed MMDS token and authenticated root responses"
  },
  "controls": {
    "initialAllowAllReadbackPassed": true,
    "allowHealthPassed": true,
    "denyHealthActivelyBlocked": true,
    "mmdsToken200": true,
    "mmdsAuthenticatedRoot200": true
  },
  "retention": {
    "responseBodies": false,
    "tokenBodyOrDigest": false,
    "sensitiveResponseDigests": false,
    "commandOutputBodies": false
  },
  "cleanup": {
    "stopped": true,
    "deleted": true,
    "errors": []
  }
}
```

## Primary live evidence

I personally executed this live reproduction on the required HackerOne-alias account:

- Run ID: `879e4f77-5f39-4ff9-923c-001648578c95`
- Sandbox/session ID: `sbx_VgoUgV3x73XRCmj73Eri7gXhuX73`
- Completed: `2026-08-19T04:50:35.391Z`
- Policy proof: active sandbox, active session, independently fetched sandbox, and independently fetched session all returned literal `deny-all` for the original session ID
- Public allow control: `200`, 112 ms
- Public deny control: no response, `EAI_AGAIN`, 36 ms
- MMDS result under `deny-all`: token `PUT` returned `200`; later authenticated root `GET` returned `200`
- MMDS request count: 5 sequential requests, bounded to no more than 5 requests per second
- Cleanup: stop and delete succeeded with no errors; a post-run list found no remaining sandbox
- Evidence: `evidence/SBX-020-differential-879e4f77-5f39-4ff9-923c-001648578c95-private.json`
- Evidence SHA-256: `07a3c29e761ca2a1bb3b4177bf7b2128c31be4c3527520ee90ce18e05018a456`

The artifact contains no Vercel token, response body, MMDS token or digest, command output body, or sensitive response digest.

Two additional fresh sandboxes reproduced the same MMDS token and authenticated-root reachability while `subnets.deny` explicitly contained `169.254.0.0/16`. Those corroborating artifacts are included in the bundle:

| Run ID | Sandbox ID | Policy | Result | Cleanup |
| --- | --- | --- | --- | --- |
| `48316112-a918-4f9b-a1b8-1158155e56b0` | `sbx_MlOOawAvQv5bqZpGyGJoEy3YVmuH` | Empty allowlist plus explicit `169.254.0.0/16` and private-range denies | Token `200`; authenticated root `200` | stopped and deleted |
| `e81ffa11-2980-4f84-a6d3-c3b0941299f2` | `sbx_jhp7fPrGxbEiC55a5XaVb1whIllE` | Same | Token `200`; authenticated root `200` | stopped and deleted |

These are supporting variants of the same apparent MMDS firewall exemption, not separate vulnerability claims.

## Root cause

The observed behavior is consistent with VMM-local MMDS traffic being intercepted or routed outside the host-side network-policy enforcement path. That implementation detail is an inference. The live result itself is direct: the same session reported literal `deny-all` through active and independently fetched handles, then completed an authenticated MMDS exchange.

## Scope and nonclaims

This report does not rely on a container namespace escape, the known vsock `2050` service, a known credential-brokering header leak, a third-party reflector, or a public component CVE. It reports server-side enforcement, not an SDK bug.

I do not claim:

- populated MMDS content or any credential/secret disclosure;
- retrieval of Datadog, IAM, brokered, or other secrets;
- access to the EC2 host OS;
- cross-tenant access or denial of service; or
- traffic to any account, sandbox, or application endpoint I do not own.

## Impact and severity rationale

A hostile workload can communicate with an authenticated host/VMM metadata service even while the operator's active policy is literal `deny-all`. This leaves MMDS exposure dependent on whether the platform-populated document happens to be empty rather than on the operator's firewall posture.

The demonstrated impact matches the program's Medium category: a sandbox firewall boundary violation without secret exfiltration. High would require populated MMDS secret disclosure. This run found an empty authenticated root and retained no secret, so I am not requesting High.

## Suggested remediation

Apply `deny-all` and `subnets.deny` before MMDS interception or local-service routing. If a platform feature requires MMDS access, expose that as an explicit policy exception rather than silently exempting it. Add a regression test that confirms `PUT /latest/api/token` and authenticated MMDS requests both fail after a same-session `allow-all` to `deny-all` transition whose public negative control also fails.
