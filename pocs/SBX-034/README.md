# SBX-034 — host-side `forwardURL` redirect credential leak

Status: **implemented and tested locally; not live-run**.

## The exploit question

The sandbox sends one HTTPS request to owned origin A with redirect handling set
to `manual`. Vercel's host-side firewall forwards that request to an A receiver
and injects a signed Sandbox OIDC token. The A receiver verifies the request and
returns an HTTP 307 to distinct owned origin B.

If Vercel's internal forwarding client follows the 307 and carries the injected
token to B, B independently verifies the token's RS256 signature, Vercel issuer,
JWKS, audience, temporal claims, and exact team/project/sandbox identity. The
guest never follows the redirect and direct guest access to B must be blocked
immediately before and after the attack request.

Outcome classification:

- no B request: pass;
- exactly one attributable B request without a valid platform token: Medium
  candidate (misrouting only);
- exactly one attributable B request with one independently verified platform
  token and exact claims: High candidate;
- any failed policy, session, manual-redirect, direct-block, or cleanup control:
  indeterminate/error.

## Files

- `receiver.ts`: two local HTTP roles intended to sit behind two owned HTTPS
  tunnels. A uses the official `defineSandboxProxy`; B verifies OIDC independently.
- `forwardurl-redirect.ts`: bounded five-request Vercel controller. It is not run
  by tests.
- `verdict.ts`: fail-closed severity engine.
- `../../guest/forwardurl-redirect-probe.mjs`: one-shot manual/no-follow guest.

## Local verification only

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
npx vitest run test/sbx-034-forwardurl-redirect.test.ts test/sbx-034-receiver.test.ts
node --check guest/forwardurl-redirect-probe.mjs
npx tsc --noEmit --strict --exactOptionalPropertyTypes \
  --target ES2022 --module NodeNext --moduleResolution NodeNext \
  --types node --skipLibCheck \
  pocs/SBX-034/receiver.ts pocs/SBX-034/verdict.ts \
  pocs/SBX-034/forwardurl-redirect.ts
```

These commands perform no Vercel or public-endpoint requests.

## Future live prerequisites

Do not run the controller until two distinct researcher-owned HTTPS origins are
connected to the receiver's A and B ports. The receiver requires:

```sh
SBX034_ADMIN_KEY='<random 32+ character value>' \
SBX034_A_PUBLIC_ORIGIN='https://<owned-a-host>' \
SBX034_B_PUBLIC_ORIGIN='https://<owned-b-host>' \
npx tsx pocs/SBX-034/receiver.ts
```

The controller additionally requires the exact scope phrase shown in its source,
the verified HackerOne-alias Vercel credentials, and the same three receiver
variables. It holds a fixed live lock, creates one nonpersistent sandbox, makes
five sequential guest requests, and stops/deletes the sandbox and receiver state.

No raw OIDC token or token digest is logged, returned, or stored. Only the
independent verification result, public claims, and an opaque operation ID enter
the private artifact.
