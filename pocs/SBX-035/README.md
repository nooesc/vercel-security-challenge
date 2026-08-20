# SBX-035 WebSocket live-policy revocation

This single-sandbox test asks whether a WebSocket opened to an owned endpoint while allowed remains usable after the same session is changed to literal `deny-all`.

The candidate gate is intentionally narrow:

1. strict TLS to one pinned public IPv4/SNI, an exact WebSocket `101`, and an HMAC-backed public pre-canary receipt;
2. active and independent same-session `deny-all` readbacks;
3. fresh HTTPS and fresh WSS attempts to that same pinned IPv4/SNI both fail actively before TLS, without a response or timeout;
4. only then, a fresh synthetic operator secret is created, registered with the local receiver only as an HMAC commitment, written mode `0600`, and sent once on the original socket;
5. the receiver returns an opaque HMAC operation ID without reflecting or storing the secret.

A matching receipt is a High candidate under the challenge table (firewall bypass with demonstrated synthetic data exfiltration). A stateless public Worker is insufficient for this timing proof; the controller instead starts a short-lived in-memory receiver on `127.0.0.1:8788`, reached through one fresh Quick Tunnel.

## Prerequisites

Start a fresh tunnel in another terminal and leave it running for exactly one attempt:

```sh
cloudflared tunnel --url http://127.0.0.1:8788 --no-autoupdate
```

Copy its `https://...trycloudflare.com` origin, resolve one current public IPv4 immediately before the run, and execute:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"

export SBX035_SCOPE_CONFIRMATION='I_CONTROL_THE_WSS_ORIGIN_AND_AUTHORIZE_ONE_SYNTHETIC_SECRET_SEND'
export SBX035_ENDPOINT_ORIGIN='https://REPLACE.trycloudflare.com'
export SBX035_PINNED_IPV4='REPLACE_WITH_ONE_CURRENT_A_RECORD'
export SBX035_RECEIVER_PORT='8788'
export SBX035_RECEIVER_KEY="$(openssl rand -hex 32)"
export VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ'
export VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa'
export VERCEL_TOKEN="$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')"

npx tsx pocs/SBX-035/websocket-live-revocation.ts
```

Stop the Quick Tunnel after the controller finishes. The controller always attempts to overwrite the guest secret file, stop/delete the sandbox, clear the receiver run, and close the local receiver. Its sanitized evidence file is mode `0600` under ignored `artifacts/`; it contains no raw operator secret, secret digest, guest configuration, command output, or WebSocket frame.

Focused local verification:

```sh
npx vitest run test/sbx-035-websocket-revocation.test.ts
```
