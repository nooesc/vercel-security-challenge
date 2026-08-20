# SBX-041 TLS 1.2 session-bound authorization confusion

This bounded harness tests whether authorization or credential-transform state for allowed origin A is incorrectly reused on a fresh TLS 1.2 connection that sends `Host: B` over A's reachable transport. It runs matched pairs both with client-configured SNI B and with SNI omitted:

1. A-transport/SNI-B/Host-B without a session (must not reach B).
2. The same route after offering an authenticated A session.
3. A-transport/no-SNI/Host-B without a session (must not reach B).
4. The same route after offering an authenticated A session.

Node/OpenSSL may omit SNI on the wire during TLS 1.2 resumption even when the client configured `servername: B`; the local integration test records server-side SNI and the evidence distinguishes configured SNI from identity and transport hosts. Do not describe ticket reuse alone as a vulnerability.

Proof gates:

- A and B are distinct researcher-owned HTTPS origins backed by different receiver ports.
- Before a sandbox is created, outside-sandbox probes prove both A-transport routes, A's certificate validity for B, and cross-host TLS 1.2 resumption.
- Direct B is blocked before and after, and both matched no-session controls produce no B event.
- Active and independent pre/post readbacks show one exact transformed allow rule for A on the same session.
- Every A/B request has one exact raw `Host`, correlation canary, bounded event count, and deterministic operation ID.
- The guest never receives the transform value or raw TLS session. Only digests and an opaque operation ID are retained.
- Seven guest cases run sequentially with a 350 ms minimum inter-case delay, no retries, at most nine connection attempts, and at most seven HTTP requests.

Verdicts:

- `candidate-high`: a session variant reaches denied B and B receives the exact non-reflected A-only brokered secret.
- `candidate-medium`: a correlated session-only request reaches B without the brokered secret.
- `pass`: both session variants and both no-session controls are blocked before B receives HTTP.
- `indeterminate`: ticket reuse alone, a no-session control reach, unsuitable identity, or incomplete/ambiguous evidence.

## Endpoint prerequisites

Run one receiver and expose its two ports through two fresh Quick Tunnels:

```sh
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43141
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43142
```

Use the first exact lower-case `https://...trycloudflare.com` origin as A and the second as B:

```sh
export SBX041_ADMIN_KEY="$(openssl rand -hex 32)"
export SBX041_A_PUBLIC_ORIGIN="https://<A>.trycloudflare.com"
export SBX041_B_PUBLIC_ORIGIN="https://<B>.trycloudflare.com"
npx tsx pocs/SBX-041/receiver.ts
```

After both health endpoints work, run only under the verified HackerOne-alias account:

```sh
SBX041_SCOPE_CONFIRMATION=I_CONTROL_BOTH_SBX041_ORIGINS_AND_AUTHORIZE_BOUNDED_TLS_RESUMPTION_TESTING \
SBX041_ALIAS_EMAIL_CONFIRMATION=swve@wearehackerone.com \
SBX041_ADMIN_KEY="$SBX041_ADMIN_KEY" \
SBX041_A_PUBLIC_ORIGIN="$SBX041_A_PUBLIC_ORIGIN" \
SBX041_B_PUBLIC_ORIGIN="$SBX041_B_PUBLIC_ORIGIN" \
VERCEL_TOKEN="$VERCEL_TOKEN" \
VERCEL_TEAM_ID=team_n98ERpVwV7HqmWRudAyK8sXQ \
VERCEL_PROJECT_ID=prj_CyyVykdN06Nrkla6KidZcecLgbCa \
npx tsx pocs/SBX-041/tls-session-resumption.ts
```

The controller writes one mode-0600 private artifact and always attempts sandbox deletion/absence verification and receiver-state deletion. No live run is justified unless every outside-sandbox topology preflight passes.
