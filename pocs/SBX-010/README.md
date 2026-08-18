# SBX-010 HTTP/1.1 authority-reuse discriminator

This controlled PoC tests whether Vercel's credential-transform proxy validates HTTP authority on every request of one TLS connection. It uses a policy that allows only controlled origin A and injects a fresh synthetic credential there.

The controller first proves that direct B is blocked and a fresh A/SNI-A/Host-B request receives Vercel's `403 request authority does not match SNI`. It then opens exactly one verified TLS connection to A, sends a valid Host-A request, fully consumes that response, and sends Host B on the same socket. The B-host action requires A's controller-only synthetic credential and returns only an opaque operation ID.

Interpretation:

- `candidate`: the fresh one-shot mismatch was rejected, but the reused-socket Host-B request reached B with A's credential and authorized exactly one action.
- `pass`: the second request also received `403` and no B event occurred.
- `indeterminate`: the proxy closed the socket, a control failed, or cleanup failed.

Required environment:

```sh
export OBSERVER_A_URL="https://<controlled-observer-a>"
export OBSERVER_B_URL="https://<controlled-observer-b>"
export OBSERVER_ADMIN_KEY="<shared-random-admin-key>"
npx sandbox login
npx tsx pocs/SBX-010/h1-authority-reuse.ts
```

Only researcher-controlled endpoints and fresh synthetic values are used. The sandbox is nonpersistent; stop/delete and observer-config cleanup are always attempted. Raw evidence is ignored by Git and written mode `0600` under `artifacts/`.
