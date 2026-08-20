# SBX-049: query matcher key/value association

Status: local packet only. Do not submit or describe as a finding unless one bounded live run produces `candidate-high` with all controls and cleanup green.

## Why this is distinct from SBX-014

The current Vercel firewall documentation says that multiple `queryString` entries are ANDed, that query names and values are case-sensitive, and that *multiple values for the same key* use any-matching-value semantics. The installed `@vercel/sandbox@3.0.0` type is likewise one `NetworkPolicyKeyValueMatcher` object containing its own optional `key` and `value` matchers.

SBX-014 covered the documented duplicate-value behavior for one key plus encoding variants. SBX-049 asks a different question: can the matcher detach the key half from the value half inside one matcher entry and satisfy them from two different query parameters?

The exact rule is:

```ts
{
  allow: {
    "<owned-host>": [{
      match: {
        queryString: [{
          key: { exact: "role" },
          value: { exact: "privileged" }
        }]
      },
      transform: [{
        headers: { "x-sbx049-brokered-secret": "<controller-only-secret>" }
      }]
    }]
  }
}
```

The four fresh, sequential requests are:

| Case | Query data | Expected transform |
| --- | --- | --- |
| `exact-pair` | `role=privileged` | yes; proves the rule and secret transform work |
| `key-half` | `role=user` | no |
| `value-half` | `decoy=privileged` | no |
| `combined-halves` | `role=user&decoy=privileged` | no |

Only the last request is decisive. A candidate requires both isolated halves to remain negative while `combined-halves` receives the exact controller-only secret. The receiver validates that secret through a keyed commitment and returns an opaque HMAC operation ID; it retains neither the secret nor a plain digest. Exact active and independently fetched same-session policy readbacks are required before and after the matrix. The ledger must contain exactly the four events above in that order, with no extras. Sandbox stop/delete/two absence checks and receiver delete/absence are global verdict gates.

The current session API projects the transform and redacted header name but omits the configured request matcher. The controller requires that exact projection, then proves matcher enforcement behaviorally: `exact-pair` must broker and both isolated halves must remain unbrokered. If creation simply dropped the matcher, those half-controls would fail and a candidate would be impossible.

Impact is High-capable under the supplied bounty table only if that exact secret proof succeeds: it would demonstrate credential exfiltration across the L7 firewall matcher boundary. Ordinary reachability to the explicitly allowed owned host is not a finding.

References:

- Vercel Sandbox firewall, request matching: <https://vercel.com/docs/vercel-sandbox/concepts/firewall#request-matching>
- Installed SDK type: `node_modules/@vercel/sandbox/dist/network-policy.d.ts`
- SBX-014 disposition: `notes/LIVE_RUN_2026-08-18.md`

## Local verification

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
npx vitest run test/sbx-049-protocol.test.ts test/sbx-049-guest.test.ts test/sbx-049-receiver.test.ts test/sbx-049-verdict.test.ts
node --check guest/query-entry-binding-probe.mjs
./node_modules/.bin/tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --types node --skipLibCheck pocs/SBX-049/*.ts test/sbx-049-*.test.ts
```

## One bounded live run

This needs one fresh researcher-owned Quick Tunnel and three terminals. Do not overlap another live sandbox test.

Terminal 1:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
cloudflared tunnel --no-autoupdate --loglevel info --url http://127.0.0.1:43149
```

Copy its exact lower-case `https://…trycloudflare.com` origin as `https://<OWNED>.trycloudflare.com` below. Generate two distinct keys locally with `openssl rand -hex 32`; reuse the same values in Terminals 2 and 3, and never paste them into chat or commit them.

Terminal 2:

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
export SBX049_ADMIN_KEY='<FRESH_ADMIN_64_HEX>'
export SBX049_ACTION_KEY='<FRESH_ACTION_64_HEX>'
export SBX049_PUBLIC_ORIGIN='https://<OWNED>.trycloudflare.com'
export SBX049_PORT=43149
npx tsx pocs/SBX-049/receiver.ts
```

Wait for `{"ready":true,"port":43149}` and verify the tunnel health URL returns the SBX-049 test identity.

Terminal 3 (the single live controller command):

```sh
cd "/Users/coler/Documents/ChatGPT/vercel hack/vercel-security-challenge"
task_vercel_token=$(node --input-type=module -e 'import { getAuth } from "./node_modules/@vercel/sandbox/dist/auth/file.js"; const auth=getAuth(); if(!auth?.token)process.exit(2); process.stdout.write(auth.token)')
VERCEL_TOKEN="$task_vercel_token" \
VERCEL_TEAM_ID='team_n98ERpVwV7HqmWRudAyK8sXQ' \
VERCEL_PROJECT_ID='prj_CyyVykdN06Nrkla6KidZcecLgbCa' \
SBX049_ALIAS_EMAIL_CONFIRMATION='swve@wearehackerone.com' \
SBX049_SCOPE_CONFIRMATION='I_CONTROL_SBX049_ORIGIN_AND_AUTHORIZE_BOUNDED_QUERY_MATCHER_TESTING' \
SBX049_PUBLIC_ORIGIN='https://<OWNED>.trycloudflare.com' \
SBX049_ADMIN_KEY='<SAME_ADMIN_64_HEX>' \
SBX049_ACTION_KEY='<SAME_ACTION_64_HEX>' \
DOTENV_CONFIG_PATH=.env.local \
npx tsx pocs/SBX-049/query-entry-binding.ts
task_sbx049_status=$?
unset task_vercel_token
printf 'SBX-049 exit status: %s\n' "$task_sbx049_status"
```

Read the JSON `assessment`, not the exit status alone. Stop the receiver and tunnel after the controller has completed its receiver absence check.
