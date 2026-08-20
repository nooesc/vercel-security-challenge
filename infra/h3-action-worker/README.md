# Controlled HMAC action Worker

This temporary Worker provides the researcher-owned action endpoint used by the SBX-017 HTTP/3 and SBX-031 ECH discriminators. It accepts only a bounded `GET /v1/h3-action` request and returns an opaque HMAC-derived operation ID. The correlation canary is not echoed or logged by the Worker. Platform observability is disabled in `wrangler.jsonc` so request query strings are not intentionally retained through Worker logs.

`H3_ACTION_KEY` is declared as a required secret and must be set with Wrangler; never commit it. The controller gets the same synthetic value but does not place it in guest configuration.

Validation and deployment:

```sh
npm ci
npm run types
npm run check
npx wrangler secret put H3_ACTION_KEY
npx wrangler deploy
```

Delete the temporary Worker after evidence capture:

```sh
npx wrangler delete --name vsc-h3-action-swve
```

## SBX-032 two-host setup

The `sbx032_allowed` and `sbx032_denied` Wrangler environments create two distinct owned `workers.dev` hostnames with identical code and no shared request state:

```text
https://vsc-tls-allow-swve.cyrus-206.workers.dev
https://vsc-tls-deny-swve.cyrus-206.workers.dev
```

Use one fresh controller-only key for both. Keep it only in the current shell and Cloudflare's encrypted secret bindings:

```sh
task_sbx032_key=$(openssl rand -base64 48)
printf '%s' "$task_sbx032_key" | npx wrangler secret put H3_ACTION_KEY --env sbx032_allowed
printf '%s' "$task_sbx032_key" | npx wrangler secret put H3_ACTION_KEY --env sbx032_denied
npx wrangler deploy --env sbx032_allowed
npx wrangler deploy --env sbx032_denied
```

After the bounded Vercel runs and evidence review, delete only these temporary Workers:

```sh
npx wrangler delete --name vsc-tls-allow-swve
npx wrangler delete --name vsc-tls-deny-swve
unset task_sbx032_key
```
