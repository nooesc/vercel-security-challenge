# FLAGS-001: Cross-group replay of signed precompute codes changes flag values

## Summary

The `flags` package signs only the compact serialized value bytes. The signature does not bind the token to flag keys, option values or ordering, the flag group, or the route that created it. Applications normally use one `FLAGS_SECRET` for every group, and the official documentation supports multiple groups.

A valid code issued for one group can therefore be supplied to a route that deserializes a different group. The same signed option indices are reinterpreted using the second group's definitions. The attacker neither learns the secret nor forges a signature.

## Affected code

`packages/flags/src/lib/serialization.ts`:

- `serialize()` signs the matched indices plus optional spilled JSON values.
- No group identifier or definition digest is included in the signed payload.
- `deserialize()` verifies the signature and interprets the payload using the caller-provided `flags` array.

Both `flags/next` and `flags/sveltekit` use these shared functions.

## Reproduction

Run the test in `pocs/FLAGS-001/cross-group-replay.security.test.ts` from a `vercel/flags` checkout by placing it under `packages/flags/src/lib/`, then execute:

```sh
pnpm --filter flags test src/lib/cross-group-replay.security.test.ts
```

Observed result: one test passes. A legitimate token representing public flag `theme = "dark"` at option index 1 is accepted by a second group and becomes `admin-preview = true`, also option index 1.

## Attack flow

1. An application configures at least two precompute groups under the application-wide `FLAGS_SECRET`.
2. The attacker obtains a legitimate code generated for a public route. These codes are transported in URL path segments.
3. The attacker supplies it in another code segment whose route deserializes a different, compatible flag array.
4. Signature verification succeeds because the code is authentic.
5. The target route renders a flag variant the attacker was never assigned.

With on-demand ISR, the substituted interpretation may also be generated and cached at the attacker-selected signed URL.

## Suggested remediation

Bind signatures to a canonical, versioned digest of the intended group, including every flag key and its ordered option values. Recompute and verify that digest before interpreting the compact indices. An explicit group or route audience can provide additional domain separation.

## Classification

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-294: Authentication Bypass by Capture-replay

