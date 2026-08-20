# High-impact local backlog audit — 2026-08-18

This note ranks the next bounded High-impact Sandbox hypotheses after `SBX-013`. It is an internal routing document, not a report and not evidence that any vulnerability exists.

## Constraints applied

- One fresh alias-owned sandbox per live packet; only owned endpoints and synthetic data.
- No second-account dependency, cross-tenant probing, crash, resource pressure, fuzzing, or DoS.
- No live testing was performed during this audit.
- Exclude known container/vsock primitives, the `SBX-031` ECH semantics hold, and root causes already closed by conclusive negative controls.
- A High candidate requires exact proof that fresh file-backed synthetic operator data reached an unauthorized controlled destination. Reachability alone is Medium at most.
- One report per root cause. Variants that exercise the same failed enforcement decision are supporting evidence, not separate submissions.

## Ranked candidates

### 1. `SBX-021`: explicit `/32` deny loses to a domain allow

**Why first:** current Vercel guidance states that denied CIDRs take precedence over allowed domains and CIDRs. The existing owned Worker currently exposes two public IPv4 edges, so the comparison is deterministic, low request count, and needs no DNS mutation or new infrastructure.

**Root cause if positive:** the host firewall authorizes TLS by SNI but fails to apply the explicit destination-address deny to the same connection.

**Minimum proof bar:**

1. The endpoint hostname's current A set contains distinct `T` and `S` addresses selected before sandbox creation.
2. Under exact `{allow:[hostname]}`, a verified HTTPS request pinned to `T` returns the expected HMAC operation ID for a public canary.
3. The same `sbx_…` session updates to exact `{allow:[hostname],subnets:{deny:[T/32]}}`; both active and independent non-resuming handles return that policy and the original session ID.
4. A verified request pinned to non-denied `S` still returns the expected public-canary operation ID.
5. Only then does the `T` target read a fresh mode-`0600` secret file. Candidate requires verified TLS whose peer address is exactly `T` and the exact controller-derived HMAC operation ID. The raw secret must not appear in guest configuration, output, or evidence.
6. Stop and delete succeed.

**Severity discipline:** this meets the program's High wording literally if an explicitly denied IP is treated as an unauthorized data destination. The current Cloudflare `T` and `S` paths terminate at the same logical Worker, so a positive discovery run should be reproduced with separately controlled `S` and `T` receivers behind one certificate/hostname before making an unqualified High claim. Without a distinct denied recipient, present the maximum demonstrated impact conservatively and let triage assign severity.

**Consolidation:** DNS rotation, CNAME, Happy Eyeballs, and address-order variants caused by the same missing deny-precedence check belong in this report. `SBX-006` remains distinct because it tests alternate IP representation parsing.

**Local status:** isolated packet and tests implemented under `pocs/SBX-021/`, `guest/fixed-ip-deny-probe.py`, and `test/sbx-021-explicit-deny-high.test.mjs`. No live run.

### 2. `SBX-032`: TLS ClientHello stream/record reassembly fail-open

**Why second:** domain enforcement depends on parsing cleartext SNI. TCP may split bytes arbitrarily, and TLS permits a handshake message to span records. A parser that treats an incomplete ClientHello as uninspectable-but-allowed could send operator data to a clearly denied hostname. This is semantically distinct from ECH: the denied hostname is present in cleartext and the defect would be reassembly, not encrypted-name policy.

**Root cause if positive:** the host SNI parser fails open when a valid ClientHello's `server_name` bytes span TCP writes or TLS handshake records.

**Minimum proof bar:**

1. Use Python `SSLObject` plus `MemoryBIO` to generate a genuine ClientHello for owned denied hostname `B`; do not hand-build a partial approximation.
2. Prove under `allow-all` that ordinary, TCP-segmented, and two-record ClientHellos for `B` all complete strict certificate/hostname verification and execute public-canary actions.
3. Rewrite only record framing: two content-type-22 records whose concatenated handshake payload is byte-for-byte identical to the original, split inside or immediately before the SNI hostname. Record the original/reassembled hashes, not raw ClientHello bytes.
4. Under exact `{allow:[A]}`, prove a fragmented request to owned `A` succeeds and an ordinary fresh request to `B` is actively blocked.
5. On one fresh connection, send the record-fragmented `B` variant whose HTTP action reads the fixed operator-secret file. Candidate requires strict TLS to `B`, peer-IP attribution, and `B`'s exact non-reflecting HMAC operation ID.
6. Stop at the first success and clean up.

**Consolidation:** TCP segmentation and TLS-record fragmentation should be one report if they fail through the same reassembly state machine. Prefer the standards-valid TLS-record split as primary evidence; TCP write boundaries alone are weaker because the wire may coalesce them.

**Local status:** being implemented independently under `SBX-032`; no live run during this audit.

### 3. `SBX-001`: authoritative DNS exfiltration under literal `deny-all`

**Why third:** Vercel currently states that `deny-all` blocks DNS resolution. The earlier `CONTROL-DENY` run saw a guest DNS/HTTP failure, but it did not have authoritative DNS telemetry, so it cannot exclude a query leaving the sandbox while the reply is suppressed. This is cheap to close once an owned authoritative observer is available.

**Root cause if positive:** DNS interception returns a local failure but forwards or recursively resolves a denied query, creating a one-way exfiltration channel.

**Minimum proof bar:**

1. Use an owned authoritative zone and a non-reflecting observer that processes query names in memory, records only an opaque HMAC action, and never persists raw secret labels.
2. Under `allow-all`, a fresh random public-control FQDN must reach the authoritative server with exact run/case attribution.
3. Update the same session to literal `deny-all`; active and independent readbacks must agree and retain the same session ID.
4. Send one fresh public-control query. If it is not observed, stop and record a pass. If it is observed, send exactly one target query carrying a fresh mode-`0600` synthetic operator secret in bounded base32 labels.
5. Candidate requires the authoritative observer's exact HMAC operation ID for that secret. A guest resolver error, local DNS packet, cache hit, timing change, or reply without authoritative receipt is not a candidate.
6. Cap DNS actions below five per second and always stop/delete the sandbox.

**Severity discipline:** externally observable public canary traffic is a Medium policy violation at most. High requires the exact file-backed operator-data proof. All record types and encoding variants sharing one DNS fail-open belong in one report.

## Lanes deliberately deprioritized

- `SBX-018` retained sockets: five hardened alias-account runs blocked all 15 sockets after `deny-all`.
- TLS 1.3 resumption/0-RTT after revocation: plausible, but it is lifecycle-adjacent to `SBX-018` and lower-signal than the three packets above.
- `SBX-017` HTTP/3: the exact same-IP `deny-all` control was negative.
- `SBX-020` MMDS: token issuance with an authenticated empty root is supporting reachability only; no populated secret exists to prove High impact.
- HTTP/1 and HTTP/2 authority reuse: fresh and reused mismatches were rejected.
- WebSocket/CONNECT through an operator-allowed proxy: tunneling by a destination the operator explicitly allowed is not by itself a firewall bypass.
- Sandbox control-plane authorization and snapshot ownership: convincing cross-tenant impact requires a second owned account under the program rules.
- Host/VMM crash, resource pressure, stale-block cross-tenant reads, and device fuzzing: excluded by this audit's non-destructive and single-account constraints.

## Primary references

- [Vercel Sandbox firewall](https://vercel.com/docs/vercel-sandbox/concepts/firewall)
- [Advanced egress firewall filtering for Vercel Sandbox](https://vercel.com/changelog/advanced-egress-firewall-filtering-for-vercel-sandbox)
- [Vercel Sandbox versus CodeSandbox](https://vercel.com/kb/guide/vercel-sandbox-vs-codesandbox)
- Local HackerOne policy: `notes/HACKERONE_PROGRAM_POLICY.md`
