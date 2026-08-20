# Vercel Sandbox: 30 exploit hypotheses and test cases

Last updated: 2026-08-19

## Model and proof bar

The security boundary is the Firecracker microVM plus the host-enforced network layer. Root in the Linux container, escape into the guest OS, and full control of the guest kernel are assumed. A report needs a live boundary break, not only a source-level defect.

Use only researcher-owned sandboxes, domains, IPs, proxy endpoints, credentials, and paired "attacker/victim" resources. Stop at the minimum proof. For host/link-local probes, demonstrate reachability with a harmless request and do not retain real platform credentials or tenant data.

Priority legend:

- **P0:** Cheap, high-signal network or credential-boundary test.
- **P1:** Requires a custom endpoint, two sandboxes, lifecycle manipulation, or protocol tooling.
- **P2:** Kernel/VMM fuzzing or resource-intensive work.

## Hypothesis matrix

| ID | Priority | Hypothesis | Controlled test | Boundary-breaking success signal |
| --- | --- | --- | --- | --- |
| SBX-001 | P0 | `deny-all` still permits externally observable DNS queries. | Point a unique subdomain at a researcher-owned authoritative DNS server. From a `deny-all` sandbox, request A, AAAA, TXT, and deliberately nonexistent names carrying unique markers. | The authoritative server receives a query or any reply reaches the guest despite `deny-all`. |
| SBX-002 | P0 | A domain allowlist validates only the original name and follows a CNAME to an unauthorized destination. | Allow `allowed.research.test`, configure it as a CNAME to `blocked.research.test`, and deny the blocked server's CIDR. | A TCP/TLS connection reaches the blocked controlled server. |
| SBX-003 | P0 | DNS rebinding creates a time-of-check/time-of-use gap between policy evaluation and connection routing. | Make one allowed hostname alternate between two controlled IPs; explicitly deny one CIDR. Exercise low TTLs, concurrent connects, and connection retries. | Traffic arrives at the denied controlled IP. |
| SBX-004 | P0 | Hostname canonicalization differs across DNS, SNI, and policy matching. | Test case, a trailing dot, repeated dots, percent escapes where accepted, IDNA A-label/U-label pairs, and normalized Unicode against one controlled domain. | A spelling not covered by the allow rule reaches the endpoint, or a denied spelling is treated as allowed. |
| SBX-005 | Closed negative | Wildcard matching crosses label boundaries or matches the apex/sibling suffix. SBX-044 is the executable, contract-aware refinement of this same root cause; it is not a separate report. | Live run `b5085200-7760-4b25-ba40-1caadb385a54` tested the documented middle-label pattern `s44a.*.form-app.app` against controlled A `s44a.one.form-app.app` and deeper B `s44a.one.two.form-app.app`. | No finding: A succeeded before/after; B failed pre-connect with exact `EAI_AGAIN/getaddrinfo/-3001` and recorded zero event; all keyed controls, policy readbacks, and cleanup passed. |
| SBX-006 | P0 | Denied CIDRs can be bypassed with alternative IP representations. | Deny a controlled IPv4/IPv6 range and connect using IPv4-mapped IPv6, compressed IPv6, IPv4-compatible forms, and API-accepted integer/legacy literal forms. | The denied controlled address receives traffic. |
| SBX-007 | P0 | An allowed HTTP origin can redirect the firewall to an unauthorized origin. | Allow controlled origin A and have it return 301/302/307/308 to denied controlled origin B across ports and schemes. | B receives the redirected request. |
| SBX-008 | P0 | TLS SNI and HTTP `Host` are authorized independently, enabling domain-fronting-style policy confusion. | Connect to the allowed controlled TLS endpoint while varying SNI and `Host`/absolute-form authority between allowed and denied controlled names. | The denied virtual host or backend is reached through the allowed connection. |
| SBX-009 | P0 | HTTP/2 `:authority` is not consistently bound to TLS SNI and the policy domain. | Reuse one TLS connection to a controlled multi-origin HTTP/2 server and send streams with different `:authority` values. | A stream for a non-allowed authority succeeds or receives brokered credentials. |
| SBX-010 | P0 | HTTP/1 connection reuse allows a second, unauthorized authority after the first allowed request. | Keep an allowed TLS/TCP connection alive, then send additional requests with changed authority/Host where the controlled server can distinguish them. | The firewall does not re-evaluate the later authority and the unauthorized request succeeds. |
| SBX-011 | P0 | Redirects, retries, or authentication challenges carry injected credentials to a different origin. | Broker a synthetic canary header to controlled origin A; respond with cross-origin redirects and 401/407 challenges toward controlled origin B. | B receives the canary credential or an authorization-derived value. |
| SBX-012 | P0 | Duplicate or differently cased headers defeat the promised overwrite semantics for brokered credentials. | Send duplicate `Authorization`/`authorization` fields, obs-fold-like variants where libraries allow them, comma-joined values, and HTTP/2 lowercase duplicates to a controlled echo endpoint. | The sandbox controls any credential-bearing value, the original canary is exposed unexpectedly, or both values reach the origin in an ambiguous order. |
| SBX-013 | P0 | L7 path matching occurs before a different normalization step. | Configure credential injection only for `/safe/`. Test dot segments, repeated slashes, backslashes, percent-encoded separators/dots, double encoding, semicolon parameters, and empty segments against a controlled echo server. | The canary is injected on a path outside the configured match or withheld on a canonical path that should match in a security-relevant way. |
| SBX-014 | P0 | Query-string matcher ambiguity enables credential injection on a nonmatching request. | Exercise duplicate keys, empty values, `+` versus `%20`, encoded key names, ordering, semicolon separators, and mixed-case encodings. | A request that does not satisfy the configured query predicate receives the canary credential. |
| SBX-015 | P0 | Method matching can be bypassed by normalization or override conventions. | Restrict injection to one method and test method case, extension/custom methods, `HEAD`, `OPTIONS`, `CONNECT`, and common method-override headers/parameters. | A nonmatching effective request gets transformed or forwarded as the privileged method. |
| SBX-016 | P1 | A WebSocket upgrade or HTTP `CONNECT` to an allowed domain becomes a tunnel to unauthorized destinations. | Use a controlled allowed server that offers WebSocket and CONNECT-style proxy behavior, then request a second controlled denied address through the tunnel. | The denied endpoint receives bytes attributable to the sandbox. |
| SBX-017 | P1 | Non-TCP egress is outside enforcement. | Under `deny-all`, send UDP/QUIC datagrams and ICMP echo to researcher-owned endpoints; also test arbitrary UDP ports, not only port 53. | Any controlled external endpoint receives packets. |
| SBX-018 | P1 | Existing sockets survive an `allow-all` to `deny-all` live policy update. | Open long-lived TCP, TLS, HTTP/2, and WebSocket sessions to controlled endpoints; update the sandbox to `deny-all`; send fresh marked data on each connection and create same-destination new connections. | Post-update data leaves on an old socket when the documented policy is expected to take effect immediately. |
| SBX-019 | P1 | DNS answers cached before lockdown remain usable after a policy update and bypass the new rule. | Resolve and connect to a controlled domain under `allow-all`, switch to a restrictive policy, change DNS, and exercise cached-address connection paths with and without keepalive. | A new post-lockdown connection reaches an address not authorized by the new policy. |
| SBX-020 | P1 | Link-local, metadata, host-gateway, or platform service ranges are reachable despite an explicit deny policy. | Under `deny-all` plus explicit private/link-local CIDR denies, probe only harmless paths on the default gateway, common link-local ranges, and metadata-style addresses. Record status/handshake only. | Any host/platform endpoint responds. Do not request or retain real credentials. |
| SBX-021 | P1 | CIDR deny precedence fails when a permitted domain resolves to both allowed and denied addresses. | Give one controlled allowed hostname mixed A/AAAA answers spanning allowed and denied ranges, rotate order, and test Happy Eyeballs behavior. | Any connection lands on the explicitly denied address. |
| SBX-022 | P1 | `forwardURL` OIDC audience normalization permits token replay across proxy routes or deployments. | Configure two researcher-owned proxy paths/origins. Capture only each request's synthetic identity result, then replay a request/token across trailing-slash, nested-path, encoded-path, and alternate deployment URL variants. | A Sandbox OIDC token is accepted at an audience other than the configured forwarding endpoint. |
| SBX-023 | P1 | Forwarded metadata headers can be spoofed or desynchronized from signed claims. | From the guest, pre-set every `vercel-forwarded-*` header while using a controlled forwarding proxy that calls `defineSandboxProxy`. Vary duplicate headers and authority/path combinations. | The proxy handler observes attacker-selected host/path/tenant metadata or an authenticated request inconsistent with token claims. |
| SBX-024 | P1 | A policy-update race leaks a credential during rule replacement. | Continuously issue marked requests to a controlled echo server while rapidly switching between a brokered rule, plain allow rule, and `deny-all`. | A request receives the canary credential or network access during a state where the active policy should forbid it. |
| SBX-025 | P1 | Fork/resume restores a stale or weaker network policy than the sandbox's current configuration. | Create a persistent sandbox, tighten its policy, stop/snapshot/fork/resume it through each supported lifecycle path, and query configuration before sending controlled probes. | A resumed or forked session can use a destination or credential rule removed before the snapshot/fork. |
| SBX-026 | P1 | Snapshot or fork identifiers are not fully scoped to the owning team/project. | With two researcher-owned projects/teams if available, attempt SDK/API `get`, restore, fork, and delete operations using the other project's snapshot/sandbox IDs. | Cross-project content, metadata, mutation, or lifecycle control succeeds. Never use IDs belonging to other researchers. |
| SBX-027 | P1 | Published-port routing can collide across sandbox ID/name reuse or stale routes. | Run two owned sandboxes with distinguishable canary services, stop/delete/recreate/fork them, republish the same ports, and repeatedly query their assigned `vercel.run` routes. | A route returns the other owned sandbox's canary or remains bound to a stopped/reassigned tenant resource. |
| SBX-028 | P2 | Malformed VirtIO network descriptor chains corrupt or crash host-side VMM state. | From the guest OS, use a purpose-built VirtIO-net harness to fuzz descriptor lengths, chaining, indirect descriptors, queue indices, resets, and packet offload metadata while a second owned sandbox monitors isolation. | Firecracker/jailer/host crash, host code execution, or measurable crash of the paired victim sandbox. Guest-only kernel crashes do not count. |
| SBX-029 | P2 | Snapshot restore accepts guest-controlled device/filesystem state that destabilizes Firecracker or exposes stale blocks. | Mutate high-I/O and edge-case filesystem/device state immediately before repeated snapshot/stop/resume/fork cycles; compare owned canaries and session health. | Host/VMM crash, data from another owned sandbox, or cross-sandbox state appears. Ordinary persistence of the source sandbox is expected and not a finding. |
| SBX-030 | P2 | Unbounded guest I/O or memory/device pressure can crash a different sandbox on the same host. | Use an attacker/victim pair owned by us. Stress block flush/writeback, VirtIO queues, balloon/memory pressure, network queue bursts, and reset loops separately while measuring victim liveness. Ramp gradually and stop at the first reproducible cross-sandbox symptom. | The attacker reliably crashes or materially disrupts the victim sandbox; self-DoS alone does not count. |

## Recommended execution order

### Wave 1: baseline and cheap policy bypasses

Run SBX-001 through SBX-015 using two controlled HTTPS origins and one authoritative DNS zone. These tests are fast, deterministic, and directly target the host-side boundary Vercel highlighted.

### Wave 2: stateful protocols and lifecycle

Run SBX-016 through SBX-027. Add a controlled WebSocket/HTTP2 echo service, forwarding proxy, and two researcher-owned projects or sandboxes.

### Wave 3: Firecracker boundary

Only after baseline telemetry is reliable, run SBX-028 through SBX-030. Keep each device class and root cause separate so a report maps to one reproducible failure.

## Initial harness requirements

1. A named attacker sandbox with a short timeout and tags identifying the test ID.
2. A second owned sandbox used only as a victim/liveness canary.
3. Two controlled HTTPS origins on distinct IPs and domains.
4. An authoritative DNS zone with programmable A/AAAA/CNAME answers and query logging.
5. HTTP/1.1, HTTP/2, WebSocket, raw TCP, UDP, and QUIC echo listeners.
6. Separate non-secret correlation canaries and synthetic brokered secrets that never enter the guest before a probe.
7. Timestamped JSONL logging of policy, request, DNS, destination IP, TLS SNI, Host/authority, and observed headers.

## Sources

- Vercel challenge: <https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox>
- Vercel Sandbox documentation: <https://vercel.com/docs/sandbox>
- Vercel network firewall, credential brokering, and proxying announcements:
  - <https://vercel.com/changelog/safely-inject-credentials-in-http-headers-with-vercel-sandbox>
  - <https://vercel.com/changelog/vercel-sandbox-firewall-now-supports-request-proxying-and-filtering>
- Vercel persistence and snapshots: <https://vercel.com/kb/guide/vercel-sandbox-duration-and-persistence>
- Firecracker design: <https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md>
- Firecracker production host setup: <https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md>
