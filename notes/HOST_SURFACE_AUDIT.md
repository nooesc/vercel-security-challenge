# Firecracker guest-facing host-surface audit

This is an internal research-routing note, not a reportable finding. It applies the challenge's published known-finding and eligibility rules before selecting another live probe.

## Surfaces that remain reachable from a hostile guest

| Surface | Guest interface | Current decision |
| --- | --- | --- |
| MMDS | Firecracker's embedded HTTP/TCP/IPv4 stack, configured on a virtio-net interface | Keep `SBX-020`. It is the only fixed, documented host/VMM service with a safe secret-disclosure success condition. |
| Virtio-vsock | Guest connects to host CID 2 and an exact port; Firecracker maps that port to a host Unix socket | Do not scan. Port 2050 and its resource, proxy-CA, cache-oracle, OCI-image-config, and metrics behavior are published duplicates. Test another port only if a guest-visible client/configuration or an existing `/proc/net/vsock` peer identifies it exactly, then derive a protocol-specific read-only request before connecting. |
| Virtio-net | TAP-backed packet path plus MMDS interception | Network-policy hypotheses already cover this surface. A gateway or DNS banner alone is implementation disclosure/informative, not a Medium finding. |
| Virtio-block | Root/data drives | A stale-block or cross-sandbox read needs two researcher-owned tenant accounts and must stop on owned canaries. With only one eligible account, it cannot safely establish the required Critical impact. |
| Virtio-balloon / entropy | Memory-pressure and random-data devices | No bounded read-only request yields host or tenant data. Crash/pressure testing risks self-DoS and only qualifies if a second owned tenant is measurably affected. |
| Serial / keyboard | Minimal legacy devices | Firecracker documents the production serial console as not host-exposed; the keyboard controller is a stop mechanism, not a read surface. |
| Firecracker API | Host Unix-domain control socket | Not guest-facing. Reaching it would already require a new microVM escape or host-file/socket primitive. |
| Guest-OS Unix sockets | `containerd.sock`, `ipc.sock`, APM/metrics sockets | Published duplicate and still inside the Firecracker boundary unless chained to a new host/cross-tenant primitive. |

## MMDS correction and next bounded run

Firecracker documents two response selectors: exact `Accept: application/json` for JSON, and either `Accept: plain/text` or no `Accept` for IMDS directory output. The earlier `SBX-020` discovery request used `Accept: text/plain`, which is not the documented selector. A zero-length `200` from that run therefore should not close the MMDS lane.

`SBX-020` now:

- omits `Accept` on the root, role-index, and namespace listings;
- uses exact `Accept: application/json` only after one allowlisted secret leaf is selected;
- accepts a validated JSON scalar or known-key object only in guest memory;
- wipes all bodies and retains no token, role, arbitrary directory key, or secret value;
- emits a fixed request-format attestation that candidate classification requires;
- remains capped at eight sequential requests and five requests per second.

This corrected packet is the only justified new live-ready host-surface probe from this audit. Do not add guessed MMDS paths or vsock ports after a clean authenticated root listing.

## Primary references

- [Firecracker MMDS user guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-user-guide.md#mmds-formats)
- [Firecracker MMDS design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/mmds/mmds-design.md)
- [Firecracker virtio-vsock design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)
- [Firecracker design and device boundary](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Firecracker FAQ device inventory](https://github.com/firecracker-microvm/firecracker/blob/main/FAQ.md)
- Local program policy: `notes/HACKERONE_PROGRAM_POLICY.md`
