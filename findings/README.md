# Findings index

This directory contains narrowly scoped reports and reproduction material from authorized research. Status labels distinguish a technical result from its program disposition.

## New Vercel Sandbox findings

| ID | Report | Technical status | Program status |
| --- | --- | --- | --- |
| `SBX-020` | [Literal `deny-all` still permits authenticated MMDS access](SBX-020-mmds-explicit-link-local-deny-bypass.md) | Confirmed same-session firewall differential with authenticated MMDSv2 access. | HackerOne `#3952509` closed as an exact duplicate of `#3951306`; Vercel confirmed the Firecracker/MMDS root cause. |
| `SBX-031` | [ECH permits a denied inner hostname through an allowed outer SNI](SBX-031-ech-domain-allowlist-bypass.md) | Reproduced twice with a fresh synthetic file secret and non-reflecting receipt. | Clarification-gated: the public contract does not define whether an allowed ECH public name authorizes hidden inner names. |

Reproduction archives and SHA-256 manifests are available under [`attachments/`](attachments/).

## Earlier and supporting reports

| ID | Report | Status |
| --- | --- | --- |
| `FLAGS-001` | [Cross-group precompute replay](FLAGS-001-cross-group-precompute-replay.md) | Reproduced OSS draft. |
| `SBX-013` | [Encoded dot-segment brokered credential disclosure](SBX-013-encoded-dot-segment-brokered-credential-disclosure.md) | Reproduced historical Sandbox report. |
| `SBX-018` | [Live `deny-all` stale transform](SBX-018-live-deny-all-stale-transform.md) | Historical signal not reproduced by five hardened alias runs. |

## Status terminology

- **Confirmed** describes what the retained evidence demonstrates.
- **Duplicate** means the program linked the report to an earlier report of the same root cause; it is not a technical retraction.
- **Clarification-gated** means the behavior is reproduced but reportability depends on the vendor's intended security contract.
- **Historical signal** means an earlier observation was not reproduced by the hardened packet and is not presented as a current finding.
