# Sovrn Agent Protocol

> Open standard for agent identity, credentials, reputation, and delegation in jurisdictional contexts.

**Status:** v0.1.0-draft | **License:** Apache 2.0 | **Spec:** [SPEC.md](SPEC.md)

## What This Is

Data formats for AI agents that need to prove who they are, what they can do, who authorized them, and how trustworthy they are. Built on W3C Verifiable Credentials 2.0, UCAN 1.0 delegation tokens, and ERC-8004 agent registration. Designed for agents operating in economic zones, but usable in any context where agent identity matters.

## Why It Exists

Agents today lose context between sessions. No identity persists, no credentials carry over, no reputation compounds, no delegation survives a context window boundary. Every interaction starts from zero.

This protocol provides five layers of durable agent context:

```
Layer 4: Governance       Jurisdictional compliance (proprietary, Gov Mode)
Layer 3: Reputation       Time-bound scoring with zone-scoped breakdown
Layer 2: Delegation       Human-to-agent authority via UCAN capability chains
Layer 1: Credentials      W3C VC 2.0 with selective disclosure (SD-JWT)
Layer 0: Discovery        ERC-8004 agent card + DID Document
```

Existing standards handle parts of this. W3C VC 2.0 handles credentials. UCAN handles delegation. ERC-8004 handles discovery. No existing standard combines identity + reputation + credential portability across jurisdictions in a single schema. That is what this protocol adds.

The protocol's companion, the **agent-memory-board** (a separate repository), supplies the layer the agent-memory ecosystem consistently names as its open problem: who an agent *is* across sessions, and where a remembered fact *came from*. Memory frameworks persist content; none treats identity, credentials, and authorization as first-class memory state. The memory-board does- every entry is DID-anchored and carries byte-level cryptographic provenance (an integrity hash chain plus a pointer to the credential or delegation whose execution produced it), so cross-session memory arrives with a verifiable source of truth instead of an unattributed blob. The concept is defined in [docs/memory-board.md](docs/memory-board.md); the full specification lives in a separate repository.

## The Two Modes

**Play Mode (this repo):** Open, permissionless. Any agent can self-issue credentials, build reputation, receive delegations. Apache 2.0 licensed. No KYC required.

**Gov Mode (proprietary):** Sovereign-grade. Zone authorities co-sign credentials. FATF-aligned compliance. Principal KYC required. Available through [sovrn.place](https://sovrn.place).

Both modes share the same credential format. Gov Mode extends Play Mode; it does not replace it.

## Schemas

| Schema | Description |
|--------|-------------|
| [agent-credential.v1.json](schemas/agents/agent-credential.v1.json) | Agent identity and capabilities (W3C VC 2.0, multi-proof co-signing) |
| [agent-credential.sd-jwt-vc.v1.json](schemas/agents/agent-credential.sd-jwt-vc.v1.json) | SD-JWT-VC envelope of the same credential (selective disclosure) |
| [agent-record.v1.json](schemas/agents/agent-record.v1.json) | Composite agent record (application-level) |
| [delegation-token.v1.json](schemas/agents/delegation-token.v1.json) | UCAN 1.0 delegation profile |
| [reputation-record.v1.json](schemas/reputation/reputation-record.v1.json) | Time-bound reputation record (W3C VC 2.0) |

## Examples

| Example | What It Shows |
|---------|---------------|
| [play-mode-agent.json](examples/play-mode-agent.json) | Self-issued credential with a Data Integrity proof array |
| [delegation-chain.json](examples/delegation-chain.json) | Three-level UCAN delegation with capability attenuation |
| [sd-jwt-agent-credential.json](examples/sd-jwt-agent-credential.json) | SD-JWT-VC envelope: issued payload with salted digests + the disclosable set |

## Verification

- **Resolution algorithm** ([docs/resolution-algorithm.md](docs/resolution-algorithm.md)): the verifier procedure — Procedure A (presentation-time) and Procedure B (invocation-time) over a shared check library, with a normative failure-mode table.
- **Conformance suite:** 40 fixtures (positive / negative-per-failure-mode / graded / edge) against a deterministic verifier contract; ships with the publication.
- **Reference implementation** ([reference-implementations/mcp-server/](reference-implementations/mcp-server/)): a stateless, hardened MCP verifier server implementing Layers 0-2 and both procedures; passes 100% of the conformance MUST set with exact cited rules.

## Live Contexts

The JSON-LD contexts are hosted at their canonical URLs:

- Agent: [`https://schema.sovrn.place/agent/v1`](https://schema.sovrn.place/agent/v1)
- Reputation: [`https://schema.sovrn.place/reputation/v1`](https://schema.sovrn.place/reputation/v1)

**Immutability:** everything under `https://schema.sovrn.place/agent/v1/` and `.../reputation/v1/` is frozen once published — signed credentials depend on byte-stable contexts. Any breaking change ships under a new version path (`/v2/`), never by editing a published document.

## Standards Compatibility

- W3C Verifiable Credentials 2.0 (credential envelope)
- ERC-8004 (on-chain agent registration, 20K+ agents). Reputation summaries are designed to publish to public registries, including ERC-8004's Reputation Registry.
- DIF KYA-OS (designed for Level 2/3 alignment)
- UCAN 1.0 (delegation tokens)
- OID4VCI / OID4VP (credential issuance and presentation)
- ISO mdoc (EUDI Wallet compatibility target)
- SD-JWT-VC (selective disclosure)

## Specification

Full specification: [SPEC.md](SPEC.md)

Documentation:
- [Architecture](docs/architecture.md)
- [Play Mode Guide](docs/play-mode.md)
- [Gov Mode Overview](docs/gov-mode.md)
- [Agent Memory Board](docs/memory-board.md)

## Status

v0.1.0-draft. Schema structure is stabilizing. Breaking changes are expected before v1.0.0.

Components marked DRAFT, EXPERIMENTAL, or DEFERRED in the [spec status table](SPEC.md#1-overview).

## Governance

Maintained by Sovrn. Apache 2.0 licensed. Contributions welcome via pull request. Designed for potential standards body governance (DIF, W3C) in the future.

## Related

- [sovrn-protocol](https://github.com/Sovrn-place/sovrn-protocol): Human zone credentials (sibling repo)
- agent-memory-board: verifiable, provenance-bound agent memory (companion repository)
- [sovrn.place](https://sovrn.place): Production Gov Mode platform
