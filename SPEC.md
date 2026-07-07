# Sovrn Agent Protocol Specification v0.1.0-draft

**Status:** DRAFT. This specification is under active development. Breaking changes are expected before v1.0.0.

**License:** Apache 2.0 (Play Mode schemas and interfaces). Gov Mode extensions are proprietary.

---

## 1. Overview

The Sovrn Agent Protocol defines data formats for agent identity, credentials, reputation, and delegation in jurisdictional contexts. It enables AI agents to carry verifiable claims about their capabilities, their principal's identity, and their authority to act within specific economic zones.

The protocol has two modes:

- **Play Mode (this specification):** Open, permissionless schemas that any agent framework can adopt. Apache 2.0 licensed. Agents build reputation through interactions. No KYC required. Self-issued credentials are supported but distinguished from authority-issued ones.

- **Gov Mode (proprietary extensions):** Sovereign-grade layer for agents acting on behalf of verified citizens within specific jurisdictions. Zone authorities co-sign credentials. FATF-aligned compliance. Requires principal KYC. Available through Sovrn's production platform.

Both modes share the same credential format (W3C VC 2.0) and delegation format (UCAN 1.0). Gov Mode adds fields to Play Mode credentials; it does not replace them.

### Relationship to sovrn-protocol

This protocol is a sibling to sovrn-protocol, which defines credential schemas for human citizens (zone residency, business formation, KYC attestations). The agent protocol extends those patterns to AI agents acting on behalf of citizens.

### Component Status

| Component | Status | Description |
|-----------|--------|-------------|
| Agent Credential (SovrnAgentCredential) | DRAFT | W3C VC 2.0 credential type for agent identity and capabilities |
| Reputation Record (SovrnReputationRecord) | DRAFT | Time-bound reputation VC with implementation-defined dimensions |
| Delegation Token | DRAFT | UCAN 1.0 profile for human-to-agent capability delegation |
| Agent Record (composite) | DRAFT | Application-level aggregation of identity, credentials, reputation, delegations |
| Gov Mode Extension | DRAFT | Proprietary jurisdictional compliance extension |
| JSON-LD Contexts | EXPERIMENTAL | Context documents for agent and reputation credential types |
| DID Method (did:sovrn:agent:) | EXPERIMENTAL | Agent DID resolution. DID method specification not yet registered with W3C. |
| ERC-8004 Integration | EXPERIMENTAL | On-chain agent card extension for discovery |
| Conformance Test Suite | DRAFT | 40-fixture suite + deterministic verifier contract (positive / negative-per-failure-mode / graded / edge classes); ships with the publication. The MCP server reference implementation passes 100% of the MUST set with exact cited rules |
| Resolution Algorithm | DRAFT | Specified in [docs/resolution-algorithm.md](docs/resolution-algorithm.md): Procedure A (presentation-time) + Procedure B (invocation-time) over a shared check library; implemented by the reference verifier |
| SD-JWT-VC Envelope | DRAFT | Selective-disclosure envelope ([schemas/agents/agent-credential.sd-jwt-vc.v1.json](schemas/agents/agent-credential.sd-jwt-vc.v1.json)) alongside the W3C VC 2.0 envelope; disclosable set per Layer 1 D6 |
| MCP Server Reference Implementation | DRAFT | Stateless Layer 0-2 verifier over MCP transport (`reference-implementations/mcp-server/`): credential request handoff, presentation verification, delegation-chain validation; public-surface resources only |

---

## 2. Architecture

### The 5-Layer Hybrid Stack

The protocol uses a layered architecture where each layer handles a specific trust concern using the format best suited to it.

```
Layer 4: Governance (Gov Mode, proprietary)
   Jurisdictional bindings, compliance attestations, regulatory holds, audit trail

Layer 3: Reputation (SovrnReputationRecord VC)
   Time-bound, oracle-issued, implementation-defined dimensions and tiers

Layer 2: Delegation (UCAN 1.0 tokens)
   Human-to-agent authority chains, capability-scoped, attenuating

Layer 1: Credentials (W3C VC 2.0 + SD-JWT)
   Portable, verifiable claims about agent capabilities and verification status

Layer 0: Discovery (ERC-8004 agent card + DID Document)
   Agent-finds-agent, on-chain registry, service endpoint advertisement
```

**Play Mode** uses Layers 0 through 3. **Gov Mode** adds Layer 4 as a proprietary extension.

### Layer 0: Discovery

Agents advertise their existence and service endpoints via:
- A DID Document (did:sovrn:agent:{uuid}) with verification methods and service endpoints
- An optional ERC-8004 agent card registered on Ethereum for on-chain discoverability

The DID Document includes service endpoints for MCP, A2A, OID4VP, and OID4VCI protocols, enabling other agents and verifiers to discover how to interact with the agent.

### Layer 1: Credentials

Agent capabilities and verification status are expressed as W3C VC 2.0 credentials (SovrnAgentCredential type). Credentials may be:
- **Self-issued** (SELF_ATTESTED): Agent asserts its own capabilities. Provides identity only, not trust.
- **Community-attested** (COMMUNITY_ATTESTED): Co-signed by N other agents or community members.
- **Zone-issued** (ZONE_ISSUED): Issued by a zone authority with jurisdictional binding.
- **Oracle-issued** (ORACLE_ISSUED): Issued by a reputation or verification oracle.

The `issuanceMethod` field distinguishes these explicitly. Verifiers should set trust thresholds based on issuance method.

Selective disclosure is supported via SD-JWT securing (IETF draft-ietf-oauth-sd-jwt-vc).

### Layer 2: Delegation

Human-to-agent authority is expressed as UCAN 1.0 capability tokens embedded in the credential's evidence array. UCAN tokens are JWT-based, EdDSA-signed, and support:
- **Attenuation:** Child delegations must be a subset of parent capabilities
- **Chaining:** Personal Agent can sub-delegate to Specialist Agent
- **Scoping:** Capabilities are bound to specific resources (zones, wallets, document types)
- **Expiration:** Time-bound authority with explicit expiry

The `sovrn:` URI scheme is used for resource identifiers (e.g., `sovrn:zone:zone-a`, `sovrn:wallet:principal`). This is a Sovrn protocol extension to UCAN resource naming.

Note: UCAN revocation uses BitstringStatusList (reuse of W3C VC revocation infrastructure). This is a Sovrn-profile extension not part of the UCAN 1.0 core specification.

### Layer 3: Reputation

Agent reputation is expressed as a time-bound W3C VC (SovrnReputationRecord) issued by a reputation oracle. The record includes:
- A composite score (range and computation are implementation-defined)
- A tier label (tier names, count, and thresholds are implementation-defined)
- An array of dimension scores (dimension names, count, and weighting are implementation-defined)
- Per-zone reputation breakdowns
- An epoch number for versioning
- A computation method identifier and hash for auditability

Reputation records are re-issued periodically. Epoch duration is implementation-defined.

### Layer 4: Governance (Proprietary)

Gov Mode adds jurisdictional compliance, zone-authority co-signing, FATF-aligned assurance, regulatory operations, and an audit trail on top of the open layers. Its schema, field definitions, and algorithms are proprietary and are not part of this specification. Gov Mode is named here for context only; the open protocol carries no Gov Mode schema, fields, or worked examples.

---

## 3. Standards Compatibility

| Standard | Relationship | Notes |
|----------|-------------|-------|
| W3C VC 2.0 | Credential envelope format | SovrnAgentCredential and SovrnReputationRecord are VC types. Custom terms require published JSON-LD contexts. |
| ERC-8004 | Discovery layer | Agent card registered on-chain. Designed against v1; adapter pattern recommended for v2 migration. |
| DIF KYA-OS | Designed for alignment | Play Mode targets KYA-OS Level 2 alignment. Gov Mode targets Level 3. Conformance not yet tested. did:sovrn:agent: not yet registered with W3C DID Method Registry. |
| OID4VCI | Credential issuance | Agents can receive credentials via OID4VCI endpoints |
| OID4VP | Credential presentation | Agents present credentials to verifiers via OID4VP |
| ISO mdoc | Format compatibility target | EUDI Wallet interop requires mdoc support alongside SD-JWT-VC. Deferred to v1.0.0. |
| UCAN 1.0 | Delegation format | Sovrn profile of UCAN 1.0 with BitstringStatusList revocation extension. Most production UCAN implementations use 0.10; compatibility notes are needed for cross-ecosystem delegation. |
| EUDI Wallet ARF | Target compatibility | SD-JWT-VC output and OID4VP presentation targeted for EUDI interop. Full EUDI conformance deferred to v1.0.0. |

---

## 4. Schemas

### Play Mode (Open, Apache 2.0)

| Schema | File | Description |
|--------|------|-------------|
| Agent Credential | `schemas/agents/agent-credential.v1.json` | W3C VC 2.0 type for agent identity, capabilities, delegation evidence |
| Agent Credential (SD-JWT-VC) | `schemas/agents/agent-credential.sd-jwt-vc.v1.json` | SD-JWT-VC envelope of the agent credential (selective disclosure) |
| Agent Record | `schemas/agents/agent-record.v1.json` | Composite application-level record (not a VC itself) |
| Delegation Token | `schemas/agents/delegation-token.v1.json` | UCAN 1.0 profile for Sovrn delegation |
| Reputation Record | `schemas/reputation/reputation-record.v1.json` | Time-bound reputation VC with implementation-defined dimensions |

Gov Mode extensions are proprietary and are not included in this repository (see §6).

### JSON-LD Contexts

| Context | File | Status |
|---------|------|--------|
| Agent Context | `contexts/agent-v1.jsonld` | EXPERIMENTAL. Published (live) at https://schema.sovrn.place/agent/v1 |
| Reputation Context | `contexts/reputation-v1.jsonld` | EXPERIMENTAL. Published (live) at https://schema.sovrn.place/reputation/v1 |

The published contexts and schemas under `https://schema.sovrn.place/agent/v1/` and `.../reputation/v1/` are immutable: they are frozen once published because signed credentials depend on byte-stable contexts, and any breaking change ships under a new version path (`/v2/`) rather than by editing a published document.

### Validation

All schemas use JSON Schema Draft 2020-12. Validation can be performed with any compliant validator (ajv, hyperjump, etc.).

Hash fields use algorithm-prefixed format (`sha256:`, `sha3-256:`, `shake256:`) to support algorithm agility. SHA-256 is the current default. Implementers should plan for post-quantum hash algorithm migration.

---

## 5. Play Mode

Play Mode is the open, permissionless layer. Any agent framework can adopt it.

### Trust Model

Reputation-based. Agents build reputation through interactions. Verifiers set their own trust thresholds. No central authority gates participation.

### Getting Started

1. Generate an Ed25519 keypair
2. Create a DID Document (did:sovrn:agent:{uuid} or any DID method)
3. Self-issue a SovrnAgentCredential with `issuanceMethod: "SELF_ATTESTED"`
4. Optionally register in ERC-8004 for on-chain discoverability
5. Accumulate reputation through zone interactions

### Constraints

- No KYC requirement
- No assuranceLevel field (Gov Mode only)
- Reputation is self-reported or community-attested (no authoritative oracle required)
- Delegation is verifiable but not jurisdictionally binding
- Credentials are bearer tokens; holder presents, verifier decides trust level
- On-chain anchoring is optional

---

## 6. Gov Mode

Sovrn operates a proprietary Gov Mode layer that adds jurisdictional compliance attestations, zone-authority co-signing, FATF-aligned assurance, regulatory operations, and an audit trail on top of the open layers specified here. The Gov Mode layer — its schema, field definitions, assurance-tier semantics, compliance and cross-zone-trust algorithms, and regulatory controls — is proprietary and out of scope for this specification. No Gov Mode schema, field definitions, or worked examples travel in this repository.

### Access

Gov Mode is available through Sovrn's production platform. Contact: https://sovrn.place

### Upgrade Path

1. Agent starts in Play Mode (self-attested credential)
2. Principal completes KYC (Tier 1 minimum)
3. Zone authority issues jurisdictional binding
4. Compliance monitoring begins
5. Full Gov Mode: credential carries both Play Mode (portable) and Gov Mode (jurisdictional) layers

---

## 7. Versioning

This specification uses semantic versioning (semver).

- **PATCH** (0.1.x): Documentation fixes, non-breaking clarifications
- **MINOR** (0.x.0): New optional fields, new credential types, backwards-compatible extensions
- **MAJOR** (x.0.0): Breaking schema changes, field removals, format changes

Backwards compatibility commitment: once a field is marked STABLE, it will not be removed or have its type changed without a major version bump.

---

## 8. Governance

This specification is maintained by Sovrn. Contributions are welcome via pull request.

Changes are proposed via GitHub issues. Accepted changes follow the versioning policy above.

A path to standards body governance (DIF, W3C, or similar) is open for future consideration. The protocol is designed for KYA-OS alignment to facilitate this transition if pursued.
