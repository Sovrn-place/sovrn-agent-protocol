# Play Mode

## What Play Mode Is

The open, permissionless layer of the Sovrn Agent Protocol. Any agent framework can adopt it. No registration, no KYC, no approval required. Apache 2.0 licensed.

Play Mode provides agent identity, credentials, delegation, and reputation using open standards (W3C VC 2.0, UCAN 1.0, ERC-8004).

## Who It Is For

- Agent framework developers (LangChain, CrewAI, MCP, AutoGen integrations)
- Open-source AI agent projects
- Developers building multi-agent systems that need portable identity
- Researchers exploring agent trust and reputation

## Getting Started

### 1. Generate a keypair

```
Ed25519 keypair (recommended)
Public key in multibase encoding (z6Mk... prefix)
```

### 2. Create a DID Document

Use `did:sovrn:agent:{uuid}` or any DID method. The DID Document must include:
- At least one `verificationMethod` (Ed25519)
- `authentication` and `assertionMethod` references
- Service endpoints for protocols you support (MCP, A2A, OID4VP)

### 3. Self-issue a credential

Create a `SovrnAgentCredential` with:
- `issuer.id` = your agent's DID (self-issued)
- `issuanceMethod` = `"SELF_ATTESTED"`
- `capabilities` listing what your agent can do
- `credentialHash` for integrity verification

See [examples/play-mode-agent.json](../examples/play-mode-agent.json) for a complete example.

### 4. Register on-chain (optional)

Register in the ERC-8004 Identity Registry for discoverability. Your agent card includes your DID and service endpoints.

### 5. Build reputation

Interact with zones and other agents. Receive reputation records from oracles or community attestation.

## Trust Model

Reputation-based. There is no central authority. Verifiers decide their own trust thresholds.

- `SELF_ATTESTED` credentials provide identity but not trust
- `COMMUNITY_ATTESTED` credentials carry co-signatures from other agents
- `ZONE_ISSUED` credentials carry authority attestation (Gov Mode)

A verifier that only accepts `ZONE_ISSUED` credentials will reject self-attested agents. A verifier that accepts any credential will interact with all agents. The protocol does not enforce trust policy; it provides the data for verifiers to implement their own.

## Upgrade to Gov Mode

When an agent needs to operate within a jurisdiction:

1. Principal completes KYC (minimum Tier 1)
2. Request credential from zone authority
3. Zone authority issues `ZONE_ISSUED` credential with `assuranceLevel` and `govMode` extension
4. Agent now carries both Play Mode (portable, any verifier) and Gov Mode (jurisdictional, zone verifiers) credentials

See [Gov Mode overview](gov-mode.md) for details.
