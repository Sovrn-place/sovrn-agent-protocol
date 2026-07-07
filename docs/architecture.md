# Architecture

## The 5-Layer Hybrid Stack

The Sovrn Agent Protocol uses five composable layers. Each layer uses the format best suited to its trust concern.

```
+----------------------------------------------------------+
| Layer 4: Governance (Proprietary)                        |
|   Jurisdictional bindings, compliance, regulatory holds  |
|   Format: Proprietary JSON extension on VC               |
+----------------------------------------------------------+
| Layer 3: Reputation                                      |
|   Time-bound scoring, zone-scoped, oracle-issued         |
|   Format: W3C VC 2.0 (SovrnReputationRecord)            |
+----------------------------------------------------------+
| Layer 2: Delegation                                      |
|   Human-to-agent authority, capability chains            |
|   Format: UCAN 1.0 (JWT, EdDSA)                         |
+----------------------------------------------------------+
| Layer 1: Credentials                                     |
|   Identity, capabilities, verification status            |
|   Format: W3C VC 2.0 + SD-JWT (SovrnAgentCredential)    |
+----------------------------------------------------------+
| Layer 0: Discovery                                       |
|   Agent registration, service endpoints                  |
|   Format: DID Document + ERC-8004 agent card             |
+----------------------------------------------------------+
```

## Why Hybrid

No single standard covers the full problem:

- **W3C VC 2.0** handles verifiable claims but not delegation or discovery
- **UCAN** handles delegation but not identity or reputation
- **ERC-8004** handles discovery but not credentials
- **DIF KYA-OS** defines conformance levels but not credential formats

The hybrid approach lets each layer evolve independently. A breaking change in ERC-8004 v2 affects only Layer 0. A new UCAN version affects only Layer 2. The credential format (Layer 1) is the most stable layer and changes least frequently.

## How Layers Compose

A verifier checking an agent's authorization performs checks across multiple layers:

1. **Resolve the agent's DID** (Layer 0) to get public keys and service endpoints
2. **Fetch the agent's credential** (Layer 1) via OID4VP
3. **Verify the delegation chain** (Layer 2) by checking UCAN tokens in the credential's evidence array
4. **Check reputation** (Layer 3) if the verifier requires a minimum reputation threshold
5. **Check compliance** (Layer 4, Gov Mode only) if the interaction requires jurisdictional authority

Each check is independent. A verifier can stop at any layer based on their trust requirements. A Play Mode verifier might check Layers 0-1 only. A zone authority would check all five.

The canonical resolution algorithm — defining behavior when layers disagree (e.g., revoked VC but valid UCAN) — is specified in [resolution-algorithm.md](resolution-algorithm.md): two procedures (presentation-time and invocation-time) over a shared check library, with a normative failure-mode table. The cross-layer revocation walk resolves exactly this class of disagreement: a credential whose embedded delegation chain contains a revoked link is rejected even when the credential's own status bit is clear, and vice versa. The MCP server reference implementation implements both procedures.

## Standards Mapping

| Layer | Primary Standard | Secondary |
|-------|-----------------|-----------|
| 0 | W3C DID Core 1.0 | ERC-8004 v1 |
| 1 | W3C VC 2.0 | SD-JWT-VC (IETF), OID4VCI/VP (OpenID) |
| 2 | UCAN 1.0 | - |
| 3 | W3C VC 2.0 | - |
| 4 | Proprietary | eIDAS 2.0 alignment target |

## Play Mode vs Gov Mode

Play Mode uses Layers 0 through 3. All schemas are open (Apache 2.0).

Gov Mode adds Layer 4. The extension schema is proprietary. Gov Mode credentials carry all Play Mode fields plus the `govMode` extension object containing jurisdictional bindings, compliance attestations, and audit trail references.

An agent can always present its Play Mode credential to any verifier. The Gov Mode extension is only presented when interacting with zone authorities or compliance-aware verifiers.
