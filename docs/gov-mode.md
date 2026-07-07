# Gov Mode

## What Gov Mode Adds

Gov Mode extends Play Mode credentials with jurisdictional compliance fields. It is the proprietary layer where agents act on behalf of verified citizens within specific economic zones.

Gov Mode is not part of the open specification. This document provides an overview for context. Production access is available through [sovrn.place](https://sovrn.place).

## Who It Is For

- Economic zone operators (SEZs, freeports, digital free zones)
- Government authorities that issue residency, business, or investment credentials
- Compliance teams that need audit trails and regulatory controls
- Enterprise platforms operating in regulated jurisdictions

## Trust Model

Authority-attested. Zone authorities co-sign agent credentials. Sovrn's compliance engine validates principal KYC. Agent behavior is monitored and assessed.

Unlike Play Mode's reputation-based trust, Gov Mode trust comes from:
- Zone authority attestation (the authority vouches for the agent)
- KYC verification of the principal (the human is identity-verified)
- Compliance monitoring (ongoing behavior assessment)
- Regulatory controls (holds, suspensions, revocations)

## What Gov Mode Adds, at a Glance

Gov Mode layers jurisdictional compliance, zone-authority co-signing, FATF-aligned assurance, regulatory operations, and an audit trail on top of the open layers specified here. The field-level schema, the assurance-tier definitions, the compliance and cross-zone-trust algorithms, and the regulatory-control mechanics are proprietary and are not documented in this repository. Gov Mode is named here for context only; it is out of scope for this specification.

## Agent Role in Gov Mode

Based on research into government identity systems (Estonia X-Road, EUDI Wallet, India DigiLocker, Singapore Singpass, UK GOV.UK One Login), no government system currently supports software agent delegation. Gov Mode agents operate as "agent-assisted, human-authenticated":

The agent:
- Prepares applications (pre-fills forms, gathers documents)
- Monitors status (checks progress, alerts on deadlines)
- Presents credentials (via OID4VP when the system supports it)
- Coordinates across zones (cross-zone eligibility, credential portability)

The human:
- Authenticates with government systems directly
- Signs documents with their own identity credentials
- Approves high-value actions

## Access

Gov Mode is available through Sovrn's production platform. Its schema and reference implementation are not part of this repository; contact Sovrn for details.
