# Agent Memory Board

The full specification lives in a separate repository
(`Sovrn-place/agent-memory-board`) on its own version line. This page defines
the concept; the specification defines the construction.

## Definition

The agent-memory-board is **verifiable, provenance-bound agent memory**: a
persistent, DID-anchored record of an agent's history in which every entry
carries cryptographic evidence of where it came from, who wrote it, and under
what authority.

It is the memory layer for sovereign agents: agents that carry identity,
credentials, reputation, and memory provenance in one accountable stack.

Three properties define it:

1. **DID-anchored accountable history.** Memory is keyed to the agent's
   decentralized identifier. What an agent did, learned, and was authorized to
   do accumulates under an identity that can be verified, not a session that
   evaporates.
2. **Tamper-evident, hash-chained provenance.** The record is an append-only
   log. Entries are hash-chained, so deletion, reordering, and after-the-fact
   edits are detectable. Corrections are appended, never rewritten.
3. **Provenance-bound entries.** Every entry points to the credential or
   delegation whose execution produced it. A remembered fact arrives with its
   source of authority attached, and it stays traceable to that source later,
   including when the source is revoked.

## The thesis: the write path is the primary defense

Integrity of bytes is not integrity of meaning. The published memory-poisoning
results share one shape: the attack does not tamper with stored bytes, it
writes validly formed, validly authorized, adversarial content through the
legitimate write path. A hash proves an entry was not altered after it was
stored. It cannot catch a faithfully stored lie.

The decisive control is therefore the write path, not the stored bytes. Writes
are gated: every write presents a valid credential or delegation before an
entry is admitted, and every entry is bound to the capability that produced
it. Read-time scoring and content heuristics can layer above this; they are
not a substitute for it.

## Projection, not passthrough

Reads are computed views over the log, not raw forwarding of everything the
log contains. A projection exposes what a consumer is entitled to see and
redacts what it is not. Sensitive underlying values stay redacted:
reputation, for example, is projected as an opaque token, never as the
issuer's internal scoring detail.

## Relationship to the Sovrn Agent Protocol

The memory board is downstream infrastructure, not a protocol layer. It
consumes what the protocol's layers produce: agent DIDs (Layer 0), credentials
(Layer 1), delegations (Layer 2), and reputation records (Layer 3), and it
stores and exposes them as accountable memory state. The two specifications
version independently.

Together they address what the agent-memory ecosystem consistently names as
its open problem: who an agent is across sessions, and where a remembered fact
came from. Point solutions give agents an identity, or a memory, or a score;
sovereign agents carry all of it, accountably, in one stack a regulator can
verify.
