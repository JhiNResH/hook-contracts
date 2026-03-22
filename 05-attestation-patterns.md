# Attestation Patterns for ERC-8183

## Overview

Job outcomes in ERC-8183 (complete/reject) are emitted as events but not persisted in a standardized, queryable format. This document describes how **EAS (Ethereum Attestation Service)** attestations can serve as an immutable receipt layer for agentic commerce — enabling credit histories, reputation aggregation, and composable trust infrastructure.

## Why Attestations?

Events are ephemeral — they require archive nodes or indexers to query historically. EAS attestations are:

- **Persistent**: Stored on-chain as first-class data, not just logs
- **Queryable**: Native GraphQL indexer (`easscan.org/graphql`) with filtering by recipient, schema, and attester
- **Composable**: Any protocol can read attestations without custom integrations
- **Non-revocable** (when configured): Job outcomes are facts, not opinions — they should not be retractable

## AttestationHook

`AttestationHook.sol` extends `BaseACPHook` and writes an EAS attestation on every job completion or rejection.

### Lifecycle

```
Job completes/rejects
  → AgenticCommerceHooked calls afterAction
  → AttestationHook reads job data from ACP contract
  → Writes EAS attestation with structured receipt data
  → Attestation is permanently on-chain
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| `afterAction` only | Never blocks job lifecycle — attestations are records, not gates |
| `try/catch` on EAS calls | EAS failures must never revert the parent transaction |
| `recipient = provider` | Providers accumulate reputation from completed/rejected jobs |
| `revocable = false` | Job outcomes are immutable facts |
| `expirationTime = 0` | Permanent records — no expiry |

### Schema

```
uint256 jobId,
address client,
address provider,
address evaluator,
uint256 budget,
bytes32 reason,
bool completed
```

**Target registry**: Base EAS (`0x4200000000000000000000000000000000000021`)

## Attester Trust Chain

The value of an attestation depends on the **attester's credibility**. Hook deployers can establish trust at multiple levels:

### Level 1: Anonymous Attester
```
attester: 0xHookContract → unknown identity → baseline trust
```

### Level 2: Identified Attester (via ERC-8004)
```
attester: 0xHookContract → ERC-8004 Identity Registry → verified identity → higher trust
```

### Level 3: Named Attester (ERC-8004 + ENS)
```
attester: 0xHookContract → ERC-8004 Registry → ENS name → highest trust
```

Deployers **SHOULD** register their hook contract address in an ERC-8004 Identity Registry and optionally associate it with an ENS name to maximize attestation credibility.

## Composability with Other Hooks

| Hook | Phase | Purpose |
|---|---|---|
| `TrustGateACPHook` (PR #6) | `beforeAction` | Pre-transaction gate — blocks untrusted actors |
| `AttestationHook` (this PR) | `afterAction` | Post-transaction receipt — records outcomes |

Combined, these form a complete trust lifecycle: **gate → execute → record**.

For deployments requiring both, a router pattern can compose multiple hooks behind a single hook address (see [Future Work](#future-work)).

## Extensions

### Invoice NFT

Attestation hooks **MAY** mint an ERC-1155 token to the client as a visible, wallet-native receipt. This enables:

- **Wallet visibility**: Clients can see their transaction receipts directly in their wallet
- **Incentive mechanisms**: Each invoice NFT can serve as a lottery ticket (inspired by Taiwan's Uniform Invoice lottery system)
- **Proof of usage**: Clients can present invoice NFTs as proof of having used a service (e.g., for vouching or reviewing)

### Reputation Aggregation

Off-chain indexers **MAY** query EAS attestations by `recipient` address and `schemaId` to compute aggregate metrics:

- **Completion rate**: `completed=true` count / total attestations
- **Total volume**: Sum of `budget` across all completed attestations
- **Client diversity**: Count of unique `client` addresses
- **Activity recency**: Timestamp of most recent attestation
- **Average deal size**: Mean `budget` across attestations

These metrics form the basis for **agent financial reports** — analogous to corporate earnings reports but for autonomous agents.

### Cross-Reference with Token Markets

Agent token prices often diverge from actual service quality. Attestation-derived metrics (completion rate, revenue, client count) provide **fundamental analysis** for agent tokens — independent of market speculation.

## Future Work

- **Hook Router**: A composable router that chains multiple hooks (attestation + gate + custom plugins) behind a single hook address
- **Payment Layer Interop**: EAS attestations for non-escrow payment methods (x402 HTTP payments, micropayment channels) to capture the full transaction spectrum
- **Bidirectional Attestations**: Writing attestations to both provider and client, enabling client reputation in addition to provider reputation

## Security Considerations

- **Gas costs**: Each attestation requires gas. On L2s (Base, Arbitrum), costs are minimal (~$0.001–$0.01)
- **EAS availability**: If EAS is unavailable, the `try/catch` ensures jobs still complete normally
- **Schema immutability**: Once registered, EAS schemas cannot be changed. The `setSchemaUID` admin function allows switching to a new schema if needed
- **Attestation spam**: Since attestations are only written by the hook contract (called by AgenticCommerceHooked), spam is not possible — each attestation corresponds to a real job outcome
