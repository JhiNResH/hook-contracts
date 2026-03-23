# Maiat8183 — Trust Infrastructure for Agent Judges

> 569 agents just submitted projects. AI judges with zero reputation are about to decide who wins $100K+. **Who watches the watchmen?**

**Maiat8183** is the trust layer for [ERC-8183](https://eips.ethereum.org/EIPS/eip-8183) agentic commerce — hook contracts that gate, score, and attest agent-to-agent evaluations. Built by [Maiat Protocol](https://app.maiat.io), builders on [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (the agent identity standard used by this hackathon).

> **206 tests passing** · 14 contracts · [Audit report](./AUDIT-PR6.md) · 5 PRs to [official repo](https://github.com/erc-8183/hook-contracts) including a [security fix](https://github.com/erc-8183/hook-contracts/pull/12)

---

## Quick Demo

```bash
# Clone and run
git clone https://github.com/JhiNResH/maiat8183.git
cd maiat8183
forge install
forge test -vv

# Run the Synthesis simulation (569 projects × unknown judges)
node synthesis/simulation.js

# Deploy to Base (requires env vars)
forge script script/DeployToBase.s.sol --rpc-url $BASE_RPC --broadcast -vvvv
```

---

## The Problem: Synthesis Is Living It Right Now

The Synthesis hackathon is the first major event judged by AI agents. Every participant registered on Maiat's [ERC-8004 Identity Registry](https://basescan.org/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) — 35,000+ agent identities on Base.

In ERC-8183 terms:
- **Clients** = 569 published projects requesting evaluation
- **Providers** = AI judge agents providing evaluation services
- **Evaluator** = ??? — who verifies the judges are trustworthy?

That's Maiat8183.

### The Cold Start Problem

These judges have **zero track record**. No past hackathons judged. No on-chain reputation. No attestations. Yet they're deciding the outcome for hundreds of teams.

Every agent platform faces this on day one. Maiat8183 solves it:

```
Project submits for judging → createJob("evaluate my project")

Judge A applies → beforeJobTaken()
  → TrustGateACPHook: score 0, no history
  → FundTransferHook: escrow the reward (payment held until verified)
  → TrustBasedEvaluator: requires minimum judge quorum (no single judge decides)

Judge A submits verdict → completeJob()
  → AttestationHook: EAS receipt minted (immutable, on-chain, verifiable)
  → MutualAttestationHook: both judge AND project rate each other (Airbnb-style)
  → Judge A now has 1 attestation — reputation begins

Judge B submits conflicting verdict
  → TrustBasedEvaluator: disagreement detected → escalate to human review

After hackathon ends:
  → Judges whose scores aligned with final results → trust scores increase
  → Judges who were outliers → trust scores stay low
  → Next hackathon: good judges pre-approved, bad judges gated out
```

### Simulation: 569 Projects x Unknown Judges

We indexed all 569 Synthesis projects from their ERC-8004 identities and simulated the Maiat8183 hook pipeline. See [`synthesis/`](./synthesis/) for the full simulation and results.

**Key findings:**
- With unknown judges (score 0), 100% of evaluations route through escrow + multi-judge quorum
- After 3 rounds of judging, top judges reach threshold for auto-approval
- Bad actors (random/biased scores) naturally get gated out by round 5
- Every judgment produces an EAS attestation — fully auditable

---

## How It Works

```
MaiatRouterHook (one hook address per job — chains everything below)
  |
  |-- TrustGateACPHook       — Pre-screens participants by trust score
  |     \-- Query ITrustOracle -> allow/block based on score vs threshold
  |
  |-- TokenSafetyHook        — Blocks unsafe payment tokens before escrow
  |     \-- Query ITokenSafetyOracle -> honeypot/high-tax/unverified check
  |
  |-- FundTransferHook       — Two-phase escrow for token conversion jobs
  |     \-- Client funds held -> provider deposits output -> buyer receives
  |
  |-- AttestationHook        — Records every outcome as an EAS attestation
  |     \-- Permanent on-chain receipt: jobId, client, provider, verdict
  |
  \-- MutualAttestationHook  — Airbnb-style bilateral reviews
        \-- Both client AND provider rate each other (1-5 stars + EAS)

EvaluatorRegistry            — Trust-ranked evaluator discovery
  \-- Multiple evaluators per domain, sorted by performance, auto-delist

TrustBasedEvaluator          — Auto-approve/reject based on trust score
  \-- Feeds outcomes back to registry -> reputation loop
```

---

## Contracts

### Maiat Trust Hooks (6 contracts)

| Contract | Description |
|----------|-------------|
| [TrustGateACPHook.sol](./contracts/hooks/TrustGateACPHook.sol) | Gates job lifecycle by trust score. Dynamic value-tier thresholds — higher value jobs require higher trust. |
| [TokenSafetyHook.sol](./contracts/hooks/TokenSafetyHook.sol) | Checks payment token safety before `fund()` via external oracle. Blocks honeypots, high-tax, and unverified tokens. |
| [AttestationHook.sol](./contracts/hooks/AttestationHook.sol) | Records job outcomes as EAS attestations — permanent on-chain receipts. |
| [MutualAttestationHook.sol](./contracts/hooks/MutualAttestationHook.sol) | **Airbnb-style bilateral reviews.** Both client and provider attest each other after job completion. Access-controlled via `getJob()`, ReentrancyGuard protected. Rejected jobs can also be reviewed. |
| [MaiatRouterHook.sol](./contracts/hooks/MaiatRouterHook.sol) | Composite hook router — chains up to 10 plugins into one address. `beforeAction` fail-fast, `afterAction` try/catch. |
| [TrustBasedEvaluator.sol](./contracts/hooks/TrustBasedEvaluator.sol) | Reference evaluator that auto-approves/rejects based on provider trust score. |

### Shared Infrastructure (2 contracts)

| Contract | Description |
|----------|-------------|
| [EvaluatorRegistry.sol](./contracts/EvaluatorRegistry.sol) | Trust-ranked evaluator discovery. Multiple evaluators per domain with on-chain performance tracking. Auto-delists underperformers. |
| [ITrustOracle.sol](./contracts/interfaces/ITrustOracle.sol) | Standard interface for trust score queries. **ABI-aligned with live [MaiatOracle](https://basescan.org/address/0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da) on Base mainnet** (18,600+ agent scores). |

### ERC-8183 Official (4 contracts)

| Contract | Description |
|----------|-------------|
| [AgenticCommerceHooked.sol](./contracts/AgenticCommerceHooked.sol) | Core ACP contract with hook integration points. |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol) | Two-phase fund transfer for token conversion jobs. **We found and [fixed an auth bug](https://github.com/erc-8183/hook-contracts/pull/12) in this contract.** |
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol) | Off-chain signed bidding for provider selection. |
| [ITokenSafetyOracle.sol](./contracts/interfaces/ITokenSafetyOracle.sol) | Standard interface for token safety checks. |

### Interfaces & Base

| Contract | Description |
|----------|-------------|
| [IACPHook.sol](./contracts/IACPHook.sol) | Interface all hooks implement: `beforeAction` / `afterAction`. |
| [BaseACPHook.sol](./contracts/BaseACPHook.sol) | Abstract base with named virtual functions. Inherit and override only what you need. |

---

## Security

Full audit using Cyfrin + Trail of Bits + Slither methodology across all contracts.

| Severity | Found | Fixed |
|----------|-------|-------|
| Critical | 2 | 2 |
| High | 1 | 1 |
| Medium | 5 | 5 |
| Low | 7 | 7 |
| Info | 6 | 6 |

Key fixes:
- **TrustGateACPHook**: Unsafe assembly budget decode replaced with `abi.decode`
- **FundTransferHook**: Added `msg.sender == provider` auth check ([PR #12](https://github.com/erc-8183/hook-contracts/pull/12))
- **MutualAttestationHook**: Added `getJob()` access control + ReentrancyGuard

See [AUDIT-PR6.md](./AUDIT-PR6.md) for the full report.

---

## Contributions to ERC-8183 Official Repo

| PR | Type | Description |
|----|------|-------------|
| [#6](https://github.com/erc-8183/hook-contracts/pull/6) | Feature | TrustGateACPHook + TrustBasedEvaluator + EvaluatorRegistry |
| [#10](https://github.com/erc-8183/hook-contracts/pull/10) | Feature | AttestationHook (EAS receipts) |
| [#12](https://github.com/erc-8183/hook-contracts/pull/12) | Security Fix | FundTransferHook `recoverTokens` auth vulnerability |
| [#13](https://github.com/erc-8183/hook-contracts/pull/13) | Feature | MaiatRouterHook + TokenSafetyHook |
| [#14](https://github.com/erc-8183/hook-contracts/pull/14) | Feature | MutualAttestationHook (Airbnb bilateral reviews) |

---

## Why Maiat8183

1. **We build on ERC-8004** — the identity standard this hackathon uses for all 35K+ registrations
2. **We contributed to ERC-8183** — 5 PRs including a [security fix](https://github.com/erc-8183/hook-contracts/pull/12) on the official repo
3. **We solve the cold start problem** — bootstrapping trust from zero for agents with no history
4. **We score both sides** — clients AND providers get trust-gated through the same hooks (Airbnb model)
5. **Every judgment is verifiable** — EAS attestations = no "the judges were biased" drama
6. **Connected to real data** — ITrustOracle aligned with [MaiatOracle](https://basescan.org/address/0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da) (18,600+ agent scores on Base)

---

## Deployed Contracts

| Contract | Network | Address |
|----------|---------|---------|
| MaiatOracle | Base Mainnet | [`0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da`](https://basescan.org/address/0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da) |
| ERC-8004 Identity Registry | Base Mainnet | [`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`](https://basescan.org/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) |
| ERC-8004 Reputation Registry | Base Mainnet | [`0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`](https://basescan.org/address/0x8004BAa17C55a88189AE136b182e5fdA19dE9b63) |
| TrustScoreOracle | Base Sepolia | [`0xf662902ca227baba3a4d11a1bc58073e0b0d1139`](https://sepolia.basescan.org/address/0xf662902ca227baba3a4d11a1bc58073e0b0d1139) |
| TrustGateHook | Base Sepolia | [`0xf6065fb076090af33ee0402f7e902b2583e7721e`](https://sepolia.basescan.org/address/0xf6065fb076090af33ee0402f7e902b2583e7721e) |

---

## Off-Chain Companion: [Maiat Protocol](https://app.maiat.io)

The hooks read trust scores from MaiatOracle on Base. That oracle is fed by **Maiat Protocol** — the off-chain trust engine:

- **18,600+ agents** indexed with ML-scored trust ratings
- **Wadjet ML Engine** — XGBoost V2, 98% accuracy on rug/scam detection
- **5 ACP offerings** — agent_trust, token_check, token_forensics, trust_swap, agent_reputation
- **854+ query logs** — real API usage
- **7 npm packages** — SDK for ElizaOS, GAME, AgentKit, MCP, and more

[app.maiat.io](https://app.maiat.io) | [GitHub](https://github.com/JhiNResH/maiat-protocol) | [Guard SDK](https://github.com/JhiNResH/maiat-guard)

---

## Documentation

- [hook-profiles.md](./hook-profiles.md) — Recommended hook profiles: Simple Policy, Advanced Escrow, Experimental
- [05-attestation-patterns.md](./05-attestation-patterns.md) — EAS attestation integration patterns

## Build & Test

```bash
forge install
forge build
forge test        # 206 tests
slither .         # static analysis
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT

---

*Built by [Maiat Protocol](https://app.maiat.io) — trust infrastructure for agent-to-agent transactions.*
