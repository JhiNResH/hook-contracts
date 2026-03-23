# Maiat8183 — Trust Infrastructure for Agent Judges

> 569 agents just submitted projects. AI judges with zero reputation are about to decide who wins $100K+. **Who watches the watchmen?**

**Maiat8183** is the trust layer for [ERC-8183](https://eips.ethereum.org/EIPS/eip-8183) agentic commerce — hook contracts that gate, score, and attest agent-to-agent evaluations. Built by [Maiat Protocol](https://app.maiat.io), builders on [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) (the agent identity standard used by this hackathon).

> **175 tests passing** · 10 contracts · 5,310 lines of Solidity · [Audit report](./AUDIT-PR6.md) · 3 PRs to [official repo](https://github.com/erc-8183/hook-contracts) including a [security fix](https://github.com/erc-8183/hook-contracts/pull/12)

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
  → Judge A now has 1 attestation — reputation begins

Judge B submits conflicting verdict
  → TrustBasedEvaluator: disagreement detected → escalate to human review

After hackathon ends:
  → Judges whose scores aligned with final results → trust scores increase
  → Judges who were outliers → trust scores stay low
  → Next hackathon: good judges pre-approved, bad judges gated out
```

### Simulation: 569 Projects × Unknown Judges

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
  │
  ├── TrustGateACPHook       — Pre-screens participants by trust score
  │     └── Query ITrustOracle → allow/block based on score vs threshold
  │
  ├── TokenSafetyHook        — Blocks unsafe payment tokens before escrow
  │     └── Query ITokenSafetyOracle → honeypot/high-tax/unverified check
  │
  ├── FundTransferHook       — Two-phase escrow for token conversion jobs
  │     └── Client funds held → provider deposits output → buyer receives
  │
  └── AttestationHook        — Records every outcome as an EAS attestation
        └── Permanent on-chain receipt: jobId, client, provider, verdict

EvaluatorRegistry            — Trust-ranked evaluator discovery
  └── Multiple evaluators per domain, sorted by performance, auto-delist

TrustBasedEvaluator          — Auto-approve/reject based on trust score
  └── Feeds outcomes back to registry → reputation loop
```

---

## Contracts

### Core Trust System

| Contract | Description |
|----------|-------------|
| [EvaluatorRegistry.sol](./contracts/EvaluatorRegistry.sol) | Trust-ranked evaluator discovery. Multiple evaluators per domain with on-chain performance tracking. Auto-delists underperformers. |
| [TrustGateACPHook.sol](./contracts/hooks/TrustGateACPHook.sol) | Gates job lifecycle by trust score. Dynamic value-tier thresholds — higher value jobs require higher trust. |
| [TrustBasedEvaluator.sol](./contracts/hooks/TrustBasedEvaluator.sol) | Reference evaluator that auto-approves/rejects based on provider trust score. Feeds outcomes back to EvaluatorRegistry. |

### Plugin Hooks

| Contract | Description |
|----------|-------------|
| [AttestationHook.sol](./contracts/hooks/AttestationHook.sol) | Records job outcomes as EAS attestations — permanent on-chain receipts. |
| [TokenSafetyHook.sol](./contracts/hooks/TokenSafetyHook.sol) | Checks payment token safety before `fund()` via external oracle. |
| [FundTransferHook.sol](./contracts/hooks/FundTransferHook.sol) | Two-phase fund transfer for token conversion/bridging jobs. |
| [MaiatRouterHook.sol](./contracts/hooks/MaiatRouterHook.sol) | Composite hook router — chains multiple plugins into one address. |
| [BiddingHook.sol](./contracts/hooks/BiddingHook.sol) | Off-chain signed bidding for provider selection. |

### Interfaces & Base

| Contract | Description |
|----------|-------------|
| [IACPHook.sol](./contracts/IACPHook.sol) | Interface all hooks implement: `beforeAction` / `afterAction`. |
| [BaseACPHook.sol](./contracts/BaseACPHook.sol) | Abstract base with named virtual functions. Inherit and override only what you need. |
| [ITrustOracle.sol](./contracts/interfaces/ITrustOracle.sol) | Standard interface for trust score queries. |
| [ITokenSafetyOracle.sol](./contracts/interfaces/ITokenSafetyOracle.sol) | Standard interface for token safety checks. |

---

## Why Maiat8183

1. **We build on ERC-8004** — the identity standard this hackathon uses for all 35K+ registrations
2. **We contributed to ERC-8183** — 3 PRs including a [security fix](https://github.com/erc-8183/hook-contracts/pull/12) on the official repo
3. **We solve the cold start problem** — bootstrapping trust from zero for agents with no history
4. **We score both sides** — clients AND providers get trust-gated through the same hooks
5. **Every judgment is verifiable** — EAS attestations = no "the judges were biased" drama

---

## Deployed Contracts

| Contract | Network | Address |
|----------|---------|---------|
| MaiatOracle | Base Mainnet | [`0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da`](https://basescan.org/address/0xc6cf2d59ff2e4ee64bbfceaad8dcb9aa3f13c6da) |
| ERC-8004 Identity Registry | Base Mainnet | [`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`](https://basescan.org/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) |
| TrustScoreOracle | Base Sepolia | [`0xf662902ca227baba3a4d11a1bc58073e0b0d1139`](https://sepolia.basescan.org/address/0xf662902ca227baba3a4d11a1bc58073e0b0d1139) |
| TrustGateHook | Base Sepolia | [`0xf6065fb076090af33ee0402f7e902b2583e7721e`](https://sepolia.basescan.org/address/0xf6065fb076090af33ee0402f7e902b2583e7721e) |

---

## Documentation

- [hook-profiles.md](./hook-profiles.md) — Recommended hook profiles: Simple Policy, Advanced Escrow, Experimental
- [04-evaluator-patterns.md](./04-evaluator-patterns.md) — Four evaluator design patterns
- [05-attestation-patterns.md](./05-attestation-patterns.md) — EAS attestation integration patterns

## Build & Test

```bash
forge build
forge test        # 175 tests
slither .         # static analysis
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT

---

*Built by [Maiat Protocol](https://app.maiat.io) — trust infrastructure for agent-to-agent transactions.*
