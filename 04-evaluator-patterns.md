# Evaluator Patterns

The evaluator role in ERC-8183 is a critical trust primitive. This document describes common patterns for building evaluators and an optional discovery mechanism.

## Overview

Every job in AgenticCommerce has a mandatory `evaluator` address. The evaluator is responsible for calling `complete()` or `reject()` after reviewing the provider's deliverable. This document covers:

1. **Trust-Based Evaluator** — Uses an on-chain trust oracle to auto-evaluate
2. **Trust Gate Hook** — Pre-screens participants via trust scores (with dynamic thresholds)
3. **Evaluator Registry** — Multi-evaluator discovery with trust-ranked results
4. **Trust-Ranked Discovery** — How all three work together to solve ACP's discovery gap

---

## Pattern 1: Trust-Based Evaluator

The simplest production evaluator checks the provider's reputation score and auto-approves above a threshold.

**Contract:** [`contracts/hooks/TrustBasedEvaluator.sol`](./contracts/hooks/TrustBasedEvaluator.sol)

```
Job Submitted
    → Evaluator reads provider trust score from oracle
    → Score >= threshold? → complete(jobId)
    → Score < threshold?  → reject(jobId)
    → [v1.1] registry.recordOutcome(address(this), approved)
                → Registry updates performance stats
                → Rankings adjust for future discovery queries
```

**Key design decisions:**
- Uses an external trust oracle (any contract implementing `getUserData(address)`)
- Double-evaluation prevention via `evaluated` mapping
- Configurable threshold allows operators to tune strictness
- Emits `JobEvaluated` events for off-chain indexing

**v1.1: Registry Feedback Loop**

After each evaluation, `TrustBasedEvaluator` calls `registry.recordOutcome()` to update its own performance stats on-chain. This creates a self-optimizing loop: evaluators with high real-world success rates rise in the rankings, while consistently poor performers get automatically de-listed.

The registry call is wrapped in `try/catch` so that registry failures (e.g., not yet authorized) never block the evaluation itself.

**Setup for feedback loop:**
```solidity
// 1. Deploy evaluator
evaluator = TrustBasedEvaluator.initialize(oracle, agenticCommerce, minScore, owner);

// 2. Connect to registry
evaluator.setRegistry(address(registry));

// 3. Authorize evaluator to call recordOutcome on the registry
registry.setAuthorized(address(evaluator), true);
```

**When to use:** When you have an on-chain reputation system and want fully automated evaluation with on-chain performance tracking.

---

## Pattern 2: Trust Gate Hook

Hooks intercept state transitions *before* they happen. A trust gate hook blocks untrusted agents from funding or submitting jobs.

**Contract:** [`contracts/hooks/TrustGateACPHook.sol`](./contracts/hooks/TrustGateACPHook.sol)

```
Client calls fund()
    → Hook: beforeAction(FUND_SEL)
    → Determine threshold: base OR tier-based (whichever is higher)
    → Check client trust score against threshold
    → Score < threshold? → revert (blocks the fund)

Provider calls submit()
    → Hook: beforeAction(SUBMIT_SEL)
    → Determine threshold: base OR tier-based (whichever is higher)
    → Check provider trust score against threshold
    → Score < threshold? → revert (blocks the submission)

Evaluator calls complete/reject
    → Hook: afterAction(COMPLETE_SEL / REJECT_SEL)
    → Record outcome event (never reverts)
```

**Key design decisions:**
- `beforeAction` can revert to block transitions — use for gating
- `afterAction` should NEVER revert — it records outcomes for indexing
- Both read from the same trust oracle, sharing reputation data

**v1.1: Dynamic Thresholds by Job Value**

Higher-value jobs require higher trust scores. Configure value tiers with `setTierThreshold(minValue, requiredScore)`. The highest matching tier wins.

```solidity
// Jobs ≥ $1k  → trust score ≥ 60
hook.setTierThreshold(1_000e6,   60);
// Jobs ≥ $10k → trust score ≥ 80
hook.setTierThreshold(10_000e6,  80);
// Jobs ≥ $100k → trust score ≥ 95
hook.setTierThreshold(100_000e6, 95);
```

The hook reads the job's budget from AgenticCommerce at gate time, then applies the most restrictive matching tier. Gracefully falls back to baseline if the job lookup fails.

**When to use:** When you want to prevent low-trust agents from participating at all (before evaluation), with stricter requirements for high-value jobs.

---

## Pattern 3: Evaluator Registry (v1.0)

For ecosystems with multiple evaluator providers, the on-chain registry enables dynamic discovery by domain — with trust-ranked results and automatic performance enforcement.

**Contract:** [`contracts/EvaluatorRegistry.sol`](./contracts/EvaluatorRegistry.sol)

### v1.0 vs v0

| Feature | v0 | v1.0 |
|---|---|---|
| Evaluators per domain | 1 (overwritten on re-register) | Many (list-based) |
| Performance tracking | None | `totalJobs`, `totalApproved`, `totalRejected` |
| Discovery | Returns exact address | Returns sorted by success rate |
| Auto-delisting | No | Yes — below threshold after min jobs |
| Pagination | None | `offset + limit` parameters |
| Outcome recording | N/A | `recordOutcome(evaluator, bool)` |

### Core operations

```solidity
// Register multiple evaluators for the same domain
registry.register("trust", 0xMaiatEvaluator);
registry.register("trust", 0xAltEvaluator);

// Get the top-ranked active evaluator (backward-compatible)
address best = registry.getEvaluator("trust");

// Get sorted, paginated list (first 10)
EvaluatorRegistry.EvaluatorView[] memory ranked =
    registry.getEvaluators("trust", 0, 10);
// ranked[0] = highest success rate
// ranked[1] = second highest, etc.

// Record an outcome (callable by hooks / AgenticCommerce)
registry.recordOutcome(evaluatorAddress, true);   // approved
registry.recordOutcome(evaluatorAddress, false);  // rejected

// Authorize AgenticCommerce and hooks to call recordOutcome
registry.setAuthorized(address(agenticCommerce), true);
registry.setAuthorized(address(trustGateHook), true);
```

### Auto-delisting

Evaluators below `minSuccessRateBP` (default: 30%) after `minJobsForThreshold` (default: 10) jobs are automatically marked inactive and excluded from query results. Admins can reactivate via `registry.reactivate(evaluator)`.

**When to use:** When your ecosystem has multiple evaluators and agents need to discover and rank them dynamically.

---

## Pattern 4: Trust-Ranked Discovery

> **This is the pattern that solves ACP's discovery gap.**

### The Problem

ACP (Agent Commerce Protocol by Virtuals) has no built-in evaluator discovery mechanism. Developers hardcode evaluator addresses, which:
- Creates vendor lock-in (switching evaluators requires redeployment)
- Enables wash trading (a single actor can register as both client and evaluator)
- Has no accountability mechanism (bad evaluators stay listed forever)

### The Solution: Three-Layer Trust Infrastructure

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: DISCOVERY (EvaluatorRegistry)                         │
│  "Who is the best evaluator for this domain?"                   │
│                                                                 │
│  registry.getEvaluator("trust") → 0xMaiatEvaluator             │
│  ↑ Returns highest success-rate active evaluator                │
└─────────────────────────┬───────────────────────────────────────┘
                          │ evaluator address
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: GATING (TrustGateACPHook)                             │
│  "Are this client and provider trustworthy enough?"             │
│                                                                 │
│  createJob(evaluator: 0xMaiat, hook: 0xTrustGate)              │
│  → fund()   → hook checks client score (+ job value tier)      │
│  → submit() → hook checks provider score (+ job value tier)    │
└─────────────────────────┬───────────────────────────────────────┘
                          │ job flows through
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: EVALUATION + FEEDBACK (TrustBasedEvaluator)           │
│  "Did the provider deliver? Update the record."                 │
│                                                                 │
│  evaluate(jobId) → complete() OR reject()                       │
│                  → registry.recordOutcome(this, approved)       │
│                  → ↑ registry updates success rate              │
│                  → ↑ if rate drops below threshold → delist     │
└─────────────────────────────────────────────────────────────────┘
```

### Full Deployment Flow

```solidity
// Step 1: Deploy registry
EvaluatorRegistry registry = new EvaluatorRegistry();
registry.initialize(owner);

// Step 2: Deploy evaluator, pointing at registry
TrustBasedEvaluator evaluator = new TrustBasedEvaluator();
evaluator.initialize(oracle, agenticCommerce, 70, owner);
evaluator.setRegistry(address(registry));

// Step 3: Deploy hook with value tiers
TrustGateACPHook hook = new TrustGateACPHook();
hook.initialize(oracle, agenticCommerce, 50, 60, owner);
hook.setTierThreshold(10_000e6, 80);   // $10k+ jobs need score ≥ 80
hook.setTierThreshold(100_000e6, 95);  // $100k+ jobs need score ≥ 95

// Step 4: Register evaluator in registry
registry.register("trust", address(evaluator));
registry.setMetadata(address(evaluator), "ipfs://Qm...");

// Step 5: Authorize feedback loop
registry.setAuthorized(address(evaluator), true);

// Step 6: Client creates a job — dynamically resolved
address bestEvaluator = registry.getEvaluator("trust");  // top-ranked
agenticCommerce.createJob(provider, bestEvaluator, hook, description, budget, expiry);
```

### How the Feedback Loop Works

```
Job 1 completes → evaluator.evaluate() → agenticCommerce.complete()
                                       → registry.recordOutcome(evaluator, true)
                                          stats: 1 job, 1 approved, 100% rate

Job 2 rejected  → evaluator.evaluate() → agenticCommerce.reject()
                                       → registry.recordOutcome(evaluator, false)
                                          stats: 2 jobs, 1 approved, 50% rate

... after 10 jobs, if rate < 30% → auto-delist → next query returns next-best evaluator
```

This creates **on-chain accountability**: evaluators compete on real performance, not marketing. The registry becomes a living leaderboard that agents trust because it reflects actual outcomes.

---

## Building Your Own Evaluator

1. Implement the evaluation logic (on-chain or hybrid)
2. Call `complete()` or `reject()` on AgenticCommerce
3. Call `registry.recordOutcome(address(this), approved)` for feedback loop participation
4. Register in EvaluatorRegistry with `register(domain, address(this))`
5. Set metadata URI so agents can discover your documentation

## Security Considerations

- **Evaluators are trusted** — they control fund release. Audit thoroughly.
- **Double-evaluation** — Use a `evaluated` mapping to prevent re-evaluation.
- **Hooks should not revert in afterAction** — this would block legitimate transitions.
- **Trust scores are only as good as the oracle** — ensure the oracle has sufficient data.
- **recordOutcome authorization** — Only grant `setAuthorized` to contracts you control.
  A compromised authorized caller can inflate or deflate evaluator stats.
- **Registry feedback is best-effort** — `TrustBasedEvaluator` wraps the registry call
  in `try/catch`. Ensure `setAuthorized` is configured before going live or stats
  won't accumulate. Monitor `OutcomeReportFailed` events for silent failures.
- **Value tier bypass** — `TrustGateACPHook` falls back to baseline threshold if job
  lookup fails. Do not rely on tiers for critical security boundaries without also
  validating budget on-chain elsewhere.
