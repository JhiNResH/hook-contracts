# 🛡️ Security Audit Report: ERC-8183 PR #6 — Trust System

**Auditor:** Jensen (Trail of Bits audit-context-building + Cyfrin + Pashov methodology)
**Date:** 2026-03-22
**Scope:** TrustBasedEvaluator.sol, TrustGateACPHook.sol, EvaluatorRegistry.sol
**Commit:** `feat/trust-evaluator-hook` branch

---

## 1. Cyfrin Standards Compliance

| Standard | TrustBasedEvaluator | TrustGateACPHook | EvaluatorRegistry |
|----------|:---:|:---:|:---:|
| Custom errors (`ContractName__` prefix) | ✅ | ✅ | ✅ |
| Named imports | ❌ (path imports) | ❌ (path imports) | ❌ (path imports) |
| Function ordering (ext→pub→int→priv) | ⚠️ mixed | ⚠️ mixed | ⚠️ mixed |
| `@custom:security-contact` NatSpec | ❌ | ❌ | ❌ |
| Events for all state changes | ⚠️ (setMinTrustScore, setOracle, setAgenticCommerce have no events) | ⚠️ (setOracle, setAgenticCommerce, setThresholds have no events) | ✅ |

---

## 2. Entry Point Analysis

### TrustBasedEvaluator.sol

| Function | Access | State Changes | External Calls |
|----------|--------|---------------|----------------|
| `initialize()` | Public (once) | oracle, agenticCommerce, minTrustScore, owner | None |
| `evaluate()` | Public (anyone) | evaluated[], totalEvaluated, totalApproved/Rejected | oracle.getUserData(), agenticCommerce.complete/reject(), registry.recordOutcome() |
| `setRegistry()` | onlyOwner | registry | None |
| `setMinTrustScore()` | onlyOwner | minTrustScore | None |
| `setOracle()` | onlyOwner | oracle | None |
| `setAgenticCommerce()` | onlyOwner | agenticCommerce | None |

### TrustGateACPHook.sol

| Function | Access | State Changes | External Calls |
|----------|--------|---------------|----------------|
| `initialize()` | Public (once) | oracle, agenticCommerce, thresholds, owner | None |
| `beforeAction()` | Public (anyone) | None (reverts or passes) | oracle.getUserData(), agenticCommerce.getJob() |
| `afterAction()` | Public (anyone) | None (events only) | None |
| `setThresholds()` | onlyOwner | clientThreshold, providerThreshold | None |
| `setTierThreshold()` | onlyOwner | _tiers[] | None |
| `setOracle()` | onlyOwner | oracle | None |
| `setAgenticCommerce()` | onlyOwner | agenticCommerce | None |

### EvaluatorRegistry.sol

| Function | Access | State Changes | External Calls |
|----------|--------|---------------|----------------|
| `initialize()` | Public (once) | owner, minSuccessRateBP, minJobsForThreshold | None |
| `register()` | onlyOwner | _domainEvaluators[], _evalDomainIdx, _domains[], _stats[] | None |
| `remove()` | onlyOwner | _domainEvaluators[], _evalDomainIdx | None |
| `setMetadata()` | onlyOwner | _metadataURIs | None |
| `recordOutcome()` | Authorized | _stats[] (totalJobs, approved, rejected, active) | None |
| `setAuthorized()` | onlyOwner | _authorized | None |
| `setThreshold()` | onlyOwner | minSuccessRateBP, minJobsForThreshold | None |
| `reactivate()` | onlyOwner | _stats[].active | None |

---

## 3. Deep Function Analysis (Trail of Bits audit-context-building)

### 3.1 TrustBasedEvaluator.evaluate()

**Purpose:** Core evaluation logic. Anyone can trigger evaluation of a submitted job. Checks provider trust score via oracle → auto-approve or reject → record outcome.

**Execution Flow (block-by-block):**

```
Line 1: if (evaluated[jobId]) revert  ← Idempotency guard. GOOD.
Line 2: job = agenticCommerce.getJob(jobId)  ← EXTERNAL CALL #1 (view, low risk)
Line 3: if (job.status != Submitted) revert  ← Status check
Line 4: if (job.evaluator != address(this)) revert  ← Self-check
Line 5: evaluated[jobId] = true  ← STATE WRITE (before external calls = CEI ✅)
Line 6: totalEvaluated++  ← STATE WRITE
Line 7: rep = oracle.getUserData(job.provider)  ← EXTERNAL CALL #2 (view, oracle manipulation risk)
Line 8-9: score calculation, approval decision  ← Pure logic
Line 10-14: if(approved) { totalApproved++; agenticCommerce.complete() }  ← STATE WRITE + EXTERNAL CALL #3
         else { totalRejected++; agenticCommerce.reject() }  ← STATE WRITE + EXTERNAL CALL #4
Line 15: emit JobEvaluated(...)  ← Event AFTER external calls ⚠️
Line 16: _reportOutcomeToRegistry(approved)  ← EXTERNAL CALL #5 (try/catch, safe)
```

**5 Whys — Why is the external call order risky?**
1. Why does `agenticCommerce.complete()` matter? → It changes job status on AC contract
2. Why could AC call back? → AC may call `hook.afterAction()` inside `complete()`
3. Why does afterAction matter? → TrustGateACPHook.afterAction emits OutcomeRecorded
4. Why could that be a problem? → If hook has more complex logic in future, reentrant path exists
5. Why is it not critical now? → `evaluated[jobId]=true` blocks same-job reentry; afterAction is event-only

**Invariants:**
- I1: Each jobId evaluated exactly once (enforced by `evaluated` mapping)
- I2: totalEvaluated == totalApproved + totalRejected (maintained by branching logic)
- I3: Only Submitted jobs can be evaluated

**Cross-contract flow:**
```
evaluate() → agenticCommerce.complete(jobId)
  → [inside AC] job.status = Completed
  → [inside AC] hook.afterAction(jobId, COMPLETE_SEL, data)
    → [inside TrustGateACPHook] emit OutcomeRecorded(jobId, true)
  → [back in AC] return
→ [back in evaluate()] emit JobEvaluated
→ _reportOutcomeToRegistry → registry.recordOutcome()
```

### 3.2 TrustGateACPHook.beforeAction()

**Purpose:** Gate fund/submit operations by trust score. Revert blocks the AC state transition.

**Execution Flow:**
```
Line 1: if selector == FUND_SEL → decode (address caller, bytes) from data
Line 2: threshold = _effectiveThreshold(jobId, clientThreshold)
  → tries agenticCommerce.getJob(jobId) for budget
  → walks _tiers[] to find highest matching tier
  → falls back to baseThreshold on any failure
Line 3: _checkTrust(jobId, caller, threshold)
  → oracle.getUserData(caller) ← EXTERNAL CALL
  → score < threshold → revert with TrustTooLow
  → score >= threshold → emit TrustGated, continue
```

**First Principles — What assumptions does abi.decode make?**
- Assumes `data` layout matches AC's actual encoding
- If AC changes parameter order → silent wrong-address decode
- No validation of decoded address (could be address(0))

**5 Whys — Why is no caller restriction a problem?**
1. Anyone can call beforeAction → yes
2. Can they cause damage? → beforeAction either reverts or passes, no state change
3. What about afterAction? → emits events only, but fake events pollute indexers
4. Why pollute indexers? → Off-chain systems might count fake OutcomeRecorded events
5. Is this exploitable for financial gain? → Not directly, but degrades data integrity

### 3.3 EvaluatorRegistry.recordOutcome()

**Purpose:** Update evaluator performance stats. Auto-delist if below threshold.

**Execution Flow:**
```
Line 1: if (!_authorized[msg.sender]) revert  ← Access control ✅
Line 2: if (evaluator == address(0)) revert  ← Zero check ✅
Line 3: stats.totalJobs++  ← Increment
Line 4: if (approved) stats.totalApproved++ else stats.totalRejected++
Line 5: rateBP = _successRateBP(approved, total)
Line 6: if (active && totalJobs >= threshold && rateBP < min) → delist
```

**5 Whys — Gaming the auto-delist:**
1. Can an attacker delist a competitor? → Need authorized status
2. Can authorized caller spam rejections? → Yes, if they're authorized
3. Who grants authorized? → Owner only (onlyOwner setAuthorized)
4. Can the evaluator itself be authorized? → Yes — TrustBasedEvaluator calls recordOutcome(address(this), approved)
5. What if evaluator is compromised? → It can only record outcomes for itself (address(this))

**Key insight:** An authorized caller can record outcomes for ANY address, including unregistered ones. This creates phantom stats.

### 3.4 EvaluatorRegistry._removeFromDomain()

**Purpose:** Swap-and-pop removal from domain's evaluator list.

```
idx = _evalDomainIdx[evaluator][domain] - 1  ← Convert 1-indexed to 0-indexed
lastIdx = list.length - 1
if (idx != lastIdx) {
  list[idx] = list[lastIdx]  ← Swap last element into removed slot
  _evalDomainIdx[last][domain] = idxOneBased  ← Update swapped element's index
}
list.pop()  ← Remove last element
delete _evalDomainIdx[evaluator][domain]  ← Clear removed element's index
```

**Invariant check:** After removal, all remaining elements have correct 1-indexed positions. ✅
**Edge case:** Single element removal (idx == lastIdx) — just pop, no swap needed. ✅

---

## 4. Cross-Contract Trust Boundary Analysis

```
┌─────────────────────┐
│   TrustOracle       │ ← READ-ONLY dependency (both Evaluator + Hook read from it)
│  (external, black   │    Risk: Oracle returns manipulated scores
│   box)              │    Mitigation: None in contracts — trusts oracle implicitly
└─────────────────────┘
         │ getUserData()
         ▼
┌─────────────────────┐     beforeAction()     ┌─────────────────────┐
│  TrustGateACPHook   │ ◄──────────────────── │  AgenticCommerce    │
│  (gates fund/submit)│ ────────────────────► │  (job lifecycle)    │
│                     │     afterAction()      │                     │
└─────────────────────┘                        └─────────────────────┘
                                                        │
                                                        │ complete/reject
                                                        ▼
                                               ┌─────────────────────┐
                                               │ TrustBasedEvaluator │
                                               │ (auto-evaluation)   │
                                               └─────────────────────┘
                                                        │
                                                        │ recordOutcome()
                                                        ▼
                                               ┌─────────────────────┐
                                               │ EvaluatorRegistry   │
                                               │ (stats + ranking)   │
                                               └─────────────────────┘
```

**Trust boundaries:**
1. Oracle → All contracts: **Implicit trust** — no score range validation, no staleness check
2. AC → Hook: **Trusted caller assumption** — but no msg.sender check enforced
3. Evaluator → AC: **Trusted** — evaluator must be assigned evaluator for the job
4. Evaluator → Registry: **Authorized** — must be in _authorized mapping

---

## 5. Findings

### [HIGH] TBE-01 — Cross-Contract Reentrancy Path via evaluate()

**Contract:** TrustBasedEvaluator.sol
**Impact:** `agenticCommerce.complete/reject()` is called mid-function before `emit JobEvaluated` and `_reportOutcomeToRegistry`. If AgenticCommerce triggers hook callbacks (afterAction), and a future hook has state-changing logic, the evaluation's event emission and registry recording happen AFTER the reentrant call returns. While `evaluated[jobId]=true` prevents same-job re-evaluation, ordering of events and registry updates can be manipulated.

**Proof of Concept:**
```
1. Attacker calls evaluate(jobId=1)
2. evaluated[1] = true, totalApproved++
3. agenticCommerce.complete(1) is called
4. Inside AC: hook.afterAction(1) fires
5. If hook calls back into some other contract that reads totalApproved, it sees the incremented value BUT JobEvaluated event hasn't been emitted yet
6. Registry outcome hasn't been recorded yet
```

**Recommendation:** Add `ReentrancyGuardUpgradeable` from OpenZeppelin. Or reorder: emit event → record registry → then call AC.complete/reject.

---

### [HIGH] TBE-02 — Initialization Front-Running (All 3 Contracts)

**Contract:** TrustBasedEvaluator, TrustGateACPHook, EvaluatorRegistry
**Impact:** All three use `initializer` modifier but lack `_disableInitializers()` in constructor. If proxy deployment and initialization are not atomic, an attacker can front-run `initialize()` to become owner of any/all contracts.

**Pashov pattern:** This is a well-known proxy deployment vulnerability. Trail of Bits recommends ALWAYS adding constructor disable.

**Proof of Concept:**
```solidity
// Attacker watches mempool for proxy deployment
// Sees TransparentProxy created at 0x1234
// Before deployer calls initialize(), attacker calls:
TrustBasedEvaluator(0x1234).initialize(attackerOracle, attackerAC, 0, attacker);
// Attacker is now owner
```

**Recommendation:** Add to all three contracts:
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```

---

### [MEDIUM] TGH-01 — No Access Control on beforeAction/afterAction

**Contract:** TrustGateACPHook.sol
**Impact:** Anyone can call `afterAction()` with arbitrary jobId and selector, emitting fake `OutcomeRecorded` events. Off-chain indexers that count these events for analytics will receive polluted data. `beforeAction()` is less concerning (it either reverts or emits TrustGated), but shouldn't be publicly callable either.

**Recommendation:** Add `msg.sender == address(agenticCommerce)` check:
```solidity
error TrustGateACPHook__OnlyAgenticCommerce();

function beforeAction(...) external override {
    if (msg.sender != address(agenticCommerce)) revert TrustGateACPHook__OnlyAgenticCommerce();
    ...
}
```

---

### [MEDIUM] TGH-02 — abi.decode Assumes Exact Parameter Layout

**Contract:** TrustGateACPHook.sol, `beforeAction()`
**Impact:** If AgenticCommerce changes the parameter encoding for `fund()` or `submit()`, the decoded `caller` address could be incorrect — potentially checking trust for the wrong party. No validation that decoded address ≠ address(0).

**Description:**
```solidity
// FUND_SEL: assumes data = abi.encode(address caller, bytes optParams)
(address caller,) = abi.decode(data, (address, bytes));
// If AC actually sends abi.encode(uint256 amount, address caller, bytes opt)
// → 'caller' would decode as a uint256 truncated to address → wrong entity checked
```

**Recommendation:** Add zero-address check after decode. Document expected encoding in NatSpec with version tag.

---

### [MEDIUM] REG-01 — recordOutcome Allows Phantom Stats for Unregistered Evaluators

**Contract:** EvaluatorRegistry.sol
**Impact:** An authorized caller can call `recordOutcome(anyAddress, true/false)` even if `anyAddress` was never registered. This creates stats for phantom evaluators. An attacker with authorized status could pre-inflate stats for an address they plan to register later, gaming the ranking system from day one.

**Proof of Concept:**
```solidity
// Authorized caller (compromised or malicious evaluator)
registry.recordOutcome(futureEvaluatorAddress, true); // ×100 times
// Later, owner registers futureEvaluatorAddress
registry.register("trust", futureEvaluatorAddress);
// futureEvaluatorAddress immediately has 100% success rate with 100 jobs
// → ranked #1 in getEvaluator("trust")
```

**Recommendation:** Add registration check:
```solidity
error EvaluatorRegistry__NotRegisteredAnywhere();
// Check that evaluator has at least one domain registration
// Or add a global `isRegistered` flag
```

---

### [MEDIUM] REG-02 — _domains Array Only Grows, No Cleanup

**Contract:** EvaluatorRegistry.sol
**Impact:** `_domains` array grows with every new domain but never shrinks, even if all evaluators are removed from a domain. `getDomains()` returns stale entries. Gas cost for enumeration increases linearly forever.

**Recommendation:** Track active evaluator count per domain. Add domain cleanup when count reaches 0.

---

### [LOW] TBE-03 — Admin Setters Accept address(0) Without Validation

**Contract:** TrustBasedEvaluator.sol
**Impact:** `setOracle(address(0))`, `setAgenticCommerce(address(0))` silently succeed. Next `evaluate()` call will revert with an unhelpful low-level error when trying to call a zero address.

**Recommendation:** Add zero-address checks to all admin setters.

---

### [LOW] TGH-03 — Admin Setters Accept address(0)

**Contract:** TrustGateACPHook.sol
**Impact:** Same as TBE-03. `setOracle(address(0))` breaks all trust checks.

**Recommendation:** Zero-address validation on setOracle and setAgenticCommerce.

---

### [LOW] TGH-04 — _tiers Array Unbounded Growth, No Removal

**Contract:** TrustGateACPHook.sol
**Impact:** No way to remove tiers. Each new `setTierThreshold()` with unique minValue grows array permanently. `_effectiveThreshold()` iterates all tiers on every call. O(n) per hook invocation.

**Recommendation:** Add `removeTier(uint256 minValue)` function. Consider max tier cap (e.g., 20).

---

### [LOW] REG-03 — reactivate() Ignores Current Stats

**Contract:** EvaluatorRegistry.sol
**Impact:** Owner can reactivate a delisted evaluator even if their stats still fail the threshold. They'll be immediately delisted again on the next `recordOutcome()` call.

**Recommendation:** Either check stats before reactivation, or document this as intentional admin override. Consider adding stats reset option.

---

### [LOW] TBE-04 — Missing Events on Admin State Changes

**Contract:** TrustBasedEvaluator.sol
**Impact:** `setMinTrustScore()`, `setOracle()`, `setAgenticCommerce()` change critical parameters without emitting events. Off-chain monitoring cannot detect configuration changes.

**Recommendation:** Add events for all admin setters:
```solidity
event MinTrustScoreUpdated(uint256 oldScore, uint256 newScore);
event OracleUpdated(address indexed oldOracle, address indexed newOracle);
event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
```

---

### [LOW] TGH-05 — Missing Events on Admin State Changes

**Contract:** TrustGateACPHook.sol
**Impact:** Same as TBE-04. `setOracle()`, `setAgenticCommerce()`, `setThresholds()` have no events.

---

### [INFORMATIONAL] ALL-01 — Duplicate ITrustOracle Interface Definitions

**Contracts:** TrustBasedEvaluator.sol, TrustGateACPHook.sol
**Impact:** ITrustOracle is defined separately in both contracts with DIFFERENT struct fields:
- TBE: `{reputationScore, totalReviews, initialized, lastUpdated}` (4 fields)
- TGH: `{reputationScore, initialized}` (2 fields)

ABI decoding will still work (extra fields ignored), but this is fragile and confusing.

**Recommendation:** Extract ITrustOracle into a shared `interfaces/ITrustOracle.sol` file.

---

### [INFORMATIONAL] ALL-02 — No Upgrade Gap Slots

**Contracts:** All 3
**Impact:** For upgradeable contracts, OpenZeppelin recommends reserving storage gap slots (`uint256[50] private __gap`) to prevent storage collision when adding new state variables in future upgrades.

**Recommendation:** Add `uint256[50] private __gap;` at the end of each contract's storage.

---

### [INFORMATIONAL] ALL-03 — Oracle Trust is Implicit

**Contracts:** TrustBasedEvaluator, TrustGateACPHook
**Impact:** Both contracts trust oracle scores without range validation. A compromised or buggy oracle returning `reputationScore = type(uint256).max` would auto-approve any agent. No staleness check on `lastUpdated`.

**Recommendation:** Add sanity bounds: `require(score <= MAX_SCORE)` where MAX_SCORE = 100.

---

## 6. Summary

| Severity | Count | IDs |
|----------|:---:|-----|
| Critical | 0 | — |
| High | 2 | TBE-01 (reentrancy), TBE-02 (init front-run) |
| Medium | 4 | TGH-01 (access control), TGH-02 (abi.decode), REG-01 (phantom stats), REG-02 (domain growth) |
| Low | 5 | TBE-03, TGH-03, TGH-04, REG-03, TBE-04/TGH-05 (missing events) |
| Informational | 3 | ALL-01 (duplicate interface), ALL-02 (no gap slots), ALL-03 (oracle trust) |
| **Total** | **14** | |

## 7. Recommended Fix Priority

1. **Immediate (before merge):** TBE-02 (`_disableInitializers` constructor) — trivial fix, prevents catastrophic ownership takeover
2. **High priority:** TBE-01 (ReentrancyGuard or CEI reorder), TGH-01 (access control on hook functions)
3. **Should fix:** REG-01 (phantom stats), ALL-02 (storage gaps), TBE-03/TGH-03 (zero-address checks)
4. **Nice to have:** Event additions, tier removal, domain cleanup

---

*Report generated using Trail of Bits audit-context-building methodology (line-by-line analysis, 5 Whys, cross-contract flow tracing), Cyfrin standards compliance check, and Pashov entry-point analysis pattern.*
