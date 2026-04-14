# Trail of Bits AI Assessment — maiat8183

**Date:** 2026-04-14
**Assessor:** Trail of Bits building-secure-contracts skill suite (code-maturity-assessor + guidelines-advisor + audit-prep-assistant)
**Frameworks:** Building Secure Contracts v0.1.0
**Scope:** 6 in-scope contracts (same scope as Pashov audit PR #5)
**Compiler:** Solidity ^0.8.20 / Foundry
**Tests run:** 225 total, 0 failed

---

## In-Scope Contracts

| Contract | Lines | Type | Upgradeable |
|----------|-------|------|-------------|
| `AgenticCommerceHooked.sol` | 332 | Core escrow | No |
| `EvaluatorRegistry.sol` | 374 | Registry | UUPS |
| `hooks/TrustBasedEvaluator.sol` | 267 | Evaluator | UUPS |
| `hooks/TrustGateACPHook.sol` | 360 | Hook | UUPS |
| `hooks/CompositeRouterHook.sol` | 408 | Hook | UUPS |
| `hooks/TrustUpdateHook.sol` | 210 | Hook | No (immutable) |

---

## Part 1 — Code Maturity Scorecard

| Category | Rating | Score | Key Finding |
|----------|--------|-------|-------------|
| Arithmetic | Satisfactory | 3/4 | Safe ^0.8.20 math; `_successRateBP(0,0)=10000` edge case |
| Auditing | Moderate | 2/4 | Good events; missing nonce in closeAndSettle; no monitoring plan |
| Authentication / Access Controls | **Weak** | 1/4 | 5 access control findings (F-01–F-05 from Pashov) |
| Complexity Management | Moderate | 2/4 | `closeAndSettle` oversized; O(n²) sort in view fn |
| Decentralization | **Weak** | 1/4 | Single owner, no timelock, single trustedGateway SPOF |
| Documentation | Moderate | 2/4 | Good NatSpec on closeAndSettle; gaps on setBudget/fund/createJob |
| Transaction Ordering Risks | **Weak** | 1/4 | Signature replay (no nonce); oracle-moment attack; budget griefing |
| Low-Level Manipulation | Satisfactory | 3/4 | SafeERC20 ✓; gas-limited hooks ✓; staticcall decode partially validated |
| Testing & Verification | Moderate | 2/4 | 225 tests; CompositeRouterHook 10% coverage; no fuzzing |

**Overall Maturity: 1.89 / 4.0 (Weak-to-Moderate)**

> Benchmark: Pre-audit Solidity projects typically score 1.5–2.5. This codebase is at the low end but has solid fundamentals — the gaps are addressable in 1–2 weeks.

---

## Part 2 — Guidelines Advisor Findings

### 2.1 Documentation & Specifications

**Status: Moderate gaps**

| Gap | Location | Severity |
|-----|----------|----------|
| No `@param`/`@return` NatSpec | `createJob`, `setBudget`, `fund`, `submit` | Medium |
| System invariants not documented | All contracts | Medium |
| No formal glossary | — | Low |
| No ARCHITECTURE.md or sequence diagrams | — | Low |
| No user stories for keeper/client/provider/evaluator flows | — | Low |

`closeAndSettle` is well-documented (best in codebase). `TrustUpdateHook` has detailed flow comments. The pattern is inconsistent — bring the whole codebase up to the `closeAndSettle` standard.

---

### 2.2 On-Chain / Off-Chain Architecture

**Status: Mostly sound, gaps in documentation**

| Observation | Note |
|-------------|------|
| `evaluate()` requires off-chain keeper | Not documented anywhere — keeper liveness is a protocol assumption |
| `closeAndSettle` requires gateway signer | Documented in NatSpec ✓ |
| Oracle reads are synchronous | No freshness/staleness check on trust score |
| Gateway is a single EOA | SPOF — no rotation mechanism defined for mainnet |

**Recommendation:** Document the keeper liveness assumption. Add oracle freshness (e.g., `lastUpdated + MAX_STALENESS` check) before mainnet.

---

### 2.3 Upgradeability

**Status: Partially correct — asymmetry issue**

| Check | Result |
|-------|--------|
| UUPS pattern | ✓ OZ v5 standard |
| `_disableInitializers()` in constructors | ✓ All 4 UUPS contracts |
| Storage gaps | ✓ 40–44 slots per contract |
| `__Ownable_init` called in initializers | ✓ |
| `authorizeUpgrade` override | OZ default (onlyOwner) — no timelock |
| TrustUpdateHook upgradeability | **No** — uses `immutable` storage |
| AgenticCommerceHooked upgradeability | **No** — not upgradeable |

**Critical asymmetry:** `AgenticCommerceHooked` (the core escrow that holds USDC) is NOT upgradeable. If a critical bug is found post-deploy, full migration is required. All hook contracts are UUPS upgradeable, but the escrow itself is not. Before mainnet, either make `AgenticCommerceHooked` upgradeable or add a migration path (e.g., admin pause + drain).

**Recommendation:** Add `emergencyPause()` + `drainTo(address)` functions gated by `ADMIN_ROLE` so stuck funds can be rescued without requiring a new escrow deployment.

---

### 2.4 Proxy / Delegatecall Patterns

**Status: Correct**

- No custom proxy implementation — OZ UUPS used throughout ✓
- No storage collision risk (dedicated storage gap arrays) ✓
- No function shadowing detected ✓
- `authorizeUpgrade` not overridden → `_authorizeUpgrade(address)` resolves to `OwnableUpgradeable.onlyOwner` ✓

Only gap: no upgrade timelock. Upgrade can be executed in a single tx by owner.

---

### 2.5 Function Composition

**Status: Mostly clean, one structural issue**

| Observation | File | Line |
|-------------|------|------|
| `closeAndSettle` is 50+ lines with complex branching | `AgenticCommerceHooked.sol` | 280–326 |
| `_beforeHook`/`_afterHook` asymmetry (no try/catch vs try/catch) | `AgenticCommerceHooked.sol` | 105–115 |
| `_reportOutcomeToRegistry` correctly extracted | `TrustBasedEvaluator.sol` | 256–265 |
| `_effectiveThreshold` cleanly abstracted | `TrustGateACPHook.sol` | 307–331 |
| `_getSortedIndices` clear and bounded | `CompositeRouterHook.sol` | 383–406 |

**Recommendation:** Extract payment logic from `closeAndSettle` into `_executePayment(uint256 jobId, bool passed, uint256 budget)`. Bring `_beforeHook` inline with `_afterHook`'s try/catch pattern or document the intentional asymmetry.

---

### 2.6 Inheritance

**Status: Clean**

```
AgenticCommerceHooked  → AccessControl, ReentrancyGuard
EvaluatorRegistry      → OwnableUpgradeable
TrustBasedEvaluator    → OwnableUpgradeable, ReentrancyGuard
TrustGateACPHook       → IACPHook, OwnableUpgradeable
CompositeRouterHook    → IACPHook, OwnableUpgradeable
TrustUpdateHook        → BaseACPHook
BaseACPHook            → IACPHook
```

No diamond problem. Depth is ≤ 2. No function shadowing detected.

---

### 2.7 Events

**Status: Mostly good, three gaps**

| Missing Event | Function | Impact |
|---------------|----------|--------|
| No `who` (client vs provider) field | `BudgetSet` | Hard to attribute setBudget call in monitoring |
| No nonce in `JobSettled` | `closeAndSettle` | Can't detect replay in event stream |
| `PluginBeforeActionFailed` defined but never emitted | `CompositeRouterHook` | Reverting plugins are opaque |

All critical state transitions have events. `JobSettled(jobId, msg.sender, passRate, passed)` is clean. Token transfers emit both contract event and ERC-20 `Transfer`.

---

### 2.8 Common Pitfalls

| Pitfall | Present? | Note |
|---------|----------|------|
| Reentrancy | Partially ✓ | `setBudget` lacks `nonReentrant` but no external calls |
| Integer overflow | N/A | Solidity 0.8.x ✓ |
| Tx-origin authentication | No ✓ | |
| Unchecked return values | 1 gap | `_beforeHook` staticcall in TrustGateACPHook: `raw.length < 32` is insufficient (F-04) |
| Centralization | ✓ flagged | Single owner, no timelock, single gateway |
| Dangerous `selfdestruct`/`delegatecall` | None ✓ | |
| Missing zero-address checks | Minor | `setProvider` allows `provider_ = job.client` |
| Front-running on `setBudget` | ✓ flagged | Both client/provider can write (F-09 from Pashov) |

---

### 2.9 Dependencies

| Dependency | Version | Assessment |
|------------|---------|------------|
| OpenZeppelin Contracts | v5.x | Well-audited, correct choice ✓ |
| OpenZeppelin Contracts Upgradeable | v5.x | Same ✓ |
| forge-std | Latest | Test-only, appropriate ✓ |

No third-party DeFi integrations. No oracles in-scope (DojoTrustScore is out-of-scope). Dependency surface is minimal — good.

---

### 2.10 Testing & Verification

**Status: Mixed — strong on some contracts, critical gaps on others**

#### Coverage by contract (in-scope)

| Contract | Lines | Statements | Branches | Functions | Grade |
|----------|-------|-----------|----------|-----------|-------|
| AgenticCommerceHooked | 54% | 46% | 22% | 67% | **D** |
| EvaluatorRegistry | 67% | 63% | 62% | 74% | **C** |
| TrustBasedEvaluator | 87% | 88% | 79% | 100% | **B+** |
| TrustGateACPHook | 64% | 62% | 61% | 93% | **C** |
| **CompositeRouterHook** | **10%** | **7%** | **0%** | **19%** | **F** |
| TrustUpdateHook | 60% | 56% | 29% | 80% | **D** |

**CompositeRouterHook at 10% line coverage is the highest-risk gap.** This contract chains plugins without try/catch in `beforeAction` — a bug here bricks all jobs using it as a hook.

#### Missing test scenarios (priority order)

1. Hook reverts in `_beforeHook` — job locked scenario (F-01)
2. CompositeRouterHook plugin reverts — all existing tests are passing
3. `closeAndSettle` with gateway signature edge cases (wrong chainid, expired)
4. `evaluate()` called on non-Submitted job
5. `setBudget` race: client and provider both call in same block
6. TrustGateACPHook staticcall failure → current behavior (fail-open)
7. `_successRateBP(0, 0)` → 10000 — new evaluators rank first

#### No fuzzing
Foundry's built-in fuzzer is not used. For a protocol handling USDC payments, property-based tests for the following invariants are critical:
- `job.budget` is always accounted for (sum of all Funded budgets == contract USDC balance)
- `job.status` monotonically progresses (no backwards transitions)
- `closeAndSettle` payment math: `fee + net == budget`

---

### 2.11 Platform-Specific

| Check | Result |
|-------|--------|
| Solidity version | `^0.8.20` — minor versions allowed; recommend pinning to `0.8.20` |
| `--via-ir` / `viaIR` | Missing from `foundry.toml` — coverage fails with "stack too deep" in `AgenticCommerceHooked` |
| Compiler warnings | None detected |
| No inline assembly | ✓ |
| `pragma abicoder v2` | Implicit in 0.8.x ✓ |

**Recommendation:** Add `via_ir = true` (or `viaIR: true`) to `foundry.toml` under `[profile.coverage]`. Or extract locals in `closeAndSettle` to fix the stack depth without `--via-ir`.

---

## Part 3 — Audit Prep Assessment

### Review Goals (proposed)

**Security objective:** Verify that escrowed USDC cannot be stolen, locked, or manipulated by any party — including malicious hooks, manipulated oracle readings, or replayed gateway signatures.

**Areas of highest concern (ranked):**
1. Hook lifecycle DoS (F-01, F-06) — Funded USDC can be locked permanently
2. `closeAndSettle` status bypass (F-02) — provider submit step can be skipped
3. Gateway signature replay (F-07) — no nonce/deadline
4. Trust gate fail-open (F-04) — security gate silently bypassed on oracle call failure
5. Permissionless `evaluate()` (F-05) — oracle-moment attack window

**Worst-case scenario:** Malicious hook deployed → client funds job → hook reverts on every interaction → USDC locked forever (no admin rescue path on non-upgradeable `AgenticCommerceHooked`).

---

### Static Analysis (Slither — not run)

Slither not available in this environment. Before external audit, run:

```bash
slither contracts/ --exclude-dependencies \
  --filter-paths "lib/" \
  --checklist
```

Expected findings to triage pre-audit:
- `reentrancy-benign` on `setBudget` (no external calls — true negative)
- `tautology` or `unused-state` in `_domainIndex` mapping sentinel
- `divide-before-multiply` check on `(budget * platformFeeBP) / 10000`

---

### Test Coverage Gaps (action items)

1. **CompositeRouterHook: write full test suite** — `beforeAction`, `afterAction`, plugin add/remove/enable/disable, priority ordering, MAX_PLUGINS enforcement
2. **AgenticCommerceHooked: hook failure tests** — hook that always reverts in `beforeAction`; verify stuck job scenario
3. **TrustUpdateHook: edge cases** — empty optParams, short optParams, provider = address(0) from getJob, dojoTrustScore reverts
4. **AgenticCommerceHooked: branch coverage** — `closeAndSettle` passed vs failed paths, fee = 0 case, platform fee at 100%

---

### Scope & Build

**In-scope files:** 6 contracts listed above
**Build:**
```bash
git clone <repo>
cd maiat8183
forge install
forge build
forge test # 225 tests, all pass
```

**Frozen commit:** Not yet created — freeze before external audit.

**Known issues (pre-audit):** See `assets/findings/maiat8183-pashov-ai-audit-report-20260414-000000.md` for 14 findings from self-audit (Pashov framework). F-01 through F-06 should be fixed before submitting to external auditors.

---

### Glossary

| Term | Definition |
|------|------------|
| ACP | Agentic Commerce Protocol — ERC-8183 escrow lifecycle |
| Job | On-chain escrow unit: Open→Funded→Submitted→Completed\|Rejected\|Expired |
| Hook | Optional callback contract per job; called before/after state transitions |
| closeAndSettle | Gateway-signed direct settlement; skips on-chain `submit()` step |
| trustedGateway | EOA whose ECDSA signature authorizes closeAndSettle |
| passRate | 0-100 score; >= 80 (PASS_THRESHOLD) → PASS settlement |
| BP / bps | Basis points. 10000 BP = 100%. Used for fee and success-rate math |
| UUPS | Universal Upgradeable Proxy Standard (OZ). Upgrade logic in implementation |
| EvaluatorRegistry | Ranked registry of evaluator contracts per domain |
| TrustOracle | External contract returning agent trust scores (0-100) |
| DojoTrustScore | Our specific TrustOracle implementation (out-of-scope for this audit) |
| Keeper | Off-chain process that calls `evaluate()` for TrustBasedEvaluator jobs |

---

## Priority Roadmap

### CRITICAL (fix before any external audit or mainnet deployment)

| # | Issue | File | Fix |
|---|-------|------|-----|
| C1 | Hook DoS — no emergency rescue path | `AgenticCommerceHooked.sol:105` | Add `emergencyDisableHook(uint256 jobId)` for ADMIN_ROLE |
| C2 | `closeAndSettle` requires Funded, skips submit | `AgenticCommerceHooked.sol:289` | Accept Funded OR Submitted |
| C3 | `evaluator == client` allowed | `AgenticCommerceHooked.sol:119` | Add `evaluator != msg.sender` guard |
| C4 | TrustGateACPHook fail-open on staticcall failure | `TrustGateACPHook.sol:176` | Revert instead of `return` |
| C5 | CompositeRouterHook: CompositeRouterHook coverage 10% | `CompositeRouterHook.sol` | Write full test suite |

### HIGH (fix before mainnet)

| # | Issue | File | Fix |
|---|-------|------|-----|
| H1 | No nonce/deadline on closeAndSettle signature | `AgenticCommerceHooked.sol:294` | Add nonce mapping + deadline param |
| H2 | `AgenticCommerceHooked` not upgradeable | — | Add `emergencyPause` + `drainTo` |
| H3 | `evaluate()` permissionless oracle-moment attack | `TrustBasedEvaluator.sol:176` | Add `permissionless` toggle + keeper allowlist |
| H4 | Gateway is single EOA SPOF | — | Plan multisig/rotation for mainnet |

### MEDIUM (fix for production quality)

| # | Issue | File | Fix |
|---|-------|------|-----|
| M1 | No foundry fuzzing for payment invariants | — | Add invariant tests |
| M2 | `_successRateBP(0,0) = 10000` ranking bias | `EvaluatorRegistry.sol:370` | Return 0 or 5000 for new evaluators |
| M3 | Coverage: AgenticCommerceHooked branches at 22% | — | Add branch tests |
| M4 | `via_ir` missing from foundry.toml | `foundry.toml` | Add `[profile.coverage] via_ir = true` |
| M5 | NatSpec gaps on 4 functions | `AgenticCommerceHooked.sol` | Add @param/@return tags |

### LOW

| # | Issue | Fix |
|---|-------|-----|
| L1 | No ARCHITECTURE.md | Write 1-page architecture doc |
| L2 | No keeper documentation | Add off-chain keeper setup guide |
| L3 | Compiler not pinned | Change `^0.8.20` to `0.8.20` |

---

## Audit Prep Checklist

- [x] Review goals documented
- [ ] Static analysis (Slither) run and triaged
- [ ] Test coverage >80% on all in-scope contracts
- [ ] C1–C5 critical findings fixed
- [ ] `forge test` clean after fixes
- [ ] Build instructions verified on fresh environment
- [ ] Stable version frozen (commit hash + branch)
- [ ] ARCHITECTURE.md written
- [ ] User stories documented (client, provider, evaluator, keeper)
- [ ] Actors/privileges map written
- [ ] Glossary complete (partial — see above)

**Current readiness: 1/10 checklist items complete. Estimated effort to reach audit-ready: 2–3 days.**

---

_Assessment generated by Trail of Bits building-secure-contracts AI skill suite. Not a substitute for professional security audit._
