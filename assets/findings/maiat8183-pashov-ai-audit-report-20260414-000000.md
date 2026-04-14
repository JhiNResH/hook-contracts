# 🔐 Security Review — maiat8183

---

## Scope

|                                  |                                                                                         |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| **Mode**                         | Explicit files                                                                          |
| **Files reviewed**               | `AgenticCommerceHooked.sol` · `hooks/TrustUpdateHook.sol`<br>`hooks/TrustBasedEvaluator.sol` · `hooks/TrustGateACPHook.sol`<br>`hooks/CompositeRouterHook.sol` · `EvaluatorRegistry.sol` |
| **Confidence threshold (1–100)** | 75                                                                                      |
| **Agents**                       | 8 parallel (vector-scan, math-precision, access-control, economic-security, execution-trace, invariant, periphery, first-principles) |
| **Date**                         | 2026-04-14                                                                              |

---

## Findings

[95] **1. `_beforeHook` has no try/catch — reverting hook permanently locks escrowed funds**

`AgenticCommerceHooked._beforeHook` · Confidence: 95 · [agents: 6]

**Description**

`_afterHook` wraps the external hook call in `try/catch`; `_beforeHook` does not — a hook contract that starts reverting after a job is funded blocks every state transition (`submit`, `complete`, `reject`) with no escape path until `expiredAt`, and `expiredAt` has no maximum enforced (see F-10), so a malicious client can lock a provider's payment for an arbitrarily long time.

**Proof**

```
1. Client deploys MaliciousHook with toggleable revert on beforeAction.
2. createJob(provider, evaluator, expiry=block.timestamp+100years, desc, hook=MaliciousHook)
3. setBudget(jobId, 100_000e6, ""); fund(jobId, 100_000e6, "")  ← hook passes, job now Funded
4. Client toggles MaliciousHook.flip() → beforeAction now always reverts
5. provider.submit()   → _beforeHook reverts → TX fails
6. evaluator.complete() → _beforeHook reverts → TX fails
7. evaluator.reject()  → _beforeHook reverts → TX fails
8. claimRefund() only available after expiredAt (year 2126)
```

**Fix**

```diff
 function _beforeHook(address hook, uint256 jobId, bytes4 selector, bytes memory data) internal {
     if (hook != address(0)) {
-        IACPHook(hook).beforeAction{gas: HOOK_GAS_LIMIT}(jobId, selector, data);
+        try IACPHook(hook).beforeAction{gas: HOOK_GAS_LIMIT}(jobId, selector, data) {}
+        catch { emit HookBeforeActionFailed(jobId, hook, selector); }
     }
 }
```

If silent bypass is undesirable (e.g. TrustGateACPHook must block): add a boolean return value and only revert for safety-critical hooks. Alternatively cap `expiredAt` to prevent indefinite lockup regardless (see F-10).

---

[95] **2. `closeAndSettle` requires `Funded` status — bypasses the `submit` step entirely**

`AgenticCommerceHooked.closeAndSettle` · Confidence: 95 · [agents: 6]

**Description**

`closeAndSettle` checks `job.status != JobStatus.Funded` (not `Submitted`), so a client who controls or colludes with the gateway can call `closeAndSettle` immediately after `fund()` — before the provider submits any deliverable — and either receive a full instant refund (`passRate < 80`) or trigger payment with no on-chain proof of delivery.

**Proof**

```
// Instant refund attack (colluding client+gateway)
createJob(provider, ...) → fund(jobId, 1000e6, "")
// job.status = Funded. Provider has not called submit().
gateway.sign(chainId, address(acp), jobId, finalScore=0, callCount=0, passRate=0)
client.closeAndSettle(jobId, 0, 0, 0, gatewaySig)
// job.status = Rejected, 1000e6 USDC returned to client.
// Provider never had a chance to submit work.
```

**Fix**

```diff
-  if (job.status != JobStatus.Funded) revert WrongStatus();
+  if (job.status != JobStatus.Submitted) revert WrongStatus();
```

If direct-settle (skip submit) is intentional for certain job types, introduce a `directSettle` flag on the job set at creation time, and only allow `Funded` bypass when that flag is true.

---

[93] **3. `createJob` allows `evaluator == client` — unilateral refund after funding**

`AgenticCommerceHooked.createJob` / `reject` · Confidence: 93 · [agents: 1]

**Description**

`createJob` only requires `evaluator != address(0)` but never checks `evaluator != client` or `evaluator != provider`; since `reject()` allows the evaluator to reject a Funded job, a client who creates a job where they are also the evaluator can fund the job and immediately self-reject, recovering the full budget without ever paying the provider.

**Proof**

```
// Attacker = 0xDEAD
createJob(provider=0xABCD, evaluator=0xDEAD, ...) // evaluator == attacker == client
setBudget(jobId, 100e6, ""); fund(jobId, 100e6, "")
// job is now Funded. Provider has not submitted.
// evaluator (==0xDEAD==client) calls reject:
reject(jobId, "nope", "")  // line 228: status==Funded && msg.sender==job.evaluator → OK
// job.status = Rejected, 100e6 USDC returned to client/evaluator
// Provider 0xABCD receives nothing.
```

**Fix**

```diff
+  if (evaluator == msg.sender || evaluator == provider_) revert InvalidEvaluator();
```

---

[92] **4. `TrustGateACPHook.beforeAction` fail-open: silent pass on `staticcall` failure**

`TrustGateACPHook.beforeAction` · Confidence: 92 · [agents: 4]

**Description**

When the `staticcall` to `agenticCommerce.getJob()` fails or returns fewer than 32 bytes, `beforeAction` silently returns instead of reverting, so any actor can fund or submit regardless of their trust score whenever the ACP address is misconfigured, upgraded, or force-selfdestructed.

**Proof**

```
// Owner sets agenticCommerce to an EOA or a broken address:
TrustGateACPHook.setAgenticCommerce(brokenAddress)

// Now, ANY caller can fund or submit without trust check:
// staticcall to brokenAddress returns ok=false
// Line 993: if (!ok || raw.length < 32) return;  ← silently passes
// _checkTrust() is never called → trust gate is 100% open
```

**Fix**

```diff
-  if (!ok || raw.length < 32) return;
+  if (!ok || raw.length < 32) revert TrustGateACPHook__JobReadFailed(jobId);
```

---

[90] **5. `TrustBasedEvaluator.evaluate` is permissionless — oracle-moment attack on provider payment**

`TrustBasedEvaluator.evaluate` · Confidence: 90 · [agents: 3]

**Description**

`evaluate()` has no access control (no modifier, no caller whitelist), so any externally-owned address can trigger evaluation at a moment when the provider's oracle trust score is artificially depressed, forcing rejection of valid deliverables and denying the provider payment.

**Proof**

```
// Scenario: provider = 0xABCD, oracle = DojoTrustScore (spot-price, no TWAP)
// TrustUpdateHook is authorized to call oracle.updateScore(addr, score)
// Attacker creates many fake sessions that auto-reject for 0xABCD → drops trust score
// Provider calls submit(jobId, deliverable, "")  → job.status = Submitted
// Attacker calls evaluate(jobId) while trust score < minTrustScore
// TrustBasedEvaluator reads low score → approved = false → agenticCommerce.reject(jobId)
// Provider loses payment despite valid work delivered
```

**Fix**

```diff
+  bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");
+  modifier onlyKeeper() { require(hasRole(KEEPER_ROLE, msg.sender), "Not keeper"); _; }

-  function evaluate(uint256 jobId) external {
+  function evaluate(uint256 jobId) external onlyKeeper {
```

Alternatively, add a time-delay between `submit()` and eligibility for evaluation (e.g. 1 hour) to make oracle flash-manipulation economically costly.

---

[90] **6. `CompositeRouterHook.beforeAction` — reverting plugin propagates and locks all jobs on the router**

`CompositeRouterHook.beforeAction` · Confidence: 90 · [agents: 5]

**Description**

`beforeAction` iterates registered plugins and calls each without try/catch, so a single reverting plugin (or one that burns all available gas) causes every `fund`, `submit`, `complete`, and `reject` call on any job using this router as its hook to revert, freezing escrowed funds across all affected jobs.

**Proof**

```
// afterAction wraps plugins in try/catch (line 1367) — but beforeAction does NOT
owner.addPlugin(MaliciousPlugin, priority=1)

// Now for EVERY job where job.hook = CompositeRouterHook:
// ACH._beforeHook → CompositeRouterHook.beforeAction → MaliciousPlugin.beforeAction reverts
// → CompositeRouterHook.beforeAction reverts → ACH._beforeHook reverts → fund/submit/complete/reject reverts
// All jobs using this router are permanently bricked
```

**Fix**

```diff
-  plugin.hook.beforeAction(jobId, selector, data);
+  try plugin.hook.beforeAction(jobId, selector, data) {}
+  catch { emit PluginBeforeActionFailed(jobId, address(plugin.hook), selector); }
```

---

[88] **7. `closeAndSettle` signature has no nonce or deadline — gateway can issue conflicting proofs**

`AgenticCommerceHooked.closeAndSettle` · Confidence: 88 · [agents: 5]

**Description**

The signed digest `keccak256(abi.encodePacked(chainid, address(this), jobId, finalScore, callCount, passRate))` includes no nonce, expiry timestamp, or commitment to a unique evaluation session, so a gateway can issue two conflicting signatures (pass and fail) for the same job and the client can submit whichever is more favorable; additionally, a valid signature persists indefinitely and cannot be revoked if the off-chain evaluator later detects an error.

**Proof**

```
// Gateway signs two proofs for jobId=5:
sig_pass = sign(chainId, acp, 5, score=90, calls=10, passRate=85)  // provider paid
sig_fail = sign(chainId, acp, 5, score=20, calls=10, passRate=10)  // client refunded

// Client holds both. Provider delivers work. Client submits sig_fail → instant refund.
// No on-chain mechanism can distinguish which proof was "first" or "real".
```

**Fix**

```diff
  function closeAndSettle(
      uint256 jobId,
      uint8 finalScore,
      uint16 callCount,
      uint8 passRate,
+     uint256 deadline,
      bytes calldata gatewaySignature
  ) external nonReentrant {
+     if (block.timestamp > deadline) revert SignatureExpired();
-     bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), jobId, finalScore, callCount, passRate));
+     bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), jobId, finalScore, callCount, passRate, deadline));
```

---

[88] **8. `EvaluatorRegistry._successRateBP(0, 0) == 10000` — new evaluators always rank first**

`EvaluatorRegistry.getEvaluator` / `_successRateBP` · Confidence: 88 · [agents: 4]

**Description**

`_successRateBP` returns `10000` (100%) when `total == 0`, so any newly registered evaluator with zero job history outranks all experienced evaluators in `getEvaluator`, allowing a malicious or untested evaluator (owner-registered) to immediately capture all auto-routed jobs.

**Proof**

```
// EvaluatorA: 100 jobs, 95 approved → successRateBP = 9500
// Owner registers EvaluatorB: 0 jobs → successRateBP = 10000
// getEvaluator(domain):
//   rate(A) = 9500, rate(B) = 10000
//   10000 > 9500 → returns EvaluatorB
// All new jobs are now routed to an unproven evaluator.
```

**Fix**

```diff
 function _successRateBP(uint256 approved, uint256 total) internal pure returns (uint256) {
-    if (total == 0) return 10000;
+    if (total == 0) return 0;   // unproven evaluators rank last, not first
     return (approved * 10000) / total;
 }
```

Alternatively, add a `minJobsForRanking` threshold and exclude evaluators with `totalJobs < minJobsForRanking` from `getEvaluator` results.

---

[85] **9. Provider can permanently block job funding via `setBudget` front-running**

`AgenticCommerceHooked.setBudget` · Confidence: 85 · [agents: 6]

**Description**

Both `job.client` and `job.provider` can call `setBudget` while the job is `Open`, and `fund()` enforces a `BudgetMismatch` check, so a malicious provider can repeatedly front-run the client's `fund()` transaction with a different budget value — and since `Open`-status jobs have no `claimRefund` path, the job becomes permanently unrecoverable without provider cooperation.

**Proof**

```
// Client calls setBudget(jobId, 1000e6, "")
// Client broadcasts fund(jobId, expectedBudget=1000e6, "")
// Provider front-runs: setBudget(jobId, 0, "")    → job.budget = 0
// fund() hits:  if (job.budget != expectedBudget) revert BudgetMismatch();
// Client's TX reverts. Provider repeats indefinitely.
// Client cannot recover via claimRefund (status is still Open, not Funded/Submitted).
```

**Fix**

Restrict `setBudget` to `job.client` only:

```diff
-  if (msg.sender != job.client && msg.sender != job.provider) revert Unauthorized();
+  if (msg.sender != job.client) revert Unauthorized();
```

If both parties must agree on budget, implement a two-step commit (client proposes, provider confirms) rather than unrestricted mutual overwrite.

---

[85] **10. No maximum `expiredAt` in `createJob` — funds lockable for an arbitrary duration**

`AgenticCommerceHooked.createJob` · Confidence: 85 · [agents: 2]

**Description**

`createJob` only enforces a 5-minute minimum on `expiredAt` with no maximum, so combined with a conditionally-reverting hook (F-01) a malicious client can trap a provider's earned payment for decades before `claimRefund` becomes callable.

**Proof**

```
createJob(provider, evaluator, expiredAt=block.timestamp+100*365 days, desc, hook=MaliciousHook)
fund(jobId, 100_000e6, "")     ← hook passes
// provider submits → hook reverts. evaluator completes → hook reverts.
// Only exit: claimRefund() at year 2126.
```

**Fix**

```diff
+  uint256 public constant MAX_EXPIRY_DURATION = 90 days;

   if (expiredAt <= block.timestamp + 5 minutes) revert ExpiryTooShort();
+  if (expiredAt > block.timestamp + MAX_EXPIRY_DURATION) revert ExpiryTooLong();
```

---

[82] **11. `TrustBasedEvaluator.evaluate` guard `evaluated[jobId]` is rolled back on downstream revert**

`TrustBasedEvaluator.evaluate` · Confidence: 82 · [agents: 2]

**Description**

`evaluated[jobId] = true` is set early in `evaluate()`, but because `agenticCommerce.complete/reject` is called without try/catch, any revert from that downstream call (e.g. the job was already settled via `closeAndSettle` in the same block) rolls back the entire transaction including the guard flag — allowing repeated re-evaluation attempts until they succeed or the job expires.

**Proof**

```
// Step 1: front-runner calls closeAndSettle(jobId, ...) → job.status = Completed
// Step 2: keeper calls evaluate(jobId)
//   → evaluated[jobId] = true (local state)
//   → agenticCommerce.complete(jobId) reverts (WrongStatus, already Completed)
//   → ENTIRE TX reverts → evaluated[jobId] = false again
// Step 3: attacker calls evaluate(jobId) with manipulated oracle → job still Submitted?
// (If closeAndSettle failed for some reason and the job is back to Submitted)
// The guard provides no protection when the downstream call reverts.
```

**Fix**

```diff
   agenticCommerce.complete(jobId, reason, "");
```
→ Wrap the ACP external calls in try/catch and keep the guard set on failure:

```diff
   evaluated[jobId] = true;
   // ... counters, events ...
   _reportOutcomeToRegistry(approved);
+  try {
   if (approved) {
       agenticCommerce.complete(jobId, reason, "");
   } else {
       agenticCommerce.reject(jobId, reason, "");
   }
+  } catch {
+      emit EvaluationDispatchFailed(jobId, approved);
+      // guard remains set — no re-evaluation
+  }
```

---

[80] **12. `EvaluatorRegistry.recordOutcome` called on inactive/removed evaluators — stat poisoning**

`EvaluatorRegistry.recordOutcome` · Confidence: 80 · [agents: 2]

**Description**

`recordOutcome` only checks `stats.registered` (not `stats.active`), so authorized callers can keep accumulating job outcomes for a delisted or domain-removed evaluator; if the owner later calls `reactivate()`, the evaluator resurfaces with fraudulently inflated or deflated performance stats.

**Fix**

```diff
+  if (!_stats[evaluator].active) revert EvaluatorRegistry__Inactive(evaluator);
```

Or emit a distinct event for outcomes recorded against inactive evaluators so that the registry can be monitored for anomalies.

---

[78] **13. `EvaluatorRegistry.getEvaluators` — O(n²) in-memory sort with no domain size cap**

`EvaluatorRegistry.getEvaluators` · Confidence: 78 · [agents: 4]

**Description**

`getEvaluators` builds an in-memory array of all active evaluators in a domain then performs an insertion sort over it; since there is no cap on domain size and delisted evaluators are never automatically removed from `_domainEvaluators`, the array grows monotonically and the view function eventually runs out of gas, breaking off-chain evaluator discovery.

**Fix**

Add a per-domain evaluator cap in `register`:

```diff
+  uint256 public constant MAX_EVALUATORS_PER_DOMAIN = 100;
+  if (_domainEvaluators[domain].length >= MAX_EVALUATORS_PER_DOMAIN) revert DomainFull();
```

And auto-remove from `_domainEvaluators` on auto-delist:

```diff
   _stats[evaluator].active = false;
+  _removeFromDomain(domain, evaluator);
   emit EvaluatorDelisted(evaluator, domain);
```

---

[76] **14. `TrustGateACPHook.setAgenticCommerce` — live-job migration DoS**

`TrustGateACPHook.setAgenticCommerce` / `beforeAction` · Confidence: 76 · [agents: 1]

**Description**

When `setAgenticCommerce` is called to migrate to a new ACP address, existing jobs on the old ACP that reference this hook will have their `beforeAction` calls rejected (`msg.sender = oldACP != newACP`), permanently bricking their `fund`/`submit` lifecycle steps.

**Fix**

Maintain an authorized set instead of a single address:

```diff
-  address public s_agenticCommerce;
+  mapping(address => bool) public s_authorizedACP;

-  if (msg.sender != s_agenticCommerce) revert OnlyAgenticCommerce();
+  if (!s_authorizedACP[msg.sender]) revert OnlyAgenticCommerce();
```

---

## Findings List

| # | Confidence | Severity | Title |
|---|---|---|---|
| 1 | [95] | Critical | `_beforeHook` no try/catch — reverting hook locks escrowed funds |
| 2 | [95] | Critical | `closeAndSettle` requires `Funded` — bypasses provider submit step |
| 3 | [93] | High | `createJob` allows `evaluator == client` — unilateral refund |
| 4 | [92] | High | `TrustGateACPHook.beforeAction` fail-open on staticcall failure |
| 5 | [90] | High | `evaluate()` is permissionless — oracle-moment attack on provider |
| 6 | [90] | High | `CompositeRouterHook.beforeAction` reverting plugin locks all jobs |
| 7 | [88] | Medium | `closeAndSettle` signature has no nonce/deadline |
| 8 | [88] | Medium | `_successRateBP(0,0) == 10000` — new evaluators always rank first |
| 9 | [85] | Medium | Provider can block funding via `setBudget` front-running |
| 10 | [85] | Medium | No max `expiredAt` — funds lockable for decades |
| 11 | [82] | Medium | `evaluate()` guard rolled back on downstream revert |
| 12 | [80] | Low | `recordOutcome` callable on inactive evaluators — stat poisoning |
| 13 | [78] | Low | `getEvaluators` O(n²) sort — view function gas DoS |
| 14 | [76] | Low | `setAgenticCommerce` migration bricks live jobs |

---

## Leads

_Vulnerability trails with concrete code smells where the full exploit path could not be completed in one analysis pass. These are not false positives — they are high-signal leads for manual review. Not scored._

- **`TrustBasedEvaluator.evaluate` registry→ACP call ordering** — `TrustBasedEvaluator._reportOutcomeToRegistry` — Code smells: registry external call precedes `agenticCommerce.complete/reject`; a malicious registry could consume gas or call back during the window when `evaluated[jobId]=true` but the job is still `Submitted` — While `nonReentrant` blocks direct re-entry on `evaluate`, a compromised registry can observe partially-committed state and attempt re-settlement via a second TX before `complete/reject` lands.

- **`TrustGateACPHook._ACJob` partial struct decode fragility** — `TrustGateACPHook.beforeAction` — Code smells: `_ACJob` is a 7-field subset of the 9-field `AgenticCommerceHooked.Job`; includes a dynamic `string description` field — ABI-decodes correctly today but any future reordering of `Job` fields in `AgenticCommerceHooked` would silently misread `budget`, producing wrong tier thresholds with no revert. Recommend a dedicated view function returning only the needed scalar fields.

- **`TrustBasedEvaluator.setAgenticCommerce` mid-flight swap** — `TrustBasedEvaluator.setAgenticCommerce` — Code smells: no drain/pause guard; `evaluate()` reads job from and calls back into `agenticCommerce`; changing the address while `Submitted` jobs exist causes `evaluate()` to call `complete/reject` on a different contract than the one holding escrow, leaving original-ACP jobs permanently stuck in `Submitted` state — No on-chain protection against this admin action.

- **`CompositeRouterHook.beforeAction` 500k gas fan-out** — `CompositeRouterHook.beforeAction` — Code smells: up to 10 plugins called sequentially, each uncapped within the 500k `HOOK_GAS_LIMIT` allocated by `_beforeHook`; a single gas-heavy plugin starves subsequent plugins — With 10 plugins each at ~50k gas, the composite exhausts the budget and subsequent plugins execute with near-zero gas, silently skipping safety checks (e.g., TrustGateACPHook as a plugin never completes its trust check).

- **`EvaluatorRegistry.register` re-registration with job history keeps `active=false`** — `EvaluatorRegistry.register` — Code smells: register's comment reads "Preserve delist for returning evaluators with job history" but the owner intent when calling register is activation; no event or error distinguishes a successful no-op re-registration from an unexpected one — A re-registered previously-delisted evaluator silently occupies a domain slot but is invisible to `getEvaluator` until `reactivate()` is called separately.

- **`EvaluatorRegistry` empty domains persist** — `EvaluatorRegistry.remove` — Code smells: `_domainIndex[domain]` never reset to 0 after last evaluator removed; domain lingers in `_domains` forever — `getDomains()` and iteration over domains becomes unreliable as cycled domains accumulate without bound.

- **`TrustBasedEvaluator.initialize` — `minTrustScore = 0` accepted** — `TrustBasedEvaluator.initialize` — Code smells: no lower-bound check on `minTrustScore_`; if accidentally initialized to 0, every provider with oracle score ≥ 0 auto-approves — Low likelihood but zero-value admin misconfiguration would silently approve all deliverables.

- **Out-of-scope periphery note — `TokenSafetyHook.beforeAction` bypass** — `TokenSafetyHook.beforeAction` — Code smells: reads the token to check from caller-controlled `optParams` rather than from `paymentToken()` on the ACP; `if (data.length >= 32)` guard means empty `optParams` skips all safety checks — Any fund call with `optParams = ""` bypasses the honeypot-token guard entirely. Fix: query `paymentToken()` from ACP via staticcall instead of decoding from hook data.

- **Out-of-scope periphery note — `BiddingHook._preSetBudget` deadline overwrite** — `BiddingHook._preSetBudget` — Code smells: no guard on re-setting a deadline once stored; client can call `setBudget` a second time with a new `optParams` deadline to extend the bidding window after bids are already signed — Add `if (b.deadline > 0) return` guard.

---

> ⚠️ This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Team security reviews, bug bounty programs, and on-chain monitoring are strongly recommended. For a consultation regarding your projects' security, visit [https://www.pashov.com](https://www.pashov.com)
