# Multi-Hook Router

## The Problem

Today, each ERC-8183 job can only attach **one hook**. If a job needs escrow handling, privacy verification, and reputation tracking, all that logic must be crammed into a single contract.

This creates **monolithic hooks** — hard to build, hard to audit, and impossible to reuse across different job types.

## The Solution

A **Multi-Hook Router** sits between the core contract and individual hooks, forwarding callbacks to an ordered list of small, focused hooks.

```
                            CURRENT                              PROPOSED
                     ┌────────────────┐                   ┌────────────────┐
                     │   ERC-8183     │                   │   ERC-8183     │
                     └───────┬────────┘                   └───────┬────────┘
                             │                                    │
                             ▼                                    ▼
                   ┌──────────────────┐               ┌───────────────────┐
                   │  Single Hook     │               │  MultiHookRouter  │
                   │  (does everything│               └──┬──────┬──────┬──┘
                   │   or nothing)    │                  │      │      │
                   └──────────────────┘                  ▼      ▼      ▼
                                                      Hook1  Hook2  Hook3
                                                    (escrow)(privacy)(reputation)
```

## How It Works

1. Job creator sets the **MultiHookRouter** as the job's hook
2. Client configures which sub-hooks to use and in what order
3. On every state transition (fund, submit, complete, etc.):
   - Router calls each sub-hook's `beforeAction` in order — any can block the transition
   - Core executes the state change
   - Router calls each sub-hook's `afterAction` in order — for bookkeeping

## Hook Flow

### Without MultiHookRouter (Single Hook)

```
Client                    ERC-8183              Single Hook
  |                          |                      |
  |-- fund() -------------->|                      |
  |                          |-- beforeAction() -->|
  |                          |<--------------------|
  |                          |                      |
  |                          |  [state change]      |
  |                          |                      |
  |                          |-- afterAction() --->|
  |                          |<--------------------|
  |<-------------------------|                      |
```

One hook = 2 external calls per transition. Always.

### With MultiHookRouter — 5 Hooks

```
Client          ERC-8183          Router           H1    H2    H3    H4    H5
  |                |                 |
  |-- fund() ---->|                 |
  |                |-- beforeAction()-->|
  |                |                 |-- before() -->|
  |                |                 |<--------------|
  |                |                 |-- before() -------->|
  |                |                 |<--------------------|
  |                |                 |-- before() -------------->|
  |                |                 |<--------------------------|
  |                |                 |-- before() ---------------------->|
  |                |                 |<---------------------------------|
  |                |                 |-- before() ------------------------------>|
  |                |                 |<-----------------------------------------|
  |                |<----------------|
  |                |                 |
  |                |  [state change] |
  |                |                 |
  |                |-- afterAction()-->|
  |                |                 |-- after() --->|
  |                |                 |<--------------|
  |                |                 |-- after() ---------->|
  |                |                 |<--------------------|
  |                |                 |-- after() --------------->|
  |                |                 |<--------------------------|
  |                |                 |-- after() ----------------------->|
  |                |                 |<---------------------------------|
  |                |                 |-- after() -------------------------------->|
  |                |                 |<------------------------------------------|
  |                |<----------------|
  |<---------------|

External calls: 2 (core -> router) + 10 (router -> hooks) = 12 total
```

### Gas Overhead

| Hooks | External Calls Per Transition | Estimated Router Overhead |
|-------|-------------------------------|---------------------------|
| 0 (no router) | 2 (core -> hook) | -- |
| 1 (via router) | 4 (core -> router -> hook x2) | ~3,000 gas |
| 5 | 12 | ~15,000 gas |
| 10 | 22 | ~30,000 gas |
| 20 | 42 | ~60,000 gas |

The formula is `2 + (N x 2)` external calls per transition. Each call from the router to a sub-hook is sequential — if any `beforeAction` reverts, the remaining hooks are never called and the entire transition is blocked.

## Comparison

|  | Current (Single Hook) | Multi-Hook Router |
|---|---|---|
| **Hooks per job** | 1 | Configurable (admin-set cap) |
| **Composability** | Must build one contract that does everything | Mix and match small, focused hooks |
| **Reusability** | Low — each hook is custom-built per use case | High — same privacy hook works across job types |
| **Audit surface** | One large contract | Multiple small contracts (easier to review individually) |
| **Core changes needed** | — | None |
| **Gas overhead** | Baseline | ~3,000 gas per additional hook |
| **Flexibility** | Add a new concern = rewrite the hook | Add a new concern = plug in another hook |

## Example: Job With Three Concerns

**Current approach** — build a single `EscrowPrivacyReputationHook`:
- 1 contract, ~500+ lines
- Tightly coupled — changing escrow logic risks breaking privacy logic
- Cannot reuse the privacy piece for a different job type

**With Multi-Hook Router** — configure 3 independent hooks:
- `FundTransferHook` — handles token escrow (already built)
- `PrivacyHook` — verifies ZK proofs for confidential deliverables
- `ReputationHook` — tracks provider completion rates

Each is independently developed, tested, and audited. A job that only needs escrow + reputation simply drops the privacy hook from the list.

## Industry Precedent

This is not a novel pattern. Major protocols use the same approach in production:

| Protocol | How They Do It |
|---|---|
| **Uniswap v4** | Hook middleware contracts chain multiple hooks per pool |
| **ERC-6900** | Modular smart accounts with composable validation, execution, and hook modules |
| **Safe (Gnosis)** | Multiple modules + guards enabled simultaneously on a single wallet |

## What Changes for Users

**Nothing.** Users interact with ERC-8183 the same way they do today. The router is transparent — it looks like a single hook to the core.

The only difference is during job setup: instead of deploying a custom hook, the client configures which existing hooks to attach.

## Risk and Tradeoffs

| Consideration | Detail |
|---|---|
| **Gas cost** | Each additional hook adds ~3,000 gas per transition. 5 hooks = ~15,000 extra gas. Manageable on L2s, noticeable on L1. |
| **Ordering matters** | Hook execution order affects behavior. Access control hooks should run before payment hooks. |
| **Hook list is locked after funding** | Once money is escrowed, the hook list cannot change. This prevents manipulation mid-job. |
| **Sub-hook compatibility** | Existing hooks need minor adaptation to work inside the router (trust chain adjustment). New hooks built for the router work out of the box. |

## Impact

- No changes to the core `AgenticCommerce` contract
- The router is a new standalone contract (~250 lines)
- Existing `FundTransferHook` continues to work as-is for single-hook jobs
- Multi-hook support is additive — it does not break or replace anything
