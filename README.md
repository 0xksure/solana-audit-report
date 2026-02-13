# Solana DeFi Security Audit Report

**Auditor:** Max (AI Co-Founder @ 0xksure)
**Date:** February 12–13, 2026
**Bounty:** [Superteam Audit & Fix Solana Repos ($3K)](https://earn.superteam.fun/listing/audit-fix-solana-repos/)

---

## Executive Summary

Independent security audit of **5 high-TVL Solana DeFi protocols** totaling **~$4.7B+ in combined TVL**. Deep manual review focusing on arithmetic safety, access control, oracle handling, state machine correctness, and common Solana vulnerability patterns.

**74 findings** identified across all targets — 2 HIGH, 17 MEDIUM, 28 LOW, and 27 INFO. Two HIGH severity issues found in Futarchy/MetaDAO (admin bypass and accounting loss).

### Severity Distribution

| Severity | Raydium | Kamino | Jito | Futarchy | Sanctum | Total |
|----------|---------|--------|------|----------|---------|-------|
| CRITICAL | 0 | 0 | 0 | 0 | 0 | **0** |
| HIGH | 0 | 0 | 0 | 2 | 0 | **2** |
| MEDIUM | 4 | 3 | 3 | 5 | 3 | **17** |
| LOW | 5 | 7 | 6 | 7 | 4 | **28** |
| INFO | 6 | 8 | 3 | 6 | 4 | **27** |
| **Total** | **15** | **18** | **12** | **20** | **11** | **74** |

### Protocols Audited

| Protocol | Category | TVL | Security Rating |
|----------|----------|-----|-----------------|
| [Kamino Lend](https://github.com/Kamino-Finance/klend) | Lending | $1.63B | STRONG |
| [Jito Stakenet](https://github.com/jito-foundation/stakenet) | Liquid Staking | $1.07B | MODERATE |
| [Raydium CLMM](https://github.com/raydium-io/raydium-clmm) | AMM | $965M | STRONG |
| [Futarchy / MetaDAO](https://github.com/metaDAOproject/futarchy) | Prediction Markets | $12M | WEAK — 2 HIGH |
| [Sanctum S Controller](https://github.com/igneous-labs/S) | LST AMM | $1.1B | STRONG |

---

## Methodology

1. **Architecture review** — program flow, PDA derivations, CPI patterns
2. **Automated scanning** — `grep`/`ripgrep` for unsafe casts (`as u64/u128`), `unwrap()`, `unsafe`, missing signer/owner checks
3. **Manual review** — arithmetic safety, access control, oracle handling, token validation, reentrancy, state machine correctness
4. **Checklist-based** — Zealynx 45-point Solana security checklist, Helius security guide, Neodyme/Sec3 vulnerability taxonomies
5. **Staking-specific threat modeling** (Jito) — covering oracle trust, delegation gaming, state machine manipulation

---

## Raydium CLMM — Concentrated Liquidity AMM ($965M TVL)

**Repo:** [raydium-io/raydium-clmm](https://github.com/raydium-io/raydium-clmm)
**Program ID:** `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK`
**Previous Audits:** OtterSec

Uniswap V3-style concentrated liquidity AMM built with Anchor. Overflow-checks enabled, extensive use of checked arithmetic and Anchor account validation. Admin gated by hardcoded pubkey.

### Summary Table

| ID | Severity | Title |
|----|----------|-------|
| F-01 | MEDIUM | Fee growth checked_sub can panic, locking user funds |
| F-02 | MEDIUM | Reward growth checked_sub can panic similarly |
| F-03 | MEDIUM | to_underflow_u64 silently zeros large fee/reward claims |
| F-04 | MEDIUM | Pool freeze via vault drain race condition |
| F-05 | LOW | assert! instead of require! gives poor errors |
| F-06 | LOW | Missing vault constraints in swap account struct |
| F-07 | LOW | Unconstrained pool_state in decrease_liquidity |
| F-08 | LOW | Operation owners bypass reward param restrictions |
| F-09 | LOW | Timestamp truncation in oracle (year 2106) |
| F-10 | INFO | Permissionless pool creation |
| F-11 | INFO | Limited oracle manipulation resistance |
| F-12 | INFO | Fee growth accumulator overflow (theoretical) |
| F-13 | INFO | reward_total_emissioned overflow risk |
| F-14 | INFO | 30+ unwrap() calls in math libraries |
| F-15 | INFO | 40+ unsafe as casts on tick_spacing |

### MEDIUM Findings

#### [RY-F01] Fee Growth checked_sub Can Panic When Tick State Is Inconsistent

- **Files:** `programs/amm/src/states/tick_array.rs:408-411, 425-428, 461, 470`
- **Description:** `get_fee_growth_inside` uses `checked_sub().unwrap()` for intermediate fee growth calculations. In Uniswap V3, wrapping subtraction is used throughout because fee growth values are designed to wrap around. If `fee_growth_outside` exceeds `fee_growth_global` after wrapping, the program panics, **bricking any position spanning those ticks**.
- **Exploit Scenario:** Pool with extremely low liquidity → high fee_growth_global accumulation → tick crossing sets fee_growth_outside to value that later exceeds global after wrapping → all position modifications panic → funds locked.
- **Impact:** Fund locking. Admin can freeze/unfreeze but affected positions remain inaccessible.
- **Fix:** Replace `checked_sub().unwrap()` with `wrapping_sub()` in intermediate calculations.

#### [RY-F02] Reward Growth checked_sub Can Also Panic

- **Files:** `programs/amm/src/states/tick_array.rs:461, 470`
- **Description:** Same issue as F-01 for reward growth calculations. `checked_sub().unwrap()` on `reward_growth_global_x64 - reward_growths_outside_x64[i]` panics on wrapping.
- **Fix:** Use `wrapping_sub()` consistently.

#### [RY-F03] to_underflow_u64 Silently Returns 0 for Large Values

- **Files:** `programs/amm/src/libraries/full_math.rs:177, 209`
- **Used in:** `personal_position.rs:180`, `increase_liquidity.rs:212`
- **Description:** `to_underflow_u64()` returns `0` when value exceeds `u64::MAX`:
  ```rust
  fn to_underflow_u64(self) -> u64 {
      if self < U128::from(u64::MAX) { self.as_u64() } else { 0 }
  }
  ```
  Used in fee and reward calculations. If accumulated fees overflow u64, the **entire amount is silently set to 0**.
- **Exploit Scenario:** Whale provides massive liquidity in narrow tick range → high trading volume → fee_growth_delta × liquidity / Q64 exceeds u64::MAX → whale gets **no fees at all**.
- **Fix:** Return `u64::MAX` instead of 0 (saturating behavior).

#### [RY-F04] Pool State Can Be Frozen via Vault Drain Race

- **Files:** `programs/amm/src/instructions/swap.rs:516-518, 531-533`
- **Description:** Pool freezes (status=255) when output vault insufficient, using stale balance. Admin can unfreeze but griefing possible with Token-2022 transfer fees.

### LOW Findings

- **F-05:** `assert!()` instead of `require!()` in admin functions and `increase_liquidity` — no error codes on panic.
- **F-06:** Input/output vaults in `SwapSingle` lack Anchor constraints; validated at runtime instead.
- **F-07:** `pool_state` in `DecreaseLiquidity` only has `#[account(mut)]`, no PDA seeds verification.
- **F-08:** Operation owners bypass reward param period restrictions — increased blast radius if key compromised.
- **F-09:** `Clock::get().unwrap().unix_timestamp as u32` truncates i64→u32, wraps in year 2106.

### INFO Findings

F-10: Permissionless pool creation (PDA-seeded, one per config+pair). F-11: Oracle manipulation resistance limited (consistent with Uniswap V3). F-12: Fee growth u128 accumulator uses checked_add (would brick pool on overflow). F-13: reward_total_emissioned u64 could overflow with high emission rates. F-14: 30+ unwrap() in math libraries. F-15: 40+ unsafe `as` casts on tick_spacing.

---

## Kamino Lend — Lending Protocol ($1.63B TVL)

**Repo:** [Kamino-Finance/klend](https://github.com/Kamino-Finance/klend)
**Program ID:** `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD`
**Previous Audits:** OtterSec, Offside Labs, Certora, Sec3
**Codebase:** ~21,300 lines of Rust (Anchor with zero_copy)

Well-engineered lending protocol with post-transfer vault balance checks, CPI restriction enforcement, flash loan sandwiching prevention, comprehensive oracle validation (TWAP/confidence/heuristic), and careful arithmetic using a `Fraction` type.

### Summary Table

| ID | Severity | Title |
|----|----------|-------|
| F-01 | MEDIUM | Pyth price unwrap can panic → DoS |
| F-02 | MEDIUM | Switchboard confidence unwrap can panic → DoS |
| F-08 | MEDIUM | saturating_sub in debt trackers may drift |
| F-03 | LOW | Scope price chain unwrap |
| F-04 | LOW | Flash loan CPI prevention assumptions |
| F-06 | LOW | Liquidation bonus approaches zero near bad debt |
| F-09 | LOW | Interest rounding direction |
| F-10 | LOW | Panic in obligation order execution |
| F-11 | LOW | Elevation group uncapped liquidation bonus |
| F-14 | LOW | i64 cast overflow in event logging |
| F-05 | INFO | Flash loan design (well-designed) |
| F-07 | INFO | Protocol fee minimum 1 lamport |
| F-12 | INFO+ | Post-transfer vault balance checks (strong) |
| F-13 | INFO | Restricted programs check only on repay |
| F-15 | INFO | No overflow-checks in Cargo.toml |
| F-16 | INFO | Self-liquidation allowed (by design) |
| F-17 | INFO+ | Emergency council limited powers (good) |
| F-18 | INFO+ | Seed deposit prevents inflation attack (good) |

### MEDIUM Findings

#### [KM-F01] Unwrap on Pyth Price Conversion Can Panic

- **File:** `programs/klend/src/utils/prices/pyth.rs:75,80,95,96,100`
- **Description:** Multiple `.unwrap()` on `u64::try_from(pyth_price.price)`, `conf.checked_mul()`, and `pyth_price.exponent.checked_abs()`. If Pyth publishes a negative price (has happened historically with some feeds), the program panics — **all operations for that reserve blocked** (deposits, borrows, withdrawals, liquidations).
- **Code:**
  ```rust
  let price = u64::try_from(pyth_price.price).unwrap(); // L75
  let exp = pyth_price.exponent.checked_abs().unwrap() as u32; // L96
  ```
- **Fix:** Return `LendingError::PriceNotValid` instead of panicking.

#### [KM-F02] Unwrap on Switchboard Confidence Calculation

- **File:** `programs/klend/src/utils/prices/switchboard.rs:113,118`
- **Description:** `checked_sub().unwrap()` on scale subtraction. Same DoS scenario if Switchboard feed has unexpected scale values.
- **Fix:** Return error instead of unwrap.

#### [KM-F08] saturating_sub Used for Debt Tracker Accounting

- **File:** `programs/klend/src/lending_market/lending_operations.rs`
- **Description:** Extensive `saturating_sub` when updating elevation group debt trackers. If tracked amounts drift due to rounding, silently floors to 0 instead of surfacing error. Over time could allow more borrowing than intended.
- **Mitigating:** Values reset during `request_elevation_group`; primary borrow limit enforced at reserve level.

### LOW Findings

- **F-03:** Scope price chain unwrap (limited risk, chain_len checked).
- **F-04:** Flash loan CPI prevention uses stack height (standard pattern, combined with program_id check).
- **F-06:** Liquidation bonus approaches zero near 100% LTV — partially addressed by `bad_debt_liquidation_bonus_bps` at 0.99 LTV.
- **F-09:** Interest rounding direction — dust-level amounts, transaction fees exceed gains.
- **F-10:** `get_constant_bonus_rate` panics on invalid order state (guarded by creation-time validation).
- **F-11:** Elevation group `max_liquidation_bonus_bps=0` defaults to uncapped (u16::MAX).
- **F-14:** `withdraw_liquidity_amount as i64 - repay_amount as i64` can overflow for event logging.

### Positive Findings

- **F-12:** Post-transfer vault balance checks prevent accounting desynchronization attacks — a strong measure many protocols lack.
- **F-17:** Emergency council limited to: set borrow limit to 0, block price usage. Excellent least-privilege design.
- **F-18:** Seed deposit on reserve init prevents first-depositor inflation attack.

---

## Jito Stakenet — Stake Pool Management ($1.07B TVL)

**Repo:** [jito-foundation/stakenet](https://github.com/jito-foundation/stakenet)
**Programs:** `steward` + `validator-history`
**Previous Audits:** jito_steward_audit.pdf, jito_validator_history_audit.pdf
**Codebase:** ~14,500 lines of Rust

Two-program system: validator-history collects on-chain data, steward uses hierarchical bit-packed scoring (commission → MEV → age → vote credits) with binary filters to determine stake delegation across validators.

### Summary Table

| ID | Severity | Title |
|----|----------|-------|
| F-01 | MEDIUM | Floating-point in consensus-critical scoring |
| F-02 | MEDIUM | Oracle authority has unilateral power over scores |
| F-03 | MEDIUM | Permissionless compute_score can reset state |
| F-04 | LOW | get_unsafe in financial calculations |
| F-05 | LOW | Equal delegation creates Sybil incentive |
| F-06 | LOW | unwrap() in production code paths |
| F-07 | LOW | Directed stake division by zero risk |
| F-08 | LOW | Score multiplication pattern |
| F-09 | LOW | Hardcoded SLOTS_PER_EPOCH |
| F-10 | INFO | Permissionless history copy instructions |
| F-11 | INFO | Epoch u16 overflow at epoch 65535 |
| F-12 | INFO | Admin can bypass all protections via SPL passthrough |

### MEDIUM Findings

#### [JT-F01] Floating-Point Arithmetic in Consensus-Critical Scoring

- **Files:** `programs/steward/src/score.rs:329,368`, `steward_state.rs:885`
- **Description:** Scoring uses `f64` for vote credits ratios and delinquency thresholds. Floating-point is non-deterministic across CPU architectures. Latent consensus risk if Solana supports heterogeneous validator hardware.
- **Code:**
  ```rust
  let average_vote_credits = epoch_credits_window.iter()
      .filter_map(|&i| i).sum::<u32>() as f64
      / epoch_credits_window.len() as f64;
  ```
- **Fix:** Replace with fixed-point integer math using basis points or scaled u128.

#### [JT-F02] Oracle Authority Has Unilateral Power Over Validator Scores

- **File:** `programs/validator-history/src/instructions/update_stake_history.rs:35-42`
- **Description:** `oracle_authority` can set arbitrary lamports, rank, and is_superminority for any validator at any past epoch. No validation on values. Compromised oracle → mark all validators superminority (score=0) → route all $1.07B to colluding validators.
- **Fix:** Add sanity bounds, consider multi-sig/timelock for oracle authority, verify against stake distribution sysvar.

#### [JT-F03] Permissionless compute_score Can Reset State Mid-Cycle

- **File:** `programs/steward/src/state/steward_state.rs:712-725`
- **Description:** If `compute_score_slot_range` elapsed, entire cycle resets via `reset_state_for_new_cycle()`. Permissionless — any cranker can trigger. A delayed crank + strategic timing could wipe partial scoring progress.
- **Impact:** Limited since delegation is equal-share (1/N), but monitoring recommended.

### LOW Findings

- **F-04:** `get_unsafe` bypasses bounds checking in delegation bitmask operations.
- **F-05:** Equal 1/N delegation incentivizes running many mediocre validators over one excellent one.
- **F-06:** `unwrap()` in score.rs, utils.rs — `bincode::deserialize` on SlotHistory is most concerning.
- **F-07:** Division by `total_excess_lamports` uses raw `/` instead of `checked_div`.
- **F-08:** Score multiplication by binary filters (0/1) — fragile if filters ever return >1.
- **F-09:** Hardcoded `SLOTS_PER_EPOCH = 432_000` — should use `EpochSchedule::slots_per_epoch`.

### Positive Observations

- Excellent checked arithmetic discipline throughout
- Strong Anchor account validation with PDA seeds
- Well-designed state machine with progress tracking prevents double-processing
- Unstake caps limit per-epoch stake movement
- Hierarchical 4-tier bit-packed scoring ensures commission always prioritized
- Transient stake detection in rebalance

---

## Futarchy / MetaDAO — Prediction Market Governance ($12M TVL)

**Repo:** [metaDAOproject/futarchy](https://github.com/metaDAOproject/futarchy)
**Programs:** futarchy, conditional_vault, mint_governor, launchpad variants, bid_wall, performance packages

Implements DAO decision-making through prediction markets. Core flow: proposals create pass/fail conditional markets; TWAP oracle determines outcomes. Custom constant-product AMM with embedded arbitrage.

### Summary Table

| ID | Severity | Title |
|----|----------|-------|
| F-02 | HIGH | Admin functions bypass in non-production mode |
| F-09 | HIGH | admin_cancel_proposal drops pass pool reserves from accounting |
| F-03 | MEDIUM | TWAP oracle manipulation via observation gap weighting |
| F-04 | MEDIUM | Arbitrage functions use unwrap() — potential DoS |
| F-05 | MEDIUM | Arbitrage profit i64 cast overflow |
| F-08 | MEDIUM | TWAP aggregator wrapping produces incorrect TWAP |
| F-10 | MEDIUM | Protocol fees in losing pool lost on finalization |
| F-14 | MEDIUM | Missing re-execution prevention in execute_spending_limit_change |
| F-06 | LOW | LP fee is 0% — lower manipulation cost |
| F-12 | LOW | Flash loan vector (mitigated by TWAP rate limiting) |
| F-13 | LOW | Position authority can be any key — permanent lock |
| F-16 | LOW | Negative team threshold lowers bar for team proposals |
| F-17 | LOW | update_dao can set unsafe parameters |
| F-18 | LOW | Arbitrage grid search suboptimal, step_size=0 edge case |
| F-20 | LOW | Minimum proposal duration vs TWAP manipulation window |
| F-01 | INFO | Unstaking from non-draft proposals (by design) |
| F-07 | INFO | Spot pool split rounding on launch |
| F-11 | INFO | No reentrancy guard on Squads CPI (mitigated) |
| F-15 | INFO | Stale balance check in conditional swap |
| F-19 | INFO | Redemption truncation (negligible for binary) |
| F-10n | INFO | finalize_proposal losing pool accounting correct for conditional tokens |

### HIGH Findings

#### [FT-F02] Admin Functions Bypass in Non-Production Mode

- **Files:** `admin_remove_proposal.rs`, `admin_cancel_proposal.rs`, `admin_approve_execute_multisig_proposal.rs`, `collect_fees.rs`
- **Description:** All admin functions use `#[cfg(feature = "production")]` to gate admin key checks. If deployed without the `production` feature flag, **any signer** can remove proposals, cancel active proposals, approve/execute multisig proposals, and collect protocol fees.
- **Exploit:** Attacker calls `admin_cancel_proposal` → forcibly fails proposal → pass token holders lose everything.
- **Fix:** Always check admin keys at runtime. Store admin in DAO state.

#### [FT-F09] admin_cancel_proposal Drops Pass Pool Reserves

- **File:** `admin_cancel_proposal.rs:95-100`
- **Description:** When admin cancels, only fail pool merged back to spot. Pass pool reserves silently dropped via `..` pattern destructure. Tokens exist in vault but untracked by AMM.
- **Exploit:** Large proposal cancelled → pass pool reserves (potentially millions) stranded permanently.
- **Fix:** Add pass pool reserves back to spot accounting.

### MEDIUM Findings

- **F-03:** TWAP oracle manipulation via observation gap weighting (`futarchy_amm.rs:358-420`). Cap `slot_difference` to ~2 minutes.
- **F-04:** Arbitrage functions use `unwrap()` extensively — potential DoS on extreme pool states (`futarchy_amm.rs:630-830`).
- **F-05:** Arbitrage profit `i64` cast overflow for large values (`futarchy_amm.rs:656,694`).
- **F-08:** TWAP aggregator `wrapping_add` produces incorrect TWAP on overflow (`futarchy_amm.rs:403-406`).
- **F-10:** Protocol fees in losing pool silently lost on finalization (`finalize_proposal.rs:158-177`).
- **F-14:** Missing re-execution prevention — no `executed` flag on proposals (`execute_spending_limit_change.rs:35-42`).

---

## Sanctum S Controller — LST AMM ($1.1B TVL)

**Repo:** [igneous-labs/S](https://github.com/igneous-labs/S)
**Programs:** S Controller, Flat Fee pricing, SOL value calculator programs
**Prior Audits:** Neodyme, Ottersec, Sec3 (2024)

Single-pool AMM holding hundreds of LSTs. CPI-based composability with pluggable pricing and SOL value calculators. Well-written codebase — no HIGH or CRITICAL findings. Main risk: centralization (single admin, no timelock) for $1.1B TVL.

### Summary Table

| ID | Severity | Title |
|----|----------|-------|
| F-01 | MEDIUM | Remove liquidity missing end total SOL value invariant check |
| F-02 | MEDIUM | Protocol fees can be set to 100% (10,000 BPS) |
| F-03 | MEDIUM | Negative fees (rebates) create arbitrage opportunities |
| F-04 | LOW | First depositor LP token minting edge case |
| F-05 | LOW | Admin can set arbitrary sol_value_calculator programs |
| F-06 | LOW | Admin can set arbitrary pricing programs |
| F-07 | LOW | Consistent get_min() slightly undervalues LP holders |
| F-08 | INFO | Unsafe code in list deserialization (sound) |
| F-09 | INFO | Single admin key centralization risk |
| F-10 | INFO | No timelock on admin operations |
| F-11 | INFO | set_admin missing pool state checks |

### MEDIUM Findings

- **F-01:** `remove_liquidity` missing `end_total_sol_value >= start_total_sol_value` invariant check (`remove_liquidity.rs:83-84`). Other operations (swap, add_liquidity) have this check.
- **F-02:** Protocol fee validation accepts 10,000 BPS (100%). Compromised admin extracts ALL fees (`set_protocol_fee.rs:44-49`). Fix: Cap at 50% + timelock.
- **F-03:** Signed i16 fees allow [-10000, 10000]. Combined negative fees produce output >200% of input (`fee_bound.rs:5-9`). Pricing manager exploit possible.

### Positive Findings

- NOT vulnerable to pool share inflation attack (9-decimal precision, 1:1 LP:SOL rate)
- All arithmetic uses `checked_*` operations — no raw `as` casts in program code
- Rebalance atomicity enforced via instructions sysvar
- Swap same LST explicitly prevented
- Strong solores-generated account verification

---

## Tools Used

- Manual code review (primary)
- `grep`/`ripgrep` for pattern scanning
- Cargo Clippy, `cargo audit` for dependency checks
- Cross-referencing: Zealynx 45-point checklist, Helius security guide, Neodyme/Sec3 vulnerability taxonomies

---

## About the Auditor

Max is an AI co-founder specializing in code review, security analysis, and full-stack development. This audit was conducted as part of the Superteam "Audit & Fix Solana Repos" bounty.

**GitHub:** [@0xksure](https://github.com/0xksure)
