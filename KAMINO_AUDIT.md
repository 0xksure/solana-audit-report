# Kamino Lend (klend) Security Audit Report

**Target:** Kamino-Finance/klend  
**TVL:** ~$1.63B  
**Auditor:** Automated + Manual Review  
**Date:** February 13, 2026  
**Codebase:** ~21,300 lines of Rust (Anchor framework)  
**Previous Auditors:** OtterSec, Offside Labs, Certora, Sec3  

---

## Executive Summary

Kamino Lend is a well-engineered Solana lending protocol with extensive safety mechanisms. The codebase demonstrates mature security practices including: post-transfer vault balance checks, CPI restriction enforcement, flash loan sandwiching prevention, comprehensive oracle validation with TWAP/confidence/heuristic checks, and careful arithmetic using a `Fraction` type built on fixed-point math. The protocol has been audited by four firms.

That said, several findings of varying severity were identified. Most are LOW/INFO level due to the existing mitigations, but a few deserve closer attention given the $1.63B TVL.

---

## Architecture Overview

### Program Structure
- **Single program:** `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD`
- **Framework:** Anchor with `zero_copy` accounts
- **Key state accounts:** `LendingMarket`, `Reserve`, `Obligation`, `GlobalConfig`

### Core Flows
1. **Deposit:** User deposits liquidity → receives cTokens (collateral tokens)
2. **Borrow:** User borrows against collateral, subject to LTV limits
3. **Repay:** User repays borrowed amount + accrued interest
4. **Liquidation:** Unhealthy obligations liquidated by third parties with bonus
5. **Flash Loans:** Single-tx borrow+repay with fee, no collateral needed
6. **Elevation Groups:** Special groups with custom LTV/liquidation params

### Oracle Integration
- **Pyth** (PriceUpdateV2 with full verification)
- **Switchboard** (PullFeedAccountData)
- **Scope** (Kamino's own oracle aggregator with price chains)
- All oracles validated for: price age, TWAP divergence, confidence intervals, price heuristics (upper/lower bounds)

---

## Findings

### FINDING-01: Unwrap on Pyth Price Conversion Can Panic
- **Severity:** MEDIUM  
- **File:** `programs/klend/src/utils/prices/pyth.rs:75,80,95,96,100`
- **Description:** Multiple `.unwrap()` calls on `u64::try_from(pyth_price.price)`, `conf.checked_mul()`, and `pyth_price.exponent.checked_abs()` that will panic if Pyth returns a negative price or exponent that overflows.
- **Code:**
  ```rust
  let price = u64::try_from(pyth_price.price).unwrap(); // L75
  let scaled_conf: u64 = conf.checked_mul(oracle_confidence_factor).unwrap(); // L80
  let value = u64::try_from(pyth_price.price).unwrap(); // L95
  let exp = pyth_price.exponent.checked_abs().unwrap() as u32; // L96
  ```
- **Exploit Scenario:** If Pyth publishes a negative price (which has happened historically with some feeds), the `try_from` will fail and the program will panic, causing a denial of service for any instruction that refreshes this reserve. All borrows, deposits, withdrawals, and liquidations for that reserve would be blocked.
- **Recommended Fix:** Use `checked_*` operations and return `LendingError::PriceNotValid` instead of panicking.
- **Mitigating Factor:** Pyth's PriceUpdateV2 with `VerificationLevel::Full` makes negative prices unlikely but not impossible (e.g., synthetic assets).

### FINDING-02: Unwrap on Switchboard Confidence Calculation
- **Severity:** MEDIUM  
- **File:** `programs/klend/src/utils/prices/switchboard.rs:113,118`
- **Description:** `checked_sub().unwrap()` on scale subtraction can panic.
- **Code:**
  ```rust
  price_scale.checked_sub(stdev_scale).unwrap(), // L113
  stdev_scale.checked_sub(price_scale).unwrap(), // L118
  ```
- **Exploit Scenario:** Same DoS scenario as FINDING-01. If Switchboard feed has unexpected scale values, reserve operations are blocked.
- **Recommended Fix:** Return error instead of unwrap.
- **Mitigating Factor:** The outer if/else structure should catch the right branch, but edge cases (equal scales not handled in one branch) could theoretically cause issues.

### FINDING-03: Scope Price Chain - Unwrap on First Element
- **Severity:** LOW  
- **File:** `programs/klend/src/utils/prices/scope.rs:98,112`
- **Description:** `price_chain_raw[0].unwrap()` after checking `chain_len == 1`, and `.min().unwrap()` both unwrap without error handling.
- **Code:**
  ```rust
  let price = price_chain_raw[0].unwrap(); // L98
  .min().unwrap(); // L112
  ```
- **Exploit Scenario:** Limited risk since chain_len > 0 is checked, but panics in production should be avoided.
- **Recommended Fix:** Use `ok_or()` with proper error.

### FINDING-04: Flash Loan - CPI Prevention Relies on Stack Height
- **Severity:** LOW  
- **File:** `programs/klend/src/lending_market/ix_utils.rs:25-45`, `flash_ixs.rs`
- **Description:** Flash loan CPI prevention uses `get_stack_height() > TRANSACTION_LEVEL_STACK_HEIGHT`. This is the standard Solana pattern but has known limitations — it only checks the current call depth, not whether the flash borrow was initiated via CPI.
- **Code:**
  ```rust
  if get_stack_height() > TRANSACTION_LEVEL_STACK_HEIGHT {
      return Ok(true);
  }
  ```
- **Exploit Scenario:** The protocol also checks `crate::ID != current_ixn.program_id` which provides defense-in-depth. Combined, these checks are robust. However, if Solana runtime behavior changes around instruction introspection, this could be affected.
- **Recommended Fix:** Current implementation is standard practice. Consider documenting the assumption.
- **Mitigating Factor:** Both program_id check AND stack height check must pass, providing strong protection.

### FINDING-05: Flash Loan - Single Reserve Per Transaction
- **Severity:** INFO  
- **File:** `programs/klend/src/lending_market/flash_ixs.rs:95-99`
- **Description:** The protocol correctly prevents multiple flash borrows in the same transaction, but the check iterates through ALL remaining instructions in the transaction. A malicious actor cannot use flash loans to manipulate oracle prices within the same transaction because:
  1. Only one flash borrow allowed per tx
  2. Flash borrow/repay must be paired with matching amounts
  3. Oracle prices are refreshed from external feeds (Pyth/Switchboard/Scope), not from on-chain AMM pools
- **Recommended Fix:** None needed — well-designed.

### FINDING-06: Liquidation Bonus Can Reach Zero Under Edge Conditions
- **Severity:** LOW  
- **File:** `programs/klend/src/state/liquidation_operations.rs:326-345`
- **Description:** The `calculate_liquidation_bonus` function caps the bonus at `diff_to_bad_debt = 1.0 - user_no_bf_ltv`. When `user_no_bf_ltv` is very close to 1.0, the bonus approaches zero, potentially making liquidation economically unattractive.
- **Code:**
  ```rust
  let diff_to_bad_debt = Fraction::ONE.saturating_sub(*user_no_bf_ltv);
  min(collared_bonus, diff_to_bad_debt)
  ```
- **Exploit Scenario:** An obligation could enter a state where its no-BF LTV is so close to 100% that liquidators have no incentive to liquidate. This would leave bad debt in the system.
- **Recommended Fix:** The `bad_debt_liquidation_bonus_bps` config partially addresses this (activated when `user_no_bf_ltv >= 0.99`), but there's a gap between ~0.99 LTV and 1.0 LTV where bonuses shrink rapidly. Consider ensuring a minimum floor bonus in this range.
- **Mitigating Factor:** The `bad_debt_liquidation_bonus_bps` kicks in at 0.99 LTV, and `socialize_loss` handles the remaining bad debt case.

### FINDING-07: Protocol Liquidation Fee Always At Least 1 Lamport
- **Severity:** INFO  
- **File:** `programs/klend/src/state/liquidation_operations.rs:965-968`
- **Description:** `calculate_protocol_liquidation_fee` uses `max(protocol_fee, 1)`, meaning even with 0% protocol fee configured, 1 lamport is always taken.
- **Code:**
  ```rust
  max(protocol_fee, 1)
  ```
- **Exploit Scenario:** No real exploit, but this is a minor deviation from expected behavior if protocol_liquidation_fee_pct is set to 0.
- **Recommended Fix:** Return 0 when protocol_liquidation_fee_pct is 0.

### FINDING-08: `saturating_sub` Used for Debt Tracker Accounting
- **Severity:** MEDIUM  
- **File:** `programs/klend/src/lending_market/lending_operations.rs` (multiple locations in `update_elevation_group_debt_trackers_on_repay`)
- **Description:** Extensive use of `saturating_sub` when updating debt trackers in elevation groups. If the tracked amounts drift due to rounding, `saturating_sub` silently floors to 0 instead of surfacing the error.
- **Code:**
  ```rust
  deposit_reserve.borrowed_amounts_against_this_reserve_in_elevation_groups
      [elevation_group_index] = deposit_reserve
      .borrowed_amounts_against_this_reserve_in_elevation_groups[elevation_group_index]
      .saturating_sub(deposit.borrowed_amount_against_this_collateral_in_elevation_group);
  ```
- **Exploit Scenario:** Over time, if rounding causes the per-collateral tracking to exceed the per-reserve tracking (due to interest accrual rounding differences), `saturating_sub` would silently undercount, potentially allowing more borrowing than intended within an elevation group's limits.
- **Recommended Fix:** Consider using `checked_sub` with an explicit error, or periodically reconciling these values.
- **Mitigating Factor:** The values are reset during `request_elevation_group` and the primary borrow limit is also enforced at the reserve level, providing defense-in-depth.

### FINDING-09: Interest Accrual Rounding Direction
- **Severity:** LOW  
- **File:** `programs/klend/src/state/reserve.rs` (interest accrual), `obligation.rs` (borrow accrual)
- **Description:** The protocol uses `Fraction` (fixed-point) math for interest accrual. The `compound_interest` function approximates compound interest. Rounding in fixed-point arithmetic slightly favors either the protocol or borrowers depending on the direction of truncation.
- **Exploit Scenario:** A sophisticated attacker could potentially extract small amounts by repeatedly depositing/withdrawing to exploit rounding. However, the amounts would be dust-level and transaction fees would exceed gains.
- **Recommended Fix:** Current implementation is acceptable. The `approximate_compounded_interest` macro and `Fraction` type handle this well.

### FINDING-10: Obligation Order Execution - Panic on Invalid State
- **Severity:** LOW  
- **File:** `programs/klend/src/state/liquidation_operations.rs:912-919`
- **Description:** `get_constant_bonus_rate` panics if bonus range start != end for non-distance-based conditions.
- **Code:**
  ```rust
  fn get_constant_bonus_rate(order: &ObligationOrder) -> Fraction {
      let range = order.execution_bonus_rate_range();
      if range.end() != range.start() {
          panic!("The order validation should not have allowed...");
      }
  ```
- **Exploit Scenario:** If order validation has a bug that allows non-constant bonus ranges for conditions without distance semantics, this would panic and cause DoS. However, this is guarded by creation-time validation.
- **Recommended Fix:** Return error instead of panic.

### FINDING-11: Elevation Group max_liquidation_bonus_bps Logic
- **Severity:** LOW  
- **File:** `programs/klend/src/state/liquidation_operations.rs:216-230`
- **Description:** `get_emode_max_liquidation_bonus` returns `u16::MAX` (effectively unlimited) when the elevation group's `max_liquidation_bonus_bps` is 0 or exceeds either reserve's max. This means misconfigured elevation groups default to no cap.
- **Code:**
  ```rust
  if elevation_group.max_liquidation_bonus_bps > collateral_reserve.max_liquidation_bonus_bps
      || elevation_group.max_liquidation_bonus_bps > debt_reserve.max_liquidation_bonus_bps
      || elevation_group.max_liquidation_bonus_bps == 0
  {
      u16::MAX
  }
  ```
- **Exploit Scenario:** If an admin misconfigures an elevation group with max_liquidation_bonus_bps=0, liquidation bonuses in that emode are effectively uncapped (up to reserve-level caps).
- **Recommended Fix:** Distinguish between "not configured" (0) and intentionally set values.
- **Mitigating Factor:** Config validation in `validate_reserve_config_integrity` checks elevation group params on the reserve side.

### FINDING-12: Post-Transfer Vault Balance Checks (Strong Defense)
- **Severity:** INFO (Positive Finding)
- **File:** `programs/klend/src/lending_market/lending_checks.rs:380-440`
- **Description:** The protocol performs post-transfer vault balance verification that compares actual token account balances against expected internal accounting. This prevents accounting desynchronization attacks.
- **Evidence:** `post_transfer_vault_balance_liquidity_reserve_checks` verifies:
  1. Pre/post vault balance differences match expected amounts
  2. Internal `available_amount` tracking matches vault reality
  3. The diff between vault balance and available_amount is constant (fees accounted for)
- **Assessment:** This is a strong security measure that many lending protocols lack.

### FINDING-13: Restricted Programs Check Only on Repay
- **Severity:** INFO  
- **File:** `programs/klend/src/handlers/handler_repay_obligation_liquidity.rs:151`
- **Description:** The `no_restricted_programs_within_tx` check is only applied on the repay instruction, not on borrow, deposit, or withdraw.
- **Code:**
  ```rust
  constraint = ix_utils::no_restricted_programs_within_tx(&instruction_sysvar_account)? @ LendingError::TransactionIncludesRestrictedPrograms
  ```
- **Exploit Scenario:** An attacker could potentially include restricted programs in transactions that don't involve repay. However, the purpose of this check is likely specific to repay (preventing certain MEV attacks on repayments).
- **Recommended Fix:** Document why the check is only on repay, or extend to other instructions if intended.

### FINDING-14: `as u64` Cast on Liquidation Handler
- **Severity:** LOW
- **File:** `programs/klend/src/handlers/handler_liquidate_obligation_and_redeem_reserve_collateral.rs:224-226`
- **Description:** Casting `u64` to `i64` for PnL logging can overflow for very large amounts.
- **Code:**
  ```rust
  withdraw_liquidity_amount as i64 - repay_amount as i64
  ```
- **Exploit Scenario:** No direct exploit — this is used for event emission/logging only. But if `withdraw_liquidity_amount` or `repay_amount` exceeds `i64::MAX`, the logged PnL will be incorrect.
- **Recommended Fix:** Use `i128` or saturating casts for event data.

### FINDING-15: Overflow Checks in Cargo.toml
- **Severity:** INFO  
- **File:** `Cargo.toml` (workspace root)
- **Description:** The workspace Cargo.toml does NOT have `overflow-checks = true` in the profile section. Anchor programs on Solana compile in release mode by default which has overflow checks **disabled**.
- **Assessment:** The protocol heavily uses the `Fraction` type which uses `checked_*` operations internally, and also uses `checked_add`, `checked_mul` etc. throughout the codebase. However, some direct arithmetic (particularly in test macros/helpers) could theoretically overflow.
- **Mitigating Factor:** Critical math paths use `Fraction` with checked operations. The `as u64` casts identified in FINDING-01 are the main concern.
- **Recommended Fix:** Add `overflow-checks = true` to the release profile for defense-in-depth.

### FINDING-16: Self-Liquidation Not Prevented
- **Severity:** INFO
- **File:** `programs/klend/src/handlers/handler_liquidate_obligation_and_redeem_reserve_collateral.rs`
- **Description:** There is no check preventing an obligation owner from liquidating their own obligation. Self-liquidation could be used to extract the liquidation bonus from oneself (essentially converting an unhealthy position into a smaller position while pocketing the bonus).
- **Exploit Scenario:** 
  1. User creates obligation with collateral near liquidation threshold
  2. Oracle price moves slightly, making position unhealthy
  3. User self-liquidates to collect bonus
  4. Net effect: user extracts value from the lending pool via the bonus
- **Mitigating Factor:** The liquidation bonus is designed to incentivize liquidation — whether the liquidator is the borrower or a third party, the protocol's health is maintained either way. The bonus is economically justified by the risk reduction.
- **Recommended Fix:** This is generally considered acceptable in DeFi lending. No fix needed.

### FINDING-17: Emergency Council Limited Powers
- **Severity:** INFO (Positive Finding)
- **File:** `programs/klend/src/lending_market/lending_operations.rs:2400-2410`
- **Description:** The emergency council can only: set borrow limit to 0 and block price usage. This is a good least-privilege design.
- **Code:**
  ```rust
  pub fn is_update_reserve_config_mode_allowed_for_emergency_council(
      mode: UpdateConfigMode,
      value: &[u8],
  ) -> bool {
      match mode {
          UpdateConfigMode::UpdateBorrowLimit if borsh_deserialize::<u64>(value) == 0 => true,
          UpdateConfigMode::UpdateBlockPriceUsage if borsh_deserialize::<u8>(value) == 1 => true,
          _ => false,
      }
  }
  ```

### FINDING-18: Seed Deposit Prevents First-Depositor Attack
- **Severity:** INFO (Positive Finding)
- **File:** `programs/klend/src/handlers/handler_seed_deposit_on_init_reserve.rs`
- **Description:** The protocol requires an initial seed deposit when initializing a reserve, preventing the classic "first depositor" inflation attack where an attacker can manipulate the exchange rate by depositing 1 wei then donating to inflate share price.

---

## Automated Scan Results

### Unsafe Casts (`as u64/u128/i64/i128`)
- **42 instances found**, mostly in:
  - Version comparisons (`PROGRAM_VERSION as u64`) — safe, constant
  - Test macros — not in production
  - Timestamp conversions (`current_ts as u64`) — safe (positive timestamps)
  - PnL event logging (FINDING-14)
  - Liquidation handler signed arithmetic (FINDING-14)

### Unwrap Usage
- **~50 instances**, categorized:
  - **Oracle price parsing (8 instances)** — FINDINGS 01-03 (MEDIUM/LOW)
  - **Test/IDL code (~15 instances)** — not in production path
  - **BorrowRateCurve (6 instances)** — validated at config time
  - **Account loading (5 instances)** — Anchor guarantees valid accounts
  - **Checked arithmetic (~10 instances)** — mostly `checked_mul().unwrap()` that should be `ok_or(MathOverflow)`

### Unsafe Code
- **0 instances** of `unsafe` keyword in program code.

### Account Validation
- All accounts use Anchor's `#[account]` constraints
- `/// CHECK:` annotations are properly justified with PDA seeds or cross-program verification
- Owner checks enforced by Anchor's `AccountLoader` and `has_one` constraints

---

## Risk Assessment Summary

| ID | Severity | Description | Status |
|----|----------|-------------|--------|
| F01 | MEDIUM | Pyth price unwrap can panic → DoS | Open |
| F02 | MEDIUM | Switchboard confidence unwrap can panic → DoS | Open |
| F03 | LOW | Scope price chain unwrap | Open |
| F04 | LOW | Flash loan CPI prevention assumptions | Acceptable |
| F05 | INFO | Flash loan design analysis | Well-designed |
| F06 | LOW | Liquidation bonus approaches zero near bad debt | Partially mitigated |
| F07 | INFO | Protocol fee minimum 1 lamport | Cosmetic |
| F08 | MEDIUM | saturating_sub in debt trackers may drift | Open |
| F09 | LOW | Interest rounding direction | Acceptable |
| F10 | LOW | Panic in obligation order execution | Open |
| F11 | LOW | Elevation group uncapped liquidation bonus | Config-dependent |
| F12 | INFO+ | Post-transfer vault balance checks | Strong defense |
| F13 | INFO | Restricted programs check scope | Documentation |
| F14 | LOW | i64 cast overflow in event logging | Open |
| F15 | INFO | No overflow-checks in Cargo.toml | Mitigated by Fraction |
| F16 | INFO | Self-liquidation allowed | By design |
| F17 | INFO+ | Emergency council limited powers | Good design |
| F18 | INFO+ | Seed deposit prevents inflation attack | Good design |

---

## Overall Assessment

**Security Rating: STRONG** (for a DeFi protocol)

The Kamino Lend codebase demonstrates mature security engineering. Key strengths:
1. Multi-oracle integration with comprehensive price validation
2. Post-transfer balance reconciliation prevents accounting attacks
3. CPI restrictions prevent flash loan manipulation via composability
4. Elevation group system provides flexible risk management
5. Emergency mode and limited council powers for incident response
6. Seed deposit mechanism prevents first-depositor attacks
7. Comprehensive LTV checking (pre and post operation invariants)

**Key Risks:**
- Oracle-related panics (F01-F02) are the highest-severity findings — they could cause temporary DoS for a reserve if an oracle publishes unexpected data
- Debt tracker drift (F08) could theoretically allow slight overborrrowing in elevation groups over long periods
- No overflow-checks in release build (F15) relies on the discipline of using checked math everywhere

**Recommendations for Bounty Submission:**
- F01 and F02 are the most actionable findings — oracle panics causing DoS in a $1.63B protocol are meaningful
- F08 (debt tracker drift via saturating_sub) is subtle and could accumulate over time
- F10 (panic in order execution) is low probability but high impact

---

*Report generated from commit at HEAD of Kamino-Finance/klend repository.*
