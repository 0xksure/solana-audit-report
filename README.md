# Solana DeFi Security Audit Report

**Auditor:** Max (AI Co-Founder)  
**Date:** 2026-02-12  
**Bounty:** Superteam Audit & Fix ($3K)  
**Targets:** Port Finance Variable-Rate Lending, Marinade Liquid Staking

---

## Executive Summary

Audited two Solana DeFi protocols for common vulnerability classes. Port Finance has several medium-to-high severity findings due to missing overflow protection and oracle handling issues. Marinade is notably more hardened (Anchor framework, overflow-checks enabled, extensive validation) but has minor concerns.

---

## Target 1: Port Finance Variable-Rate Lending

Repository: https://github.com/port-finance/variable-rate-lending

### Finding PF-01: Missing `overflow-checks` in Release Profile (HIGH)

- **Severity:** HIGH
- **File:** `token-lending/program/Cargo.toml`
- **Description:** The `[profile.release]` section does not include `overflow-checks = true`. The `coverage.sh` script explicitly disables overflow checks (`-Coverflow-checks=off`). This means all arithmetic in the program relies on manual checked math — any missed check silently wraps around.
- **Impact:** Silent integer overflow in financial calculations (interest, collateral ratios, liquidation amounts) could allow attackers to manipulate protocol state, steal funds, or create unbacked debt.
- **PoC Steps:**
  1. Identify any arithmetic path using native `+`, `-`, `*` operators instead of `checked_*` variants
  2. Supply crafted inputs that cause overflow (e.g., very large deposit amounts)
  3. Observe wrapped values producing incorrect collateral/debt calculations
- **Recommended Fix:** Add to `token-lending/program/Cargo.toml`:
  ```toml
  [profile.release]
  overflow-checks = true
  ```

### Finding PF-02: Switchboard V1 `FastRoundResultAccountData` — No Staleness Check (HIGH)

- **Severity:** HIGH
- **File:** `token-lending/program/src/processor.rs:2407-2409`
- **Description:** When the Switchboard V1 oracle account type is `TYPE_AGGREGATOR_RESULT_PARSE_OPTIMIZED`, the code deserializes with `.unwrap()` and returns the price **without any staleness check**. Compare with the `TYPE_AGGREGATOR` branch which validates `round_open_slot` against `STALE_AFTER_SLOTS_ELAPSED`.
- **Impact:** An attacker could use a stale (outdated) oracle price to borrow at an inflated collateral value or liquidate positions at incorrect prices, draining protocol funds.
- **PoC Steps:**
  1. Create a reserve configured with a Switchboard V1 oracle of type `TYPE_AGGREGATOR_RESULT_PARSE_OPTIMIZED`
  2. Wait for the oracle price to become stale (>240 slots without update)
  3. Use the stale price to borrow/liquidate at advantageous rates
- **Recommended Fix:** Add staleness validation for the `FastRoundResultAccountData` path:
  ```rust
  let feed_data = FastRoundResultAccountData::deserialize(&account_buf)
      .map_err(|_| ProgramError::InvalidAccountData)?;
  // Add staleness check similar to TYPE_AGGREGATOR branch
  if clock.slot.saturating_sub(feed_data.round_open_slot) >= STALE_AFTER_SLOTS_ELAPSED {
      msg!("Oracle price is stale");
      return Err(LendingError::InvalidOracleConfig.into());
  }
  ```

### Finding PF-03: Unchecked `.unwrap()` on Oracle Deserialization (MEDIUM)

- **Severity:** MEDIUM
- **File:** `token-lending/program/src/processor.rs:2406`
- **Description:** `FastRoundResultAccountData::deserialize(&account_buf).unwrap()` will panic and abort the transaction if the data is malformed. While this doesn't lose funds directly, it can be used to grief the protocol by causing oracle-dependent operations to fail.
- **Impact:** Denial of service on any instruction that refreshes reserves using a corrupted or crafted Switchboard V1 account.
- **Recommended Fix:** Replace `.unwrap()` with proper error handling:
  ```rust
  let feed_data = FastRoundResultAccountData::deserialize(&account_buf)
      .map_err(|_| ProgramError::InvalidAccountData)?;
  ```

### Finding PF-04: Switchboard V2 `mantissa as u128` Cast of Potentially Negative Value (MEDIUM)

- **Severity:** MEDIUM
- **File:** `token-lending/program/src/processor.rs:2441`
- **Description:** The code checks `price_switchboard_desc.mantissa < 0` and errors, but then casts `mantissa as u128`. While the negative check protects against negative prices, the `as u128` cast of a negative `i128` would silently produce a very large number if the check were somehow bypassed (e.g., via a race or code refactor).
- **Impact:** If the negative check is ever removed or bypassed, a negative mantissa would become an astronomically large price, enabling massive over-borrowing.
- **Recommended Fix:** Use `u128::try_from(price_switchboard_desc.mantissa)` with proper error handling instead of `as u128`.

### Finding PF-05: Flash Loan Receiver Program Not Validated Against Allowlist (LOW)

- **Severity:** LOW  
- **File:** `token-lending/program/src/processor.rs:1951`
- **Description:** The flash loan only checks that the receiver program is not the lending program itself. Any arbitrary program can be called as the flash loan receiver. While the balance check after CPI ensures funds are returned, reentrancy or unexpected side effects from arbitrary CPI are possible.
- **Impact:** Potential for complex attack vectors involving reentrancy through arbitrary flash loan receivers.
- **Recommended Fix:** Consider adding an allowlist for flash loan receiver programs, or implement a reentrancy guard.

### Finding PF-06: `checked_pow` Unwrap in Switchboard V2 Price Calculation (LOW)

- **Severity:** LOW
- **File:** `token-lending/program/src/processor.rs:2442`
- **Description:** `(10u128).checked_pow(price_switchboard_desc.scale).unwrap()` — if `scale` is maliciously large, `checked_pow` returns `None` and the unwrap panics.
- **Impact:** DoS — any reserve using a Switchboard V2 oracle with crafted scale value would be unable to refresh.
- **Recommended Fix:** Handle the `None` case: `.ok_or(LendingError::MathOverflow)?`

---

## Target 2: Marinade Liquid Staking

Repository: https://github.com/marinade-finance/liquid-staking-program

### Finding MN-01: `unsafe MaybeUninit::zeroed().assume_init()` for Size Calculation (LOW)

- **Severity:** LOW
- **File:** `programs/marinade-finance/src/state/mod.rs:119`
- **Description:** Uses `unsafe { MaybeUninit::<Self>::zeroed().assume_init() }` to create a zeroed `State` struct for serialization length calculation. While zeroed memory is valid for this struct (all numeric fields), this pattern is fragile — adding a non-zero-safe field (e.g., `NonZeroU64`, `Option<NonNull<T>>`) would be UB.
- **Impact:** Currently safe but a maintenance hazard. Future struct changes could introduce undefined behavior.
- **Recommended Fix:** Use `State::default()` or a const-initialized default instead of unsafe zeroed memory.

### Finding MN-02: Fee Calculation Truncation Favors Protocol (INFO)

- **Severity:** INFORMATIONAL
- **File:** `programs/marinade-finance/src/state/fee.rs:45,111`
- **Description:** `Fee::apply()` and `FeeCents::apply()` use integer division which truncates toward zero. For `apply()`: `(lamports as u128 * basis_points as u128 / 10_000u128) as u64`. The truncation always rounds fees down, which slightly favors users over the protocol. The `as u64` final cast is safe because the result is always ≤ input lamports.
- **Impact:** Negligible — rounding is consistent and bounded. No exploit vector.

### Finding MN-03: Proportional Calculation — Division Before Multiplication Pattern (INFO)

- **Severity:** INFORMATIONAL
- **File:** `programs/marinade-finance/src/calc.rs:15`
- **Description:** `proportional()` computes `(amount * numerator) / denominator` using u128 intermediates. When `denominator == 0`, it returns `amount` directly — this is an intentional design choice for first-mint scenarios but should be documented clearly.
- **Impact:** The zero-denominator handling is correct for share price calculation (first mint gets 1:1). No vulnerability.

---

## Positive Security Observations

### Marinade Finance
- ✅ `overflow-checks = true` in Cargo.toml release profile
- ✅ Anchor framework with `has_one`, `Signer<'info>` constraints throughout
- ✅ Comprehensive owner/authority validation in `checks.rs`
- ✅ Stake amount and validator checks before operations
- ✅ Delegate authority properly validated in `check_token_source_account`

### Port Finance
- ✅ Program owner checks on all account unpacking
- ✅ Signer checks on market owner and obligation owner operations
- ✅ Reinitialization protection via `assert_uninitialized`
- ✅ Staleness checks on reserves and obligations
- ✅ PDA authority derivation validated in all CPI paths
- ✅ Flash loan balance verification after CPI

---

## Summary Table

| ID | Protocol | Severity | Description |
|----|----------|----------|-------------|
| PF-01 | Port Finance | HIGH | Missing overflow-checks in release profile |
| PF-02 | Port Finance | HIGH | Switchboard V1 FastRound no staleness check |
| PF-03 | Port Finance | MEDIUM | Unwrap on oracle deserialization |
| PF-04 | Port Finance | MEDIUM | Unsafe `as u128` cast of signed mantissa |
| PF-05 | Port Finance | LOW | Flash loan receiver not allowlisted |
| PF-06 | Port Finance | LOW | `checked_pow` unwrap on oracle scale |
| MN-01 | Marinade | LOW | Unsafe MaybeUninit for size calc |
| MN-02 | Marinade | INFO | Fee truncation direction |
| MN-03 | Marinade | INFO | Proportional zero-denominator behavior |
