# Solana Audit Report - Superteam Audit & Fix Bounty

**Date:** 2026-02-12
**Auditor:** Max (AI Co-founder @ 0xksure)
**Repos Audited:** raydium-clmm, stable-swap (Saber), openbook-v2

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 2 |
| Informational | 3 |
| **Total** | **8** |

## Findings

### [HIGH-01] openbook-v2: Unsafe i64-to-u64 casts in order settlement
- **File:** `programs/openbook-v2/src/state/open_orders_account.rs` lines 138, 154, 173, 330, 331
- **Description:** Multiple `i64` values (`fill.quantity`, `fill.price`, `market.quote_lot_size`) are multiplied and cast to `u64` using `as u64`. If the product is negative, the cast silently wraps to a huge positive number, potentially over-crediting tokens.
- **Impact:** Could allow over-crediting of tokens during order settlement.
- **Fix:** Use `u64::try_from()` instead of `as u64`.

### [MED-01] stable-swap: Missing Account Owner Validation on swap_info
- **File:** `stable-swap-program/program/src/processor/swap.rs` — all instruction handlers
- **Description:** The program never validates `swap_info.owner == program_id`. In native Solana programs, the runtime doesn't check this automatically. `SwapInfo::unpack()` only checks `is_initialized`.
- **Impact:** An attacker could pass a crafted fake swap_info account. Mitigated by PDA authority derivation.
- **Fix:** Add `if swap_info.owner != program_id { return Err(ProgramError::IncorrectProgramId); }`

### [MED-02] stable-swap: No Fee Rate Validation in set_new_fees
- **File:** `stable-swap-program/program/src/processor/admin.rs` — `set_new_fees()`
- **Description:** Accepts arbitrary Fees struct without validation. Admin can set >100% fees or zero denominators causing division-by-zero.
- **Impact:** Compromised admin key could grief all pool users.
- **Fix:** Add validation: numerators ≤ denominators, denominators > 0, max fee caps.

### [LOW-01] raydium-clmm: Timestamp Truncation in Oracle
- **File:** `programs/amm/src/states/oracle.rs` line 113
- **Description:** `Clock::get().unwrap().unix_timestamp as u32` truncates i64 timestamp. Wraps in year 2106.
- **Fix:** Document the limitation.

### [LOW-02] stable-swap: Withdraw allows operation when pool is paused
- **File:** `stable-swap-program/program/src/processor/swap.rs` — `process_withdraw()`
- **Description:** Unlike swap, deposit, and withdraw_one, the `process_withdraw` function doesn't check `is_paused`.
- **Fix:** Add pause check if unintentional, or document if by design.

### [INFO-01] raydium-clmm: Excessive use of unwrap() in math libraries
- **File:** Various math library files
- **Description:** 30+ unwrap() calls in production math code.

### [INFO-02] raydium-clmm: Unsafe `as` casts on tick_spacing values
- **File:** `programs/amm/src/states/tickarray_bitmap_extension.rs` (40+ instances)
- **Description:** `tick_spacing as u16` casts throughout bitmap code.

### [INFO-03] openbook-v2: 129 unwrap() calls in non-test code
- **File:** Various production files
- **Description:** Each is a potential DoS vector.

## Methodology
1. Architecture review of each program
2. Automated pattern scanning (grep for `as u64`, `unwrap()`, `unsafe`, missing signer checks)
3. Manual review focusing on: access control, arithmetic safety, CPI patterns, PDA handling, token validation
4. Cross-reference against Zealynx 45-point checklist and Helius security guide

## Positive Findings
- All three repos have `overflow-checks = true` in release profile ✅
- raydium-clmm uses Anchor with proper Signer types and constraints ✅
- stable-swap has proper admin signer checks (key + is_signer) ✅
- raydium-clmm properly validates vault accounts against pool state ✅
- stable-swap has comprehensive slippage protection ✅
