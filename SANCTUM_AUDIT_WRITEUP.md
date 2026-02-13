# Sanctum S Controller Security Audit Report

**Auditor:** Max (AI Co-Founder @ 0xksure)  
**Date:** February 13, 2026  
**Repository:** [igneous-labs/S](https://github.com/igneous-labs/S)  
**Programs:** S Controller, Flat Fee pricing, SOL value calculator programs  
**TVL:** ~$1.1B  
**Prior Audits:** Neodyme, Ottersec, Sec3 (2024)  
**Fix PR Branch:** [0xksure/S:fix/security-audit-fixes](https://github.com/0xksure/S/tree/fix/security-audit-fixes)

---

## Executive Summary

Independent security audit of the Sanctum S Controller — a single-pool LST AMM holding hundreds of liquid staking tokens on Solana. The audit identified **3 MEDIUM, 4 LOW, and 4 INFO** findings. No CRITICAL or HIGH issues found. The codebase is well-engineered with checked arithmetic throughout, strong account verification via solores, and multiple previous professional audits.

---

## MEDIUM Severity Findings

### [SC-F01] Missing end_total_sol_value Invariant in remove_liquidity

**Severity:** MEDIUM  
**File:** `programs/s-controller/src/processor/remove_liquidity.rs`

#### Description

Both `swap_exact_in` (line 130) and `add_liquidity` (line 126) enforce a critical invariant:

```rust
let end_total_sol_value = accounts.pool_state.total_sol_value()?;
if end_total_sol_value < start_total_sol_value {
    return Err(SControllerError::PoolWouldLoseSolValue.into());
}
```

This ensures the pool's total SOL value never decreases from user operations. However, `remove_liquidity` does NOT have this check. After the final `sync_sol_value_unchecked` call, the pool's total SOL value is not verified.

#### Impact

A malicious or buggy SOL value calculator program (set by admin via `set_sol_value_calculator`) could report deflated SOL values after the withdrawal sync. This would cause:
- Pool accounting to undercount total value
- Subsequent LP token redemptions to receive less than fair value
- Gradual pool value drain over multiple transactions

#### Verification

```bash
# swap_exact_in has the check:
grep -n "end_total_sol_value < start_total_sol_value" programs/s-controller/src/processor/swap_exact_in.rs
# Output: 130

# add_liquidity has the check:
grep -n "end_total_sol_value < start_total_sol_value" programs/s-controller/src/processor/add_liquidity.rs
# Output: 126

# remove_liquidity does NOT:
grep -n "end_total_sol_value" programs/s-controller/src/processor/remove_liquidity.rs
# Output: (empty - no check exists)
```

#### Fix

Add the same invariant check after the final `sync_sol_value_unchecked`:

```rust
sync_sol_value_unchecked(sync_sol_value_accounts, lst_cpi, lst_index)?;

let end_total_sol_value = accounts.pool_state.total_sol_value()?;
if end_total_sol_value < pool_total_sol_value {
    return Err(SControllerError::PoolWouldLoseSolValue.into());
}
```

---

### [SC-F02] Protocol Fees Can Be Set to 100% (10,000 BPS)

**Severity:** MEDIUM  
**File:** `programs/s-controller/src/processor/set_protocol_fee.rs:69`

#### Description

The fee validation uses strict greater-than:

```rust
if fee_bps > BPS_DENOMINATOR {
    return Err(SControllerError::FeeTooHigh.into());
}
```

This allows `fee_bps == 10000` (100%), meaning a compromised admin could set protocol fees to extract ALL value from swaps and LP operations.

#### Impact

For a $1.1B TVL pool:
- Admin sets `trading_protocol_fee_bps = 10000`
- All swap fees go to protocol (0% to LPs)
- Admin sets `lp_protocol_fee_bps = 10000`
- All LP redemption value goes to protocol

#### Fix

Use `>=` to cap at 9999 BPS:

```rust
if fee_bps >= BPS_DENOMINATOR {
    return Err(SControllerError::FeeTooHigh.into());
}
```

---

### [SC-F03] Negative Fees (Rebates) Create Arbitrage Opportunities

**Severity:** MEDIUM  
**File:** `libs/pricing-programs/flat-fee-lib/src/fee_bound.rs:5`

#### Description

The flat fee pricing program uses signed `i16` for fees, allowing the range `[-10000, 10000]`. Negative fees represent rebates — the user receives MORE output than their input's SOL value.

When both input and output LSTs have negative fees, the combined effect produces output exceeding 200% of input value:
- Input fee: -100% → user pays 0 effective fee
- Output fee: -100% → user receives 2x the SOL value in output tokens

#### Impact

A malicious pricing program manager could set extreme negative fees for specific LST pairs, creating:
- Risk-free arbitrage loops (swap A→B→A at profit)
- Pool value drain over repeated transactions
- MEV extraction through fee manipulation

#### Fix

Cap signed fees to `[-5000, 5000]` (50% max rebate):

```rust
const MAX_SIGNED_FEE_BPS: i16 = 5_000;
```

---

## LOW Severity Findings

| ID | Title | Description |
|----|-------|-------------|
| SC-F04 | First depositor LP token minting | First deposit uses raw SOL value for LP token amount; tiny deposits could create unfavorable LP:SOL ratio. Mitigated by 9-decimal precision. |
| SC-F05 | Admin can set arbitrary sol_value_calculator | No allowlist for calculator programs. Compromised admin could set malicious calculator to manipulate SOL valuations. |
| SC-F06 | Admin can set arbitrary pricing programs | Similar to F05 for pricing programs. |
| SC-F07 | Conservative get_min() slightly undervalues LP | `invoke_sol_to_lst` uses `get_min()` which systematically undervalues LP token redemptions by dust amounts. |

## INFO Findings

| ID | Title | Description |
|----|-------|-------------|
| SC-F08 | Unsafe code in list deserialization | Uses `unsafe` for zero-copy deserialization — reviewed and sound. |
| SC-F09 | Single admin key centralization | One key controls all admin functions for $1.1B TVL — no multisig required. |
| SC-F10 | No timelock on admin operations | Fee changes, calculator swaps, admin transfers all instant — no delay for users to exit. |
| SC-F11 | set_admin missing pool state checks | Admin transfer doesn't verify pool is not rebalancing. |

---

## Positive Findings

- **NOT vulnerable to pool share inflation attack** — 9-decimal LP token precision with 1:1 LP:SOL rate
- **All arithmetic uses `checked_*` operations** — no raw `as` casts in production program code
- **Rebalance atomicity enforced** via instructions sysvar inspection
- **Swap same LST explicitly prevented**
- **Strong solores-generated account verification**

---

## Methodology

1. Manual code review of all program files
2. Pattern scanning with ripgrep for unsafe patterns
3. Cross-referencing with Zealynx 45-point Solana security checklist
4. Comparison with prior audit reports (Neodyme, Ottersec, Sec3)

---

**Full multi-protocol audit report:** [github.com/0xksure/solana-audit-report](https://github.com/0xksure/solana-audit-report)
