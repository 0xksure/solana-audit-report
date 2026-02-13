# Raydium CLMM Deep Security Audit

**Protocol:** Raydium Concentrated Liquidity Market Maker (CLMM)
**TVL:** ~$965M
**Repository:** https://github.com/raydium-io/raydium-clmm
**Program ID (mainnet):** `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK`
**Audit Date:** 2026-02-13
**Auditor:** Deep manual review

---

## Executive Summary

The Raydium CLMM program is a well-structured Uniswap V3-style concentrated liquidity AMM on Solana, built with Anchor. The codebase shows maturity — overflow-checks are enabled in release profile, most arithmetic uses `checked_*` operations, and Anchor's account validation constraints are extensively used. Admin functions are gated by a hardcoded admin pubkey. The protocol has been previously audited by OtterSec.

After thorough review, I found several findings ranging from MEDIUM to INFO severity. No CRITICAL or HIGH findings were identified — the protocol's core logic is well-implemented.

---

## Architecture Overview

- **Single program:** `amm` (programs/amm/)
- **Key instructions:** create_pool, open_position (v1/v2/token22), increase/decrease_liquidity, swap (v1/v2), swap_router_base_in, initialize_reward, set_reward_params, collect_protocol_fee, collect_fund_fee
- **Math libraries:** tick_math, sqrt_price_math, liquidity_math, swap_math, full_math, big_num (U128, U256, U512, U1024)
- **Admin:** Hardcoded `admin::ID` pubkey, plus per-config `owner` and `fund_owner`
- **Overflow protection:** `overflow-checks = true` in both workspace and program Cargo.toml

---

## Findings

### FINDING-01: Fee Growth Checked_Sub Can Panic When Tick State Is Inconsistent

**Severity:** MEDIUM
**Files:** `programs/amm/src/states/tick_array.rs:408-411, 425-428, 461, 470`
**Also:** `programs/amm/src/states/tick_array.rs:350-363` (TickState::cross)

**Description:**
The `get_fee_growth_inside` and `get_reward_growths_inside` functions use `checked_sub().unwrap()` when calculating fee/reward growth below and above for ticks that are on the "other side" of the current tick. In contrast, the final inside calculation correctly uses `wrapping_sub`. However, the intermediate `checked_sub().unwrap()` on `fee_growth_global - fee_growth_outside` will **panic** if `fee_growth_outside` ever exceeds `fee_growth_global`.

In Uniswap V3, the Solidity implementation uses unchecked (wrapping) subtraction throughout because the fee growth values are designed to wrap around. This is mathematically correct — what matters is the *delta* between snapshots, not absolute values.

If the fee_growth_global_x64 value wraps around (which is mathematically possible after very long periods with very low liquidity), these checked_sub operations would cause the program to panic, effectively **bricking any position that spans such ticks** — users would be unable to decrease liquidity or collect fees.

**Exploit Scenario:**
1. A pool with extremely low liquidity (e.g., 1 wei) accumulates very high fee_growth_global values over time
2. After a tick crossing, `fee_growth_outside` could be set to a value that later exceeds `fee_growth_global` after wrapping
3. Any user trying to modify a position spanning that tick would get an irrecoverable panic
4. Funds would be locked (though admin could freeze/unfreeze pool)

**Likelihood:** Low (requires extreme conditions), but **impact is fund locking**.

**Recommended Fix:** Replace `checked_sub().unwrap()` with `wrapping_sub()` in the intermediate calculations within `get_fee_growth_inside`, `get_reward_growths_inside`, and `TickState::cross`, consistent with how the final "inside" calculation already works.

---

### FINDING-02: Reward Growth Checked_Sub in get_reward_growths_inside Can Also Panic

**Severity:** MEDIUM  
**Files:** `programs/amm/src/states/tick_array.rs:461, 470`

**Description:**
Same issue as FINDING-01 but for reward growth calculations. The `checked_sub().unwrap()` on `reward_growth_global_x64 - reward_growths_outside_x64[i]` can panic if the outside value exceeds global due to wrapping arithmetic. This would prevent position modifications for affected positions.

**Recommended Fix:** Use `wrapping_sub()` consistently.

---

### FINDING-03: `to_underflow_u64` Silently Returns 0 for Large Values, Causing Reward/Fee Loss

**Severity:** MEDIUM  
**Files:** `programs/amm/src/libraries/full_math.rs:177, 209`
**Used in:** `personal_position.rs:180`, `increase_liquidity.rs:212`

**Description:**
The `to_underflow_u64()` function on U128 and U256 returns `0` when the value exceeds `u64::MAX`:

```rust
fn to_underflow_u64(self) -> u64 {
    if self < U128::from(u64::MAX) {
        self.as_u64()
    } else {
        0  // Silent loss!
    }
}
```

This is used in fee calculation (`calculate_latest_token_fees`) and reward calculation (`update_rewards`). If a position has accumulated enough fees/rewards that the delta calculation overflows u64, the **entire accumulated amount is silently set to 0**, losing all uncollected fees/rewards for that position.

The comment in `update_rewards` even acknowledges this: *"If reward delta overflows, default to a zero value. This means the position loses all rewards earned since the last time the position was modified or rewards were collected."*

While this is "by design," it means users with large positions or positions that haven't collected rewards for a long time can lose significant value.

**Exploit Scenario:**
1. A whale provides massive liquidity in a very narrow tick range
2. High trading volume generates enormous fee_growth_inside delta
3. When the whale tries to collect, `fee_growth_delta * liquidity / Q64` exceeds u64::MAX
4. `to_underflow_u64` returns 0, and the whale gets **no fees at all**
5. These fees remain in the pool — effectively redistributed or lost

**Impact:** Loss of accumulated fees/rewards for large positions. In a $965M TVL protocol, this could mean substantial value.

**Recommended Fix:** Either:
1. Cap at `u64::MAX` instead of returning 0 (return `u64::MAX` when overflow)
2. Use `saturating` math to give the user at least the maximum possible amount
3. Add explicit documentation warning users to collect frequently

---

### FINDING-04: Pool State Can Be Frozen by Anyone via Vault Drain Race

**Severity:** MEDIUM  
**Files:** `programs/amm/src/instructions/swap.rs:516-518, 531-533`

**Description:**
In `exact_internal`, after computing swap amounts, the code checks:
```rust
if vault_1.amount <= amount_1 {
    // freeze pool, disable all instructions
    ctx.pool_state.load_mut()?.set_status(255);
}
```

This freezes the pool (status=255, all operations disabled) when the output vault doesn't have enough tokens. While this is a safety mechanism, the check uses the **stale** `vault_1.amount` read before the transfer. The vault balance was loaded at account deserialization time.

However, this is mostly a safety net — if the swap math is correct, the vault should always have enough. The concern is that in Token-2022 with transfer fees, the actual transferable amount might differ from `amount_1`, but the v1 swap doesn't handle Token-2022. In swap_v2, transfer fees are accounted for.

**Impact:** Limited — the admin can unfreeze pools. But a griefing vector could exist with Token-2022 tokens in certain edge cases.

---

### FINDING-05: `assert!` Used Instead of `require!` in Admin Functions — Causes Uninformative Panics

**Severity:** LOW  
**Files:** `programs/amm/src/lib.rs:56-59`, `programs/amm/src/instructions/admin/update_amm_config.rs:43-53`

**Description:**
Several validation checks use `assert!()` instead of `require!()` or `err!()`. In Solana, `assert!` causes a runtime panic with no error code, making debugging difficult and returning a generic "Program failed" error to users. Examples:

```rust
// lib.rs:56-59
assert!(trade_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);

// update_amm_config.rs
assert!(protocol_fee_rate <= FEE_RATE_DENOMINATOR_VALUE);
assert!(trade_fee_rate < FEE_RATE_DENOMINATOR_VALUE);
```

Also: `assert!(liquidity != 0)` in `increase_liquidity` handler (lib.rs).

**Impact:** Poor UX, no descriptive error codes. Admin-only functions reduce risk but the `increase_liquidity` assert affects all users.

**Recommended Fix:** Replace `assert!()` with `require!()` and appropriate error codes.

---

### FINDING-06: Missing Vault Owner Validation in Swap (v1)

**Severity:** LOW  
**Files:** `programs/amm/src/instructions/swap.rs:16-48`

**Description:**
The `SwapSingle` account struct validates that `amm_config` matches the pool and `tick_array.pool_id == pool_state.key()`, and `observation_state` matches the pool. However, the `input_vault` and `output_vault` accounts only have `#[account(mut)]` constraint — they lack explicit validation that they are the pool's actual vaults.

The validation happens **inside** `exact_internal` at runtime:
```rust
require!(
    if zero_for_one {
        ctx.input_vault.key() == pool_state.token_vault_0
            && ctx.output_vault.key() == pool_state.token_vault_1
    } else { ... }
);
```

This is functionally correct but moves validation to runtime rather than using Anchor's constraint system. The `SwapSingleV2` struct has the same pattern.

**Impact:** No direct exploit, but defense-in-depth is reduced. Anchor constraints fail earlier and with better error messages.

---

### FINDING-07: Unconstrained `pool_state` in Several Account Structs

**Severity:** LOW  
**Files:** `programs/amm/src/instructions/decrease_liquidity.rs`, `decrease_liquidity_v2.rs`

**Description:**
The `pool_state` field in `DecreaseLiquidity` and `DecreaseLiquidityV2` structs only has `#[account(mut)]` without explicit pool PDA seeds verification. The link between pool_state and the position is only through `personal_position.pool_id == pool_state.key()`. If a user passes a valid personal_position with a matching pool_id, the pool_state is implicitly validated.

However, since pool_state is an `AccountLoader<PoolState>` with Anchor's discriminator check, and the personal_position constraint ties it to the correct pool, this is safe in practice.

---

### FINDING-08: `set_reward_params` Authority Check Allows Operation Account Owners to Set Any Reward Params

**Severity:** LOW  
**Files:** `programs/amm/src/instructions/set_reward_params.rs:50-57`

**Description:**
The `set_reward_params` function has a two-tier authorization:
1. **Admin operators** (operation_owners or hardcoded admin): Can call `admin_update` with fewer restrictions
2. **Reward authority**: Can call `normal_update` with more restrictions

Admin operators bypass period limits and can set emissions at any time. While operation_owners are presumably trusted, adding them via `update_operation_account` only requires the hardcoded admin. If an operation_owner key is compromised, they could manipulate reward emissions across all pools without the normal restrictions.

**Impact:** Increased blast radius if an operation_owner key is compromised.

---

### FINDING-09: `create_pool` Allows Anyone to Create Pools — Potential Spam/Confusion

**Severity:** INFO  
**Files:** `programs/amm/src/instructions/create_pool.rs:11`

**Description:**
Pool creation is permissionless (`pool_creator: Signer<'info>` with no additional constraints). While this is by design for DeFi composability, it means anyone can create pools with arbitrary token pairs and initial prices. This could be used for:
- Creating fake/misleading pools to confuse UI users
- Front-running legitimate pool creation with unfavorable parameters

The pool is a PDA seeded by `[POOL_SEED, amm_config, token_mint_0, token_mint_1]`, so only one pool per config+pair can exist, limiting spam.

---

### FINDING-10: Oracle Observation Provides Limited Manipulation Resistance

**Severity:** INFO  
**Files:** `programs/amm/src/states/oracle.rs`

**Description:**
The TWAP oracle stores tick observations but only updates on swaps (not on every block). This means:
- The oracle can be manipulated within a single transaction if there's low liquidity
- The oracle is only as fresh as the last swap
- Multi-block manipulation is possible in low-activity pools

This is consistent with Uniswap V3's design and is a known limitation, but downstream protocols relying on this oracle should be aware.

---

### FINDING-11: Fee Growth Global Accumulator Can Theoretically Overflow

**Severity:** INFO  
**Files:** `programs/amm/src/instructions/swap.rs:268-272`

**Description:**
```rust
state.fee_growth_global_x64 = state
    .fee_growth_global_x64
    .checked_add(fee_growth_global_x64_delta)
    .unwrap();
```

The fee_growth_global_x64 (u128) uses `checked_add`. If this ever overflows, the swap will panic. In practice, overflow of a u128 fee growth accumulator is essentially impossible under normal conditions, but the use of `checked_add` means it would brick the pool rather than wrapping. The Uniswap V3 design relies on wrapping arithmetic for fee growth accumulators.

**Impact:** Theoretical — practically impossible to reach u128 overflow for fees.

---

### FINDING-12: Reward `reward_total_emissioned` Can Overflow

**Severity:** INFO  
**Files:** `programs/amm/src/states/pool.rs:378-386`

**Description:**
```rust
reward_info.reward_total_emissioned = reward_info
    .reward_total_emissioned
    .checked_add(...)
    .unwrap();
```

The `reward_total_emissioned` (u64) accumulates total emissions. With high emission rates over long periods, this could overflow, causing the `update_reward_infos` function to panic, which would block ALL pool operations (swaps, position changes, etc.) since `update_reward_infos` is called from `swap_internal` and `modify_position`.

**Likelihood:** Low for well-configured rewards, but a malicious/careless reward authority setting very high `emissions_per_second_x64` could trigger this faster.

---

## Positive Security Observations

1. **Overflow checks enabled** in release profile — catches most arithmetic bugs
2. **Anchor constraints** are well-used for account validation
3. **Admin is hardcoded** — not upgradeable within the program (though program itself may be upgradeable)
4. **PDA-derived vaults** — pool vaults are derived from seeds, not arbitrary accounts
5. **Slippage protection** — both swap and liquidity operations have min/max amount checks
6. **Pool freezing safety net** — automatic freeze when vault balance is insufficient
7. **Fee/reward accounting** tracks claimed vs total to prevent over-withdrawal
8. **`check_unclaimed_fees_and_vault`** provides additional safety by disabling fee collection if accounting is inconsistent
9. **Token-2022 support** properly accounts for transfer fees in v2 instructions

---

## Summary Table

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
| F-09 | INFO | Permissionless pool creation |
| F-10 | INFO | Limited oracle manipulation resistance |
| F-11 | INFO | Fee growth accumulator overflow (theoretical) |
| F-12 | INFO | reward_total_emissioned overflow risk |

---

## Recommendations

1. **Replace `checked_sub` with `wrapping_sub`** in fee/reward growth intermediate calculations (F-01, F-02) — this aligns with Uniswap V3's design intention
2. **Change `to_underflow_u64` to return `u64::MAX` instead of 0** (F-03) — or at minimum, emit a warning event
3. **Replace all `assert!` with `require!`** with proper error codes (F-05)
4. **Add Anchor constraints** for vault validation in swap structs (F-06)
5. **Document oracle limitations** for downstream integrators (F-10)
6. **Consider `wrapping_add` for fee_growth_global_x64** to prevent theoretical bricking (F-11)
