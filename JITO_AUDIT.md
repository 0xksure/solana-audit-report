# Jito Stakenet Security Audit Report

**Date:** February 13, 2026  
**Auditor:** Subagent (Automated + Manual Review)  
**Target:** Jito Stakenet — `steward` and `validator-history` programs  
**Repository:** https://github.com/jito-foundation/stakenet  
**TVL:** $1.07B  
**Existing Audits:** `jito_steward_audit.pdf`, `jito_validator_history_audit.pdf` in `security-audits/`  
**Lines of Rust:** ~14,500 across both programs

---

## Executive Summary

The Jito Stakenet codebase is **well-engineered** with strong defensive patterns: checked arithmetic throughout, proper authority/signer checks on admin instructions, PDA-based account validation, and a clear state machine design. The scoring system uses a hierarchical bit-packing approach that is elegant and resistant to manipulation. However, several findings of varying severity were identified, primarily around floating-point arithmetic, oracle trust assumptions, edge cases in the state machine, and permissionless instruction abuse potential.

**Overall Assessment: MODERATE RISK** — No critical exploits found, but several medium/low issues warrant attention given the $1.07B TVL.

---

## Architecture Overview

### Steward Program
- **State Machine:** `RebalanceDirected → Idle → ComputeScores → ComputeDelegations → Idle → ComputeInstantUnstake → Rebalance → Idle`
- **Scoring:** 4-tier hierarchical score packed into u64: inflation commission (8 bits) > MEV commission (14 bits) > validator age (17 bits) > vote credits (25 bits). Binary filters (blacklist, delinquency, superminority, running Jito, etc.) multiply the raw score by 0 or 1.
- **Delegation:** Top N validators by score get equal share (1/N).
- **Rebalancing:** Per-epoch unstake caps (scoring, instant, stake deposit) limit movement.
- **Authorities:** admin, blacklist_authority, parameters_authority, priority_fee_parameters_authority, directed_stake_whitelist_authority, directed_stake_meta_upload_authority, directed_stake_ticket_override_authority — all set by admin.

### Validator History Program
- **Data Sources:** On-chain vote accounts (permissionless copy), oracle_authority (stake history, priority fees), gossip contact info (permissionless with sysvar proof).
- **Storage:** Circular buffer of `ValidatorHistoryEntry` per validator, `ClusterHistory` for global data.

---

## Findings

### Finding 1: Floating-Point Arithmetic in Consensus-Critical Scoring

**Severity:** MEDIUM  
**Files:**
- `programs/steward/src/score.rs:329` — `calculate_epoch_credits()`
- `programs/steward/src/score.rs:368` — `(vote_credits_ratio * VOTE_CREDITS_RATIO_MAX as f64) as u64`
- `programs/steward/src/state/steward_state.rs:885` — `.round() as u64`

**Description:** The scoring system uses `f64` floating-point arithmetic for calculating vote credits ratios, delinquency thresholds, and epoch progress. Floating-point operations are non-deterministic across different CPU architectures (x86 vs ARM) and can produce slightly different results. While Solana validators currently all run on x86_64, this is a latent risk.

**Exploit Scenario:** If Solana ever supports heterogeneous validator hardware, different validators could compute different scores for the same input, leading to consensus failures or exploitable divergence in score ordering.

**Evidence:**
```rust
// score.rs:329
let average_vote_credits = epoch_credits_window.iter().filter_map(|&i| i).sum::<u32>() as f64
    / epoch_credits_window.len() as f64;

// score.rs:368
let scaled_ratio = (vote_credits_ratio * VOTE_CREDITS_RATIO_MAX as f64) as u64;
```

**Recommended Fix:** Replace f64 arithmetic with fixed-point integer math using basis points or scaled integers. For example, use `u128` with a fixed scaling factor.

---

### Finding 2: Oracle Authority Has Unilateral Power Over Validator Scores

**Severity:** MEDIUM  
**Files:**
- `programs/validator-history/src/instructions/update_stake_history.rs:35-42`

**Description:** The `oracle_authority` in the validator-history program can set arbitrary `lamports`, `rank`, and `is_superminority` values for any validator at any past epoch. This data directly feeds into the steward's scoring (superminority check → binary filter, stake history validation). A compromised oracle can:
1. Mark any validator as superminority → score = 0 → instant unstake
2. Backfill false data for past epochs
3. Manipulate rank data

**Exploit Scenario:** If the oracle authority key is compromised, an attacker could mark all legitimate validators as superminority, zeroing their scores, and route all delegation to a colluding set of validators.

**Evidence:**
```rust
pub fn handle_update_stake_history(
    ctx: Context<UpdateStakeHistory>,
    epoch: u64,
    lamports: u64,
    rank: u32,
    is_superminority: bool,
) -> Result<()> {
    // Only check: epoch <= current epoch, and oracle_authority signer
    // No validation on lamports/rank/is_superminority values
```

**Recommended Fix:** 
- Add sanity bounds on `lamports` and `rank` values
- Consider a time-delay or multi-sig for oracle authority changes
- Add on-chain verification against the actual stake distribution sysvar where possible

---

### Finding 3: Permissionless `compute_score` Can Reset State Mid-Cycle

**Severity:** MEDIUM  
**Files:**
- `programs/steward/src/state/steward_state.rs:712-725`

**Description:** In `compute_score()`, if `progress.is_empty()` OR `current_epoch > self.current_epoch` OR `slots_since_scoring_started > compute_score_slot_range`, the entire cycle state is reset via `reset_state_for_new_cycle()`. Since `compute_score` is permissionless (no signer check beyond state machine checks), a cranker could potentially time calls to force resets.

The specific concern: if `compute_score_slot_range` is set too low, a legitimate cranking delay could trigger an unintended reset, losing partial scoring progress for all previously scored validators.

**Exploit Scenario:** A malicious cranker delays calling `compute_score` for any validator until `compute_score_slot_range` slots have passed, then calls it for their preferred validator first. All previous scores are wiped, and the attacker's validator gets scored in a fresh cycle where it can be first. However, since delegation is equal share (1/N of top validators), this doesn't directly benefit them unless combined with other manipulation.

**Evidence:**
```rust
if self.progress.is_empty()
    || current_epoch > self.current_epoch
    || slots_since_scoring_started > config.parameters.compute_score_slot_range
{
    self.reset_state_for_new_cycle(...)?;
```

**Recommended Fix:** This is by design for liveness, but consider adding an event/log when a forced reset occurs for monitoring purposes.

---

### Finding 4: `get_unsafe` Used in Financial Calculations

**Severity:** LOW  
**Files:**
- `programs/steward/src/delegation.rs:57` — `state.instant_unstake.get_unsafe(temp_index)`
- `programs/steward/src/delegation.rs:212` — `state.instant_unstake.get_unsafe(index)`

**Description:** `get_unsafe` in the BitMask implementation bypasses bounds checking. While the calling code should ensure `temp_index < num_pool_validators`, if there's ever a mismatch between `num_pool_validators` and actual data, this could read stale/garbage data from the bitmask.

**Evidence:**
```rust
// bitmask.rs
/// Unsafe version of get, which does not check if the index is out of bounds.
pub fn get_unsafe(&self, index: usize) -> bool { ... }

// delegation.rs:57
let temp_target_lamports = if state.instant_unstake.get_unsafe(temp_index) {
    0 // This validator would get all stake removed
```

**Exploit Scenario:** If `sorted_raw_score_indices` contains a stale index > `num_pool_validators` (e.g., after a validator removal race condition), `get_unsafe` could read a set bit from a previous state and incorrectly mark a validator for instant unstake, causing unauthorized stake removal.

**Recommended Fix:** Replace `get_unsafe` with `get` (bounds-checked version) in financial calculations, even at minor compute cost.

---

### Finding 5: Equal Delegation Among Top N Creates MEV Incentive to Game N

**Severity:** LOW  
**Files:**
- `programs/steward/src/state/steward_state.rs:810-825`

**Description:** The delegation strategy assigns equal shares (1/N) to the top `num_delegation_validators`. This means a validator's delegation is the same whether they rank #1 or #N. The binary filters (score × 0 or 1) mean validators with very different quality levels get identical delegation if they all pass filters.

**Exploit Scenario:** A validator operator could run multiple validators that barely pass all binary filters. Each one gets 1/N share, so running 10 mediocre validators gets 10x the stake of running 1 excellent validator. The `minimum_stake_lamports` and `minimum_voting_epochs` checks in `auto_add_validator` mitigate this somewhat, but the economic incentive exists.

**Evidence:**
```rust
for index in validators_to_delegate {
    self.delegations[index as usize] = Delegation {
        numerator: 1,
        denominator: num_delegation_validators as u32,
    };
}
```

**Recommended Fix:** Consider proportional delegation based on the 4-tier score rather than equal shares, or implement a cap on validators per operator identity.

---

### Finding 6: `unwrap()` in Production Code Paths

**Severity:** LOW  
**Files:**
- `programs/steward/src/score.rs:788` — `.fold(0, |agg, val| agg.checked_add(u64::from(val)).unwrap())`
- `programs/steward/src/utils.rs:208,210` — `pod_from_bytes::<PodU64>(slice).unwrap()`
- `programs/validator-history/src/utils.rs:14` — `.try_into().unwrap()`
- `programs/validator-history/src/instructions/copy_cluster_info.rs:34` — `bincode::deserialize(...).unwrap()`

**Description:** Several `unwrap()` calls exist in production code paths. If triggered, these would cause a transaction-level panic, which in Solana results in the transaction failing but not the program crashing. However, a carefully crafted input could DoS specific operations.

**Evidence:**
```rust
// score.rs:788 - could panic if u64 addition overflows
let total_commission: u64 = realized_commissions
    .into_iter()
    .fold(0, |agg, val| agg.checked_add(u64::from(val)).unwrap());
```

**Exploit Scenario:** If a validator has enough epochs of MAX commission (10000 bps each), the sum could theoretically overflow u64, though this would require ~1.8×10^15 epochs, making it practically impossible. The `bincode::deserialize` unwrap on SlotHistory is more concerning — a malformed sysvar could panic the instruction.

**Recommended Fix:** Replace `unwrap()` with `ok_or(StewardError::ArithmeticError)?` throughout.

---

### Finding 7: Validator History Copy Instructions are Permissionless

**Severity:** INFO  
**Files:**
- `programs/validator-history/src/instructions/copy_vote_account.rs:22-24` — `pub signer: Signer<'info>`
- `programs/validator-history/src/instructions/copy_gossip_contact_info.rs:53` — `pub signer: Signer<'info>`

**Description:** The `CopyVoteAccount` and `CopyGossipContactInfo` instructions require a signer but don't enforce any specific identity — anyone can call them. This is intentional (permissionless cranking), but it means the history data is updated at the pace of the most active cranker.

**Exploit Scenario:** A malicious actor could selectively NOT crank certain validators' data, causing them to appear delinquent or have stale data. However, since any other party can also crank, this is a weak griefing vector.

**Recommended Fix:** INFO-level — document that operational monitoring should ensure all validators are cranked regularly.

---

### Finding 8: Epoch u16 Overflow at Epoch 65535

**Severity:** INFO  
**Files:**
- `programs/validator-history/src/utils.rs:11-14`
- Throughout scoring/history code using `u16` epochs

**Description:** Epochs are stored as `u16` throughout the validator history, supporting up to epoch 65535. At ~2 days per epoch, this is ~358 years. The `cast_epoch` function uses modular arithmetic (`epoch % u16::MAX`) rather than failing, meaning epoch 65535 would wrap to 0.

**Evidence:**
```rust
pub fn cast_epoch(epoch: u64) -> Result<u16> {
    require!(epoch < (u16::MAX as u64), ...);
    let epoch_u16: u16 = (epoch % u16::MAX as u64).try_into().unwrap();
    Ok(epoch_u16)
}
```

**Recommended Fix:** INFO-level — not a practical concern for centuries. The `require!` check prevents wraparound.

---

### Finding 9: Admin Can Bypass All Protections via SPL Passthrough

**Severity:** INFO (Design Decision)  
**Files:**
- `programs/steward/src/instructions/spl_passthrough.rs`

**Description:** The admin has direct access to all SPL stake pool operations: `add_validator_to_pool`, `remove_validator_from_pool`, `increase_validator_stake`, `decrease_validator_stake`, `set_staker`, `set_preferred_validator`, etc. These bypass the scoring and delegation state machine entirely.

This is by design for operational flexibility but represents a centralization risk: the admin key can override all algorithmic decisions and directly move stake.

**Evidence:** All passthrough instructions check `address = get_config_admin(&config)?` on the admin signer.

**Recommended Fix:** INFO-level — consider timelock or multi-sig for admin operations, document admin powers clearly for stakers.

---

### Finding 10: Directed Stake Division by Zero Risk

**Severity:** LOW  
**Files:**
- `programs/steward/src/directed_delegation.rs:72` — `/ (total_excess_lamports as u128)`
- `programs/steward/src/directed_delegation.rs:162` — `/ (total_delta_lamports as u128)`

**Description:** In directed delegation calculations, division by `total_excess_lamports` and `total_delta_lamports` occurs. While there are early returns when these are 0, the division uses raw `/` operator on u128, not `checked_div`. If the early return logic has a bug, division by zero would panic.

**Evidence:**
```rust
let target_delta_proportion_bps: u128 =
    (target_delta_lamports as u128).saturating_mul(10_000) / (total_excess_lamports as u128);
```

**Recommended Fix:** Use `checked_div` with an explicit error return instead of raw `/`.

---

### Finding 11: Score Multiplication Overflow in Binary Filter Application

**Severity:** LOW  
**Files:**
- `programs/steward/src/score.rs:400-413`

**Description:** The final score is calculated by multiplying the raw_score (u64) by multiple binary filter values (each 0 or 1, cast to u64). Since each multiplier is 0 or 1, the result can only be 0 or `raw_score`, so overflow is impossible. However, the pattern is unusual and could become vulnerable if filters ever return values > 1.

**Evidence:**
```rust
let score = raw_score
    * mev_commission_score as u64
    * commission_score as u64
    * historical_commission_score as u64
    // ... 8 more multiplications
```

**Recommended Fix:** Consider using a boolean AND approach instead of multiplication for clarity and safety.

---

### Finding 12: `compute_score_slot_range` Interaction with Epoch Boundaries

**Severity:** LOW  
**Files:**
- `programs/steward/src/state/steward_state.rs:420-440`
- `programs/steward/src/state/parameters.rs`

**Description:** The `transition_idle` function uses `SLOTS_PER_EPOCH` (hardcoded 432,000) × `num_epochs_between_scoring` to determine when to start a new scoring cycle. This hardcoded value may not match actual epoch length on devnet/testnet or if Solana changes epoch length.

**Evidence:**
```rust
const SLOTS_PER_EPOCH: u64 = 432_000;
// ...
if slots_since_scoring_started >= (SLOTS_PER_EPOCH.saturating_mul(num_epochs_between_scoring)) {
```

**Recommended Fix:** Use `EpochSchedule::slots_per_epoch` instead of the hardcoded constant.

---

## Summary Table

| # | Severity | Title | File(s) |
|---|----------|-------|---------|
| 1 | MEDIUM | Floating-point in consensus-critical scoring | score.rs, steward_state.rs |
| 2 | MEDIUM | Oracle authority has unilateral power over scores | update_stake_history.rs |
| 3 | MEDIUM | Permissionless compute_score can reset state | steward_state.rs |
| 4 | LOW | `get_unsafe` in financial calculations | delegation.rs |
| 5 | LOW | Equal delegation creates Sybil incentive | steward_state.rs |
| 6 | LOW | `unwrap()` in production code paths | score.rs, utils.rs |
| 7 | INFO | Permissionless history copy instructions | copy_vote_account.rs |
| 8 | INFO | Epoch u16 overflow at epoch 65535 | utils.rs |
| 9 | INFO | Admin can bypass all protections | spl_passthrough.rs |
| 10 | LOW | Directed stake division by zero risk | directed_delegation.rs |
| 11 | LOW | Score multiplication pattern | score.rs |
| 12 | LOW | Hardcoded SLOTS_PER_EPOCH | steward_state.rs |

---

## Positive Observations

1. **Excellent checked arithmetic discipline** — Nearly all arithmetic uses `checked_add/sub/mul/div` with proper error propagation
2. **Strong Anchor account validation** — PDA seeds, owner checks, address constraints used correctly throughout
3. **Well-designed state machine** — Clear state transitions with flag-based progress tracking prevent double-processing
4. **Unstake caps** — Scoring, instant, and deposit unstake caps limit per-epoch movement, preventing catastrophic rebalancing
5. **Hierarchical scoring** — The 4-tier bit-packed scoring ensures commission is always prioritized over performance metrics
6. **Existing audit coverage** — Previous professional audits exist in the repository
7. **Transient stake detection** — Rebalance correctly skips validators with in-flight transient stake

---

## Methodology

1. **Repository cloning and structural analysis** of both programs
2. **Automated grep scanning** for: unsafe casts (`as u64/u128`), unwraps, unsafe blocks, missing account checks
3. **Manual review** of all core instruction handlers, scoring logic, delegation calculation, rebalancing, state transitions, and authority controls
4. **Staking-specific threat modeling** covering all 10 attack classes specified in the audit scope

---

*Report generated for Superteam bounty submission. Deadline: Feb 15, 2026.*
