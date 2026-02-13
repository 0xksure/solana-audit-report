# Futarchy / MetaDAO Security Audit Report

**Auditor:** Max (AI Co-Founder @ 0xksure)  
**Date:** February 13, 2026  
**Repository:** [metaDAOproject/futarchy](https://github.com/metaDAOproject/futarchy)  
**Programs:** futarchy, conditional_vault, mint_governor, launchpad variants, bid_wall  
**TVL:** ~$12M  
**Fix PR:** [0xksure/programs#fix/high-severity-security-fixes](https://github.com/0xksure/programs/tree/fix/high-severity-security-fixes)

---

## Executive Summary

Independent security audit of the MetaDAO Futarchy program — a prediction market-based DAO governance system on Solana. The audit identified **2 HIGH, 5 MEDIUM, 7 LOW, and 6 INFO** findings across 5 Anchor programs.

The two HIGH severity findings are:
1. **Admin functions bypass in non-production mode** — any signer can execute admin operations if `production` feature flag is missing
2. **admin_cancel_proposal drops pass pool reserves** — permanent fund loss when proposals are cancelled

---

## HIGH Severity Findings

### [FT-F02] Admin Functions Bypass in Non-Production Mode

**Severity:** HIGH  
**Impact:** Unauthorized access to all admin functions  
**Files:**
- `programs/futarchy/src/instructions/admin_remove_proposal.rs:21`
- `programs/futarchy/src/instructions/admin_cancel_proposal.rs:73`
- `programs/futarchy/src/instructions/admin_approve_execute_multisig_proposal.rs:56`
- `programs/futarchy/src/instructions/collect_fees.rs:35`

#### Description

All four admin functions in the futarchy program gate their admin key verification behind a compile-time feature flag:

```rust
#[cfg(feature = "production")]
require_keys_eq!(self.admin.key(), admin::ID, FutarchyError::InvalidAdmin);
```

This means the admin check is **completely absent** in any build that does not include the `production` feature. This includes:
- Local development builds
- Testnet/devnet deployments
- Any mainnet deployment where `production` is accidentally omitted from `Cargo.toml` features

#### Exploitation

Without the admin check, **any wallet** can:
1. Call `admin_remove_proposal` to delete proposals in draft state
2. Call `admin_cancel_proposal` to forcibly fail active proposals (causing pass token holders to lose everything)
3. Call `admin_approve_execute_multisig_proposal` to approve and execute arbitrary multisig transactions
4. Call `collect_fees` to steal all accumulated protocol fees

#### Proof of Concept

```bash
# Verify the cfg gate exists in source:
$ grep -n "cfg.*production" programs/futarchy/src/instructions/admin_*.rs programs/futarchy/src/instructions/collect_fees.rs

admin_cancel_proposal.rs:73:  #[cfg(feature = "production")]
admin_remove_proposal.rs:21:  #[cfg(feature = "production")]
admin_approve_execute_multisig_proposal.rs:56:  #[cfg(feature = "production")]
collect_fees.rs:35:  #[cfg(feature = "production")]

# Without "production" feature, the require_keys_eq! macro is not compiled in.
# Any Signer account passes validation.
```

#### Fix

Remove the `#[cfg(feature = "production")]` attribute. Admin key verification must always run at runtime:

```rust
// Always verify admin key - never skip based on build configuration
require_keys_eq!(self.admin.key(), admin::ID, FutarchyError::InvalidAdmin);
```

---

### [FT-F09] admin_cancel_proposal Drops Pass Pool Reserves from Accounting

**Severity:** HIGH  
**Impact:** Permanent fund loss on proposal cancellation  
**File:** `programs/futarchy/src/instructions/admin_cancel_proposal.rs:122, 160-163`

#### Description

When an admin cancels an active proposal, the futarchy program resolves the prediction market in favor of "fail" and merges pool reserves back to the spot pool. However, the code uses Rust's `..` pattern to destructure the `PoolState::Futarchy` enum, which silently discards the `pass` pool:

```rust
// Line 122: pass pool is silently dropped by `..`
let PoolState::Futarchy { fail, mut spot, .. } = dao.amm.state.to_owned() else {
    unreachable!();
};

// Lines 160-163: Only fail pool merged back
spot.base_reserves += fail.base_reserves;
spot.quote_reserves += fail.quote_reserves;
spot.base_protocol_fee_balance += fail.base_protocol_fee_balance;
spot.quote_protocol_fee_balance += fail.quote_protocol_fee_balance;
```

The `pass` pool's `base_reserves`, `quote_reserves`, `base_protocol_fee_balance`, and `quote_protocol_fee_balance` are permanently lost from the AMM's accounting. The underlying tokens still exist in the vault accounts but are untracked, effectively stranded forever.

#### Exploitation

1. A contentious proposal attracts significant trading activity on the pass market
2. Pass pool accumulates substantial reserves (base + quote tokens + protocol fees)
3. Admin cancels the proposal (legitimate governance action, e.g., proposal found to be malicious)
4. Only fail pool reserves are returned to spot — pass pool reserves are permanently stranded
5. The AMM's tracked reserves are now less than actual vault balances
6. LP token holders' claims are backed by fewer tokens than expected

#### Impact Assessment

For a proposal where the pass market accumulated $500K in reserves:
- **Direct loss:** $500K in reserves permanently untracked
- **Indirect loss:** Protocol fees in pass pool also lost
- **Affected parties:** All LP token holders (diluted claims)

#### Fix

Capture the `pass` field from the destructure and merge both pools back to spot:

```rust
// Capture pass pool instead of discarding it
let PoolState::Futarchy { pass, fail, mut spot, .. } = dao.amm.state.to_owned() else {
    unreachable!();
};

// Merge fail pool
spot.base_reserves += fail.base_reserves;
spot.quote_reserves += fail.quote_reserves;
spot.base_protocol_fee_balance += fail.base_protocol_fee_balance;
spot.quote_protocol_fee_balance += fail.quote_protocol_fee_balance;

// Merge pass pool (NEW)
spot.base_reserves += pass.base_reserves;
spot.quote_reserves += pass.quote_reserves;
spot.base_protocol_fee_balance += pass.base_protocol_fee_balance;
spot.quote_protocol_fee_balance += pass.quote_protocol_fee_balance;
```

---

## MEDIUM Severity Findings

### [FT-F03] TWAP Oracle Manipulation via Observation Gap Weighting
- **File:** `futarchy_amm.rs:358-420`
- Observation gaps are weighted by `slot_difference`, allowing manipulation by timing transactions around gaps.
- **Fix:** Cap `slot_difference` to ~2 minutes of slots.

### [FT-F04] Arbitrage Functions Use unwrap() — Potential DoS
- **File:** `futarchy_amm.rs:630-830`
- Extensive `unwrap()` in arbitrage calculations can panic on extreme pool states.
- **Fix:** Return errors instead of panicking.

### [FT-F05] Arbitrage Profit i64 Cast Overflow
- **File:** `futarchy_amm.rs:656,694`
- Large arbitrage profits overflow i64 cast silently.
- **Fix:** Use checked casts with error handling.

### [FT-F08] TWAP Aggregator Wrapping Produces Incorrect TWAP
- **File:** `futarchy_amm.rs:403-406`
- `wrapping_add` on TWAP aggregator produces incorrect values on overflow.
- **Fix:** Use saturating arithmetic or wider accumulator.

### [FT-F10] Protocol Fees in Losing Pool Lost on Finalization
- **File:** `finalize_proposal.rs:158-177`
- Protocol fees accumulated in the losing conditional pool are not recovered.
- **Fix:** Extract protocol fees before finalizing.

---

## LOW Severity Findings

| ID | Title |
|----|-------|
| FT-F06 | LP fee is 0% — lowers manipulation cost |
| FT-F12 | Flash loan vector (mitigated by TWAP rate limiting) |
| FT-F13 | Position authority can be any key — permanent lock risk |
| FT-F16 | Negative team threshold lowers bar for team proposals |
| FT-F17 | update_dao can set unsafe parameters without validation |
| FT-F18 | Arbitrage grid search suboptimal, step_size=0 edge case |
| FT-F20 | Minimum proposal duration vs TWAP manipulation window |

## INFO Findings

| ID | Title |
|----|-------|
| FT-F01 | Unstaking from non-draft proposals (by design) |
| FT-F07 | Spot pool split rounding on launch |
| FT-F11 | No reentrancy guard on Squads CPI (mitigated by Squads checks) |
| FT-F15 | Stale balance check in conditional swap |
| FT-F19 | Redemption truncation (negligible for binary outcomes) |
| FT-F10n | Finalize_proposal losing pool accounting correct for conditional tokens |

---

## Methodology

1. **Architecture review** — program flow, PDA derivations, CPI patterns across 5 programs
2. **Automated scanning** — `ripgrep` for unsafe casts (`as u64/u128`), `unwrap()`, `unsafe`, missing signer/owner checks, `cfg` gates
3. **Manual review** — arithmetic safety, access control, oracle handling, token validation, state machine correctness
4. **Checklist-based** — Zealynx 45-point Solana security checklist, Helius security guide, Neodyme/Sec3 vulnerability taxonomies
5. **Deduplication** — Cross-referenced all existing PRs and issues to ensure findings are original

## Tools Used

- Manual code review (primary)
- `grep`/`ripgrep` for pattern scanning
- Cargo Clippy, `cargo audit` for dependency checks
- Cross-referencing security checklists and known vulnerability databases

---

**Full multi-protocol audit report:** [github.com/0xksure/solana-audit-report](https://github.com/0xksure/solana-audit-report)
