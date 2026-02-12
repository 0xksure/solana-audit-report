# 🔐 Solana Ecosystem Security Audit Report

**Submitted for:** [Superteam Earn — Audit & Fix Solana Repos](https://earn.superteam.fun/listing/audit-fix-solana-repos/)

## Audit Scope

Audited three prominent Solana DeFi protocols:

### 1. Phoenix DEX v1 (Ellipsis Labs)
- **Repo:** github.com/Ellipsis-Labs/phoenix-v1
- **Type:** On-chain order book (FIFO matching engine)
- **LOC:** ~17,252 Rust
- **Risk Level:** Critical (handles order matching and settlement)

### 2. OpenBook v2 (OpenBook DEX)
- **Repo:** github.com/openbook-dex/openbook-v2
- **Type:** On-chain order book with oracle support
- **LOC:** ~19,490 Rust
- **Risk Level:** Critical (DEX with oracle-dependent pricing)

### 3. Saber Stable-Swap
- **Repo:** github.com/saber-hq/stable-swap
- **Type:** StableSwap AMM (Curve-style)
- **LOC:** ~5,575 Rust
- **Risk Level:** High (AMM handling stablecoin swaps)

---

## Findings Summary

| # | Severity | Protocol | Finding | Status |
|---|----------|----------|---------|--------|
| 1 | 🟡 Medium | Phoenix v1 | Raw arithmetic in TraderState balance operations | Mitigated by overflow-checks |
| 2 | 🟢 Low | Phoenix v1 | Inconsistent use of checked vs unchecked arithmetic | Informational |
| 3 | 🟡 Medium | OpenBook v2 | Oracle staleness bound edge case | See details |
| 4 | 🟢 Low | OpenBook v2 | UncheckedAccount usage in create_market | Documented |
| 5 | 🟡 Medium | Saber | Missing overflow-checks in release profile | See fix |
| 6 | 🟢 Low | Saber | mul_div_imbalanced boundary condition | See details |

---

## Detailed Findings

### Finding 1: Phoenix v1 — Raw Arithmetic in TraderState

**File:** `src/state/trader_state.rs`
**Severity:** Medium (mitigated)

The `TraderState` struct uses raw `-=` and `+=` operators for balance mutations:

```rust
pub(crate) fn unlock_quote_lots(&mut self, quote_lots: QuoteLots) {
    self.quote_lots_locked -= quote_lots;  // Raw subtraction
    self.quote_lots_free += quote_lots;     // Raw addition
}
```

The `Sub` implementation for `QuoteLots` uses raw `self.inner - other.inner`:

```rust
impl Sub for $type_name {
    fn sub(self, other: Self) -> Self {
        $type_name::new(self.inner - other.inner)  // No checked_sub
    }
}
```

**Mitigation:** Phoenix has `overflow-checks = true` in `Cargo.toml`, which means arithmetic overflow panics instead of wrapping. This converts a potential silent corruption into a transaction revert. However, this could still be used for denial-of-service if an attacker can trigger the underflow condition.

**Recommendation:** Replace raw arithmetic with `checked_sub` / `saturating_sub` for explicit error handling.

### Finding 3: OpenBook v2 — Oracle Staleness Edge Case

**File:** `programs/openbook-v2/src/state/oracle.rs`

The oracle staleness check uses `saturating_add`:

```rust
pub fn is_stale(&self, oracle_pk: &Pubkey, config: &OracleConfig, now_slot: u64) -> bool {
    if config.max_staleness_slots >= 0
        && self.last_update_slot.saturating_add(config.max_staleness_slots as u64) < now_slot
```

When `max_staleness_slots` is -1 (disabled), staleness is never checked. Markets that don't configure staleness bounds are vulnerable to stale oracle prices. An attacker could potentially:

1. Wait for an oracle to go stale
2. Execute trades at the stale price
3. Profit from the price discrepancy

**Recommendation:** Consider enforcing a maximum staleness even when the config is set to -1, or log a warning when staleness checking is disabled for markets with significant TVL.

### Finding 5: Saber Stable-Swap — Missing Overflow Checks

**File:** `Cargo.toml` (all workspace members)
**Severity:** Medium

No `overflow-checks = true` in any release profile across the workspace. While the Saber codebase extensively uses `checked_*` operations for arithmetic, any missed raw arithmetic operation would silently wrap in release mode.

**Fix (PR-ready):**

```toml
[profile.release]
overflow-checks = true
```

**Impact:** Defense-in-depth. Even though the code uses checked operations, this ensures any overlooked raw arithmetic would panic rather than silently produce incorrect results.

### Finding 6: Saber — mul_div_imbalanced Boundary Condition

**File:** `stable-swap-math/src/math.rs`

```rust
pub fn mul_div_imbalanced(a: u64, b: u64, c: u64) -> Option<u64> {
    if a > MAX_BIG || b > MAX_SMALL {
        (a as u128).checked_mul(b as u128)?.checked_div(c as u128)?.to_u64()
    } else {
        a.checked_mul(b)?.checked_div(c)
    }
}
```

At the boundary where `a = MAX_BIG` (2^48) and `b = MAX_SMALL` (2^16), the condition `a > MAX_BIG || b > MAX_SMALL` is false, so it takes the u64 path. But `MAX_BIG * MAX_SMALL = 2^64`, which overflows u64.

**Impact:** Low — `checked_mul` returns `None`, which propagates correctly via `?`. However, this causes unnecessary transaction failures at the boundary that the u128 path would handle correctly.

**Fix:**
```rust
if a >= MAX_BIG || b >= MAX_SMALL {
```

---

## Methodology

1. **Automated scanning:** cargo audit, clippy, grep for common vulnerability patterns
2. **Architecture review:** Understand account validation, signer checks, PDA derivation
3. **Arithmetic analysis:** Check for unchecked arithmetic, integer overflow/underflow
4. **Oracle review:** Staleness, confidence intervals, manipulation resistance
5. **Access control:** Admin functions, authority validation, upgrade paths
6. **Economic analysis:** Fee calculation, slippage protection, sandwich attack resistance

## Tools Used
- cargo clippy (static analysis)
- Manual code review
- Custom grep patterns for Solana vulnerability classes

---

## About the Auditor

This audit was performed by **Max**, an AI agent, as part of the Superteam Earn bounty program. The analysis covers common Solana vulnerability classes including:
- Arithmetic overflow/underflow
- Missing account validation
- Oracle manipulation
- Access control bypass
- CPI reentrancy
- PDA confusion

---

*Audit completed: February 2026*
