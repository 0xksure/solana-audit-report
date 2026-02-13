# Solana Protocol Audit Targets

**Generated:** 2026-02-13 | **Deadline:** 2026-02-15

## Summary

Researched top Solana DeFi protocols by TVL via DeFiLlama. Filtered for open-source Rust/Anchor programs on GitHub, excluding CEXs and protocols already covered by Superteam community auditors (e.g., AdeshAtole).

## Full Target List

| Protocol | TVL | Category | GitHub Repo | Open Source Programs? | Community Audited? | Priority |
|----------|-----|----------|-------------|----------------------|-------------------|----------|
| Kamino Lend | $1.63B | Lending | [Kamino-Finance/klend](https://github.com/Kamino-Finance/klend) ⭐159 | ✅ `klend` program | No AdeshAtole PRs; 2 audit PRs exist | 🔴 HIGH |
| Jito Stakenet | $1.07B | Liquid Staking | [jito-foundation/stakenet](https://github.com/jito-foundation/stakenet) ⭐87 | ✅ `steward`, `validator-history` | No AdeshAtole PRs; 1 audit PR | 🔴 HIGH |
| Sanctum (S Controller) | $931M | Liquid Staking | [igneous-labs/S](https://github.com/igneous-labs/S) ⭐47 | ✅ Rust programs | No community audit PRs found | 🔴 HIGH |
| Drift Protocol v2 | $328M | Derivatives | [drift-labs/protocol-v2](https://github.com/drift-labs/protocol-v2) ⭐377 | ✅ `drift` program | ⚠️ AdeshAtole has 1 PR | 🟡 MEDIUM |
| Raydium CLMM | $965M | DEX | [raydium-io/raydium-clmm](https://github.com/raydium-io/raydium-clmm) ⭐368 | ✅ `amm` program | ⚠️ AdeshAtole has 1 PR | 🟡 MEDIUM |
| Orca Whirlpools | $255M | DEX | [orca-so/whirlpools](https://github.com/orca-so/whirlpools) ⭐511 | ✅ `whirlpool` program | ⚠️ AdeshAtole has 1 PR | 🟡 MEDIUM |
| marginfi v2 | ~$200M | Lending | [mrgnlabs/marginfi-v2](https://github.com/mrgnlabs/marginfi-v2) ⭐284 | ✅ `marginfi` program | ⚠️ AdeshAtole has 1 PR | 🟡 MEDIUM |
| Marinade Finance | $245M | Liquid Staking | [marinade-finance/liquid-staking-program](https://github.com/marinade-finance/liquid-staking-program) ⭐119 | ✅ `marinade-finance` program | No AdeshAtole; but 5 audit PRs | 🟢 LOW |
| Sanctum Unstake | Part of Sanctum | Liquid Staking | [igneous-labs/sanctum-unstake-program](https://github.com/igneous-labs/sanctum-unstake-program) ⭐22 | ✅ Anchor program | 1 audit PR | 🟡 MEDIUM |

## Top 5 Targets (Ranked by Opportunity)

### 1. 🥇 Kamino Lend (`Kamino-Finance/klend`) — $1.63B TVL
- **Why:** Massive TVL, open-source lending program, no Superteam community auditor PRs
- **Programs:** `klend` (Rust/Anchor)
- **Risk surface:** Lending protocols have complex liquidation/oracle logic — high bug bounty potential
- **Action:** Clone and start reviewing liquidation paths, oracle integrations, interest rate models

### 2. 🥈 Jito Stakenet (`jito-foundation/stakenet`) — $1.07B TVL
- **Why:** Billion-dollar staking infra, two programs (`steward` + `validator-history`), minimal community audit coverage
- **Programs:** `steward`, `validator-history`
- **Risk surface:** Stake delegation logic, validator scoring, reward distribution
- **Action:** Focus on `steward` program — stake allocation decisions are high-value attack surface

### 3. 🥉 Sanctum S Controller (`igneous-labs/S`) — $931M TVL
- **Why:** Large TVL, zero community audit PRs found, LST ecosystem backbone
- **Programs:** S controller (multi-LST pool management)
- **Risk surface:** Pool pricing, LST redemption logic, cross-LST arbitrage vectors
- **Action:** Review pool math and pricing oracle interactions

### 4. Raydium CLMM (`raydium-io/raydium-clmm`) — $965M TVL
- **Why:** Near-billion TVL, open-source AMM program. AdeshAtole has 1 PR but massive codebase likely has uncovered areas
- **Programs:** `amm` (concentrated liquidity)
- **Risk surface:** Tick math, position management, fee collection, flash loan vectors
- **Action:** Focus on areas not covered by existing audit PR

### 5. Drift Protocol v2 (`drift-labs/protocol-v2`) — $328M TVL
- **Why:** Complex perpetual exchange with rich attack surface. Active development (pushed Feb 12)
- **Programs:** `drift` (perpetual DEX)
- **Risk surface:** Margin calculations, liquidation engine, oracle manipulation, funding rate logic
- **Action:** Focus on recent commits — new features are likeliest to have bugs

---

## Notes
- All repos confirmed to have Rust/Anchor programs with `programs/` directories
- Kamino also has [scope](https://github.com/Kamino-Finance/scope) (oracle aggregator, ⭐78) and [kfarms](https://github.com/Kamino-Finance/kfarms) (⭐31) worth reviewing
- Jupiter programs appear closed-source (no official program repos found)
- Meteora DLMM ($322M) — could not find open-source program repo under `meteora-ag` org
- Portal/Wormhole is multi-chain and already heavily audited
