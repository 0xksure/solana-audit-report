# Solana Protocol Audit Targets — Full Report

**Generated:** 2026-02-13 | **Deadline:** 2026-02-15 | **Source:** DeFi Llama + GitHub

## Already Audited (SKIP)
Raydium CLMM, Kamino Lend, Kamino Liquidity, Jito Stakenet, Port Finance, OpenBook v2, Saber, Marinade (all variants)

---

## 🏆 TOP 10 RECOMMENDED TARGETS

| # | Protocol | TVL | Category | GitHub Repo | Stars | Last Commit | Audit PRs? | Priority |
|---|----------|-----|----------|-------------|-------|-------------|------------|----------|
| 1 | **Orca DEX** | $256M | DEX | `orca-so/whirlpools` | 512 | 2026-02-13 | Yes (20) — has Superteam PRs already | HIGH ⚠️ |
| 2 | **MetaDAO Futarchy** | $12M | DEX/Governance | `metaDAOproject/futarchy` | 107 | 2026-02-13 | **0** | **HIGH** ✅ |
| 3 | **Sanctum (S Controller)** | $931M+$168M | Liquid Staking/DEX | `igneous-labs/S` | 47 | 2025-11-19 | 1 (old audit report) | **HIGH** ✅ |
| 4 | **Save (Solend)** | $78M | Lending | `solendprotocol/solana-program-library` | 114 | 2026-02-04 | Yes (8) — has Superteam PRs | HIGH ⚠️ |
| 5 | **Drift Protocol** | $329M+$150M | Derivatives | `drift-labs/protocol-v2` | 378 | 2026-02-12 | Yes (8) — has Superteam PRs | HIGH ⚠️ |
| 6 | **marginfi** | $65M | Lending | `mrgnlabs/marginfi-v2` | 284 | 2026-02-13 | Yes (20) — active audits | MEDIUM ⚠️ |
| 7 | **Quarry** | $6M | Yield | `quarryprotocol/quarry` | 229 | 2024-05-09 | Yes (old Quantstamp) | LOW (inactive) |
| 8 | **Jito Restaking** | $18M | Restaking | `jito-foundation/restaking` | 80 | 2025-11-24 | Yes (15) — heavily audited | LOW |
| 9 | **Realms Governance** | $42M | Governance | `solana-labs/governance-program-library` | 54 | 2025-02-09 | Yes (15) | LOW (inactive) |
| 10 | **Jito Programs** | (Jito infra) | Liquid Staking | `jito-foundation/jito-programs` | 87 | 2026-02-04 | Yes (4) — has Superteam PRs | LOW |

### 🎯 Best Opportunities (open source + active + FEW/NO audit PRs)

**#1 Pick: `metaDAOproject/futarchy`** — $12M TVL, 107★, actively maintained (pushed today!), 5 Anchor programs (`futarchy`, `conditional_vault`, `bid_wall`, `damm_v2_cpi`, `launchpad`), **ZERO audit PRs**. This is the cleanest target.

**#2 Pick: `igneous-labs/S`** (Sanctum) — $1.1B combined TVL, programs: `s-controller`, `pricing-programs`, `sol-value-calculator-programs`. Only 1 old audit report PR from 2024. Very high TVL, relatively unexplored.

**#3 Pick: `orca-so/whirlpools`** — $256M TVL, 512★, but already has Superteam audit PRs (including a Feb 11 security fix). Still viable if you find something new.

---

## Full Protocol List

### Open Source + Active (potential targets)

| Protocol | TVL | Category | GitHub Repo | Stars | Last Commit | Programs? | Audit PRs | Priority |
|----------|-----|----------|-------------|-------|-------------|-----------|-----------|----------|
| Sanctum (all) | $1.1B | Liquid Staking | `igneous-labs/S` | 47 | 2025-11-19 | ✅ s-controller, pricing | 1 (old) | **HIGH** |
| Drift Trade | $329M | Derivatives | `drift-labs/protocol-v2` | 378 | 2026-02-12 | ✅ drift | 8 (has Superteam) | HIGH ⚠️ |
| Orca DEX | $256M | DEX | `orca-so/whirlpools` | 512 | 2026-02-13 | ✅ whirlpool | 20 (has Superteam) | HIGH ⚠️ |
| Save (Solend) | $78M | Lending | `solendprotocol/solana-program-library` | 114 | 2026-02-04 | ✅ (SPL fork) | 8 (has Superteam) | HIGH ⚠️ |
| marginfi | $65M | Lending | `mrgnlabs/marginfi-v2` | 284 | 2026-02-13 | ✅ marginfi | 20 (heavy) | MEDIUM ⚠️ |
| Realms | $42M | Governance | `solana-labs/governance-program-library` | 54 | 2025-02-09 | ✅ 5 plugins | 15 | LOW (inactive) |
| Jito Restaking | $18M | Restaking | `jito-foundation/restaking` | 80 | 2025-11-24 | ✅ | 15 (heavy) | LOW |
| MetaDAO Futarchy | $12M | DEX | `metaDAOproject/futarchy` | 107 | 2026-02-13 | ✅ 5 programs | **0** | **HIGH** ✅ |
| Quarry | $6M | Yield | `quarryprotocol/quarry` | 229 | 2024-05-09 | ✅ 5 programs | 9 (old) | LOW (inactive) |

### Closed Source / No Public Solana Programs (SKIP)

| Protocol | TVL | Category | Notes |
|----------|-----|----------|-------|
| Jupiter Lend | $1.04B | Lending | No public program repo found |
| Jupiter Perpetual | $861M | Derivatives | No public program repo found |
| Jupiter Staked SOL | $825M | Liquid Staking | No public program repo |
| DoubleZero Staked SOL | $1.06B | Liquid Staking | No public repo |
| Binance Staked SOL | $699M | Liquid Staking | CEX-operated |
| Meteora DLMM | $322M | DEX | No public program repo (SDKs only) |
| Meteora DAMM V1/V2 | $71M | DEX | No public program repo |
| Meteora Vaults | $48M | Yield Aggregator | No public program repo |
| Solstice USX | $315M | Basis Trading | No public repo |
| PumpSwap | $165M | DEX | No public program repo |
| Drift Staked SOL | $150M | Liquid Staking | No separate program repo |
| Phantom SOL | $100M | Liquid Staking | CEX-operated |
| JPool | $99M | Liquid Staking | No public repo |
| The Vault Liquid Staking | $99M | Liquid Staking | No public repo |
| Exponent | $95M | Yield | No public repo |
| Lulo | $94M | Yield Aggregator | No public repo |
| Project 0 | $89M | Lending | No public repo |
| BlazeStake | $82M | Liquid Staking | Uses SPL Stake Pool (standard) |
| Loopscale | $74M | Lending | No public repo |
| Edgevana | $66M | Liquid Staking | No public repo |
| Neutral Trade | $45M | Capital Allocator | No public repo |
| Pacifica | $38M | Derivatives | No public repo |
| Perena Vaults | $25M | Capital Allocator | No public repo |
| Vectis Finance | $24M | Yield | No public repo |
| Hylo Protocol | $24M | Stablecoin | No public repo |
| Fragmetric | $20M | Restaking | No public repo |
| Solayer Restaking | $15M | Restaking | CLI only (no program source) |
| All others <$15M | Various | Various | Closed source or no Solana programs |

---

## Summary

- **58 Solana protocols** with TVL > $5M identified
- **9 protocols** have open-source Solana programs on GitHub
- **6 already have Superteam audit PRs** (Orca, Drift, Save, marginfi, Jito, Realms)
- **Most high-TVL protocols (Jupiter, Meteora, etc.) are closed-source** — not auditable

### Recommended Action Plan (before Feb 15 deadline)

1. **🎯 MetaDAO Futarchy** (`metaDAOproject/futarchy`) — Best target. 5 Anchor programs, zero audit PRs, actively maintained. Start here.
2. **🎯 Sanctum S** (`igneous-labs/S`) — High TVL ($1.1B combined), programs for LST pricing/swapping, only old audit. Second priority.
3. **⚠️ Orca/Drift/Save** — Already have Superteam PRs but still worth checking for issues others missed. Third priority.
