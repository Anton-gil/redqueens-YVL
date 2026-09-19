# Red Queen — Continuous RWA Security Advisor for DeFi

> _"It takes all the running you can do, to keep in the same place."_

**Red Queen** is a continuous security advisor for real-world-asset (RWA) DeFi protocols. It runs a full,
closed pipeline over a small but real system — **attack → synthesize → validate → bypass-check → advise** —
and emits governance-ready security advisories.

An autonomous/agentic attack layer finds exploits in mock RWA stablecoin contracts; a synthesizer turns each
exploit into a candidate on-chain invariant (a Solidity guard); the guard is empirically validated against a
benign-transaction corpus; a bypass analyzer tries to defeat it; the guard is deployed and the re-attack is
proven to **revert**; and a governance-ready advisory (Markdown + styled PDF) is produced. Our contribution is
**RWA-specific invariant classes + an RWA attack playbook + an advisory format that plugs into
real governance** — not a generic DeFi fuzzer.

> **Quick facts** · Stack: Foundry (Anvil + Forge) · Python 3.10+ · Base mainnet fork (pinned block `20000000`)
> · Claude / OpenAI-compatible LLMs (Anthropic, OpenAI, NVIDIA NIM, Groq, Hugging Face) with a deterministic
> fallback · Built for the **Multipli Hackathon 2026** by **Team YVL**.

---

## 1. Why RWA-specific?

The large RWA/DeFi losses of the last cycle were not classic reentrancy or arithmetic bugs. They were
**adapter and configuration errors**: a conversion rate derived from a manipulable pool balance, a price feed
composed with the wrong unit chain, a stale price reused across a multicall. Generic DeFi security tooling
(fuzzers, generic invariant miners, monitoring services) does not target these failure modes specifically.

Red Queen targets them directly. Its attack playbook encodes real RWA incident patterns, its invariant library
is written in the vocabulary of adapters, oracles, accrual semantics and cross-chain supply, and its advisory
format is built to slot into an emergency-role / timelock / governance-vote deployment model rather than
assuming a single privileged deployer.

---

## 2. Architecture

```
                         RED QUEEN PIPELINE
  ┌───────────┐   ┌────────────┐   ┌──────────┐   ┌───────────┐   ┌─────────┐
  │  ATTACK   │──▶│ SYNTHESIZE │──▶│ VALIDATE │──▶│  BYPASS   │──▶│ ADVISE  │
  │           │   │            │   │          │   │  CHECK    │   │         │
  │ playbook  │   │ trace diff │   │ fit vs   │   │ 4 fixed   │   │ MD+PDF  │
  │ + agent   │   │ → invariant│   │ benign   │   │ bypass    │   │ gov.    │
  │ (6 tools) │   │ class      │   │ corpus   │   │ strategies│   │ advisory│
  └───────────┘   └────────────┘   └──────────┘   └───────────┘   └─────────┘
       │                │               │               │              │
   exploit PoC     candidate guard   0 violations   resistance     RQ-2026-xxxx
   ($ unbacked)    (Solidity)        + coverage     score          + re-attack
                                     warnings                       REVERTS proof
```

The loop orchestrator writes state to disk at every step; the static frontend polls that state file.

### Directory map

```
red-queen/
├── src/                    6 mock contracts (+ mocks/interface) with 3 embedded vulns
│   ├── rwaUSDToken.sol         ERC-20, mint/burn gated to Ledger
│   ├── Ledger.sol              lock / unlock / principal accounting
│   ├── AccountManager.sol      deposit / mint / depositAndMint (Vuln C: stale read)
│   ├── PriceRouter.sol         composes feeds via getPrice() (Vuln B: missing multiplier)
│   ├── GoldAdapter.sol         exchangeRate() from pool balance (Vuln A: donation)
│   ├── xStockAdapter.sol       rebasing / corporate-action multiplier
│   ├── MockERC20.sol · MockPriceFeed.sol · IAdapter.sol
├── scripts/                Deploy.s.sol + deploy.sh (anvil fork Base, deterministic deploy)
├── test/                   3 reference exploit PoCs (ExploitVulnA/B/C) + Setup + guard proofs + fork/
├── corpus/                 generate_corpus.py → ~2,000 benign traces (JSONL) + stats + coverage report
├── playbook/               rwa_attack_playbook.yaml (structured attack patterns)
├── agent/                  attacker.py (FallbackAgent + LLM), hf_agent.py (autonomous), tools.py, config.py
├── invariants/             generators.py (5 RWA invariant classes) + validators.py
├── synthesis/              exploit_trace · differ · validate · guard_compiler · bypass  (+ generated/)
├── advisories/             generate_advisory.py + RQ-2026-0001/0002 (.md/.pdf) + MULTIPLI-BASE-RECON.md
├── orchestrator/           loop.py · run.py · server.py + state/*.json (pipeline state)
└── frontend/               index.html (single-file split-screen demo, polls state.json)
```

---

## 3. The three embedded vulnerabilities

The contracts are faithful to Multipli's public interfaces but minimal in internals. Three vulnerabilities are
embedded **naturally and unsignposted** — no flagging comments, no obviously-named variables — so the agent has
to find them the way an auditor would.

| ID | Pattern | Where | Root cause |
|----|---------|-------|------------|
| **Vuln A** | Adapter donation (Edel Finance, Jul 2026) | `GoldAdapter.exchangeRate()` | Rate is a bare reserve ratio (`poolBalance / shares`). A direct `transfer()` (donation) into the pool inflates the rate without minting shares → a tiny deposit is credited at the inflated rate → unbacked mint. |
| **Vuln B** | Unit-composition error (Moonwell cbETH misconfig, Feb 2026) | `PriceRouter` xStock path | Prices xStock off the **raw feed** and omits the rebase / corporate-action multiplier → **under-pricing**. |
| **Vuln C** | Stale-read multicall | `AccountManager.depositAndMint()` | Reads `priceRouter.getPrice()` **once** and reuses it across the deposit + mint sub-operations. |

Impact for the attacker-profit findings (Vuln A, Vuln C) is reported honestly as **unbacked value minted
(protocol bad debt)** under *rational* attack economics, not naive gross profit — see §6.

**Vuln B is a depositor-loss finding, not an attack.** It *under*-prices collateral, so it does not let an
attacker mint unbacked value (attacker profit is **$0**); the loss falls on honest depositors, and in these
mocks there is no liquidation engine to convert it into extractable profit. It is therefore **never** reported
as attack impact in any headline.

---

## 3a. Mocks vs Multipli reality

We are explicit about the gap between our test system and the live protocol, because the whole finding depends on it.

- **Live Multipli.** rwaUSD is a MakerDAO-style fork on **Ethereum** (Vat / Spotter / OSM / GemJoin, PAXG
  collateral). On **Base** there is only the token plus a CCIP `BurnMintTokenPool` — no adapter/oracle surface at
  all (confirmed by our read-only recon in `advisories/MULTIPLI-BASE-RECON.md`).
- **The mocks follow Multipli's *documented* v2 design**, which **already specifies PriceGuards** (max-delta,
  staleness, divergence). In that documented design, adapters only custody tokens — they do **not** derive an
  exchange rate from a pool balance.
- **So Vuln A is a bug we *injected* into the mocks**, and the v1 guard class (max-delta) is one Multipli's spec
  already includes. **We do not claim Multipli is vulnerable.**
- **Our contribution** is the finding that a **max-delta guard at an entry point is insufficient** — it has
  <!--NUM:bypass_v1.n_bypassed--> bypasses in the normal case — and that the durable fix is an **anchored
  conversion-integrity check at the value-crediting chokepoint** (v2), enforced on every path. That is a
  strengthening recommendation for the guard *class*, not an exploit of a live deployment.

---

## 4. The five RWA invariant classes

`invariants/generators.py` is a parametric library — each entry emits a deployable Solidity guard plus metadata;
`invariants/validators.py` holds the empirical validators. Guards constrain the **outcome** of an operation, not
the method, so an attacker cannot route around one by changing *how* they manipulate state (only by finding an
unguarded call site — which is exactly what the bypass analyzer probes).

1. **AdapterConversionIntegrity** — Ledger-recorded value for a deposit must equal `tokensIn × oraclePrice`
   within a tolerance, where `oraclePrice` is an **independent** raw USD-per-collateral-token feed, not the
   pool-derived rate. Catches Vuln A / Vuln C directly. **This is the v2 fix**, enforced at the single
   value-crediting chokepoint (see §6).
2. **AccrualSemanticConsistency** — observed price/supply/balance behavior must match a declared accrual type
   (`PriceAccrual`, `Rebase`, `MintedDividend`, `FixedNAV`).
3. **CrossChainSupplyConservation** — per-epoch cross-chain supply must not exceed collateral value less a
   safety margin. _(Built + documented; not exercised live — see limitations.)_
4. **OracleCompositionTypeSafety** — the unit chain of composed feeds must type-check to `USD / collateral_unit`.
   Catches Vuln B.
5. **ExchangeRateDeltaBound** — `|rate(t) − rate(t−window)| / rate(t−window) ≤ max_delta_bps`, checkpointed per
   adapter. This is the **max-delta guard class that Multipli's documented PriceGuards already specify**. Red
   Queen synthesizes it first (**v1**) and then demonstrates its central finding: a max-delta guard placed at an
   entry point is **insufficient** — it is bypassed in the normal case (see §6). The v2 fix (#1) moves the check
   to the value-crediting chokepoint and anchors it to an independent feed.

---

## 5. Quickstart

### Prerequisites

- **Foundry** (Anvil + Forge) — install via `foundryup`.
- **Python 3.10+**.
- **WSL note (Windows):** on the build machine, Foundry lives inside **WSL2**, and the entire Python stack is
  run inside WSL as well. `agent/config.py` auto-adds the Foundry bin dir to `PATH` for subprocess calls; the
  deploy script (`scripts/deploy.sh`) is a bash script that runs inside WSL. Run all commands below from a WSL
  shell (or any Linux/macOS environment with Foundry on `PATH`).

### Install

```bash
forge install                       # Solidity deps (forge-std, etc.)
pip install -r requirements.txt     # anthropic, pyyaml, reportlab
cp .env.example .env                # then fill in keys (never commit real values)
```

Minimal `.env` (keys the code reads — **all LLM keys are optional**; with none set, the deterministic
`FallbackAgent` still finds every embedded vuln):

```dotenv
# Fork / RPC (public keyless endpoints work for recon; a dedicated key helps heavy forking)
BASE_RPC_URL=https://mainnet.base.org
BASE_BLOCKSCOUT_API=https://base.blockscout.com/api
FORK_BLOCK_NUMBER=20000000

# Attack agent (optional). If OPENAI_API_KEY is set it takes precedence, else ANTHROPIC, else fallback.
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# Autonomous agent backends (optional). Resolved NVIDIA NIM → Groq → Hugging Face.
NVIDIA_API_KEY=
GROQ_API_KEY=
HF_TOKEN=

# Cost guard: hard USD kill-switch for the whole attack run.
RED_QUEEN_BUDGET_USD=2.00

# Real Multipli addresses for the advisory-only recon (blank = built-in verified defaults).
MULTIPLI_TARGET_ADDRESSES=
```

### Run the pipeline

```bash
# 1. Deploy the mock system onto a Base fork (starts anvil, writes orchestrator/state/deployment.json)
bash scripts/deploy.sh

# 2. Reference exploit PoCs (reproduce Vuln A/B/C in Foundry)
forge test

# 3. Generate the ~2,000-transaction benign corpus + stats + coverage report
python3 -m corpus.generate_corpus

# 4. Attack: deterministic playbook agent (guaranteed) …
python3 -m agent.attacker
#    … or the open-ended autonomous agent (NVIDIA/Groq/HF)
python3 -m agent.hf_agent

# 5. Synthesis pipeline
python3 -m synthesis.differ          # rank anomalies, pattern-match to an invariant class
python3 -m synthesis.validate        # fit threshold, confirm 0 violations across the corpus
python3 -m synthesis.guard_compiler  # emit + deploy guard, prove re-attack reverts, measure gas
python3 -m synthesis.bypass          # run 4 deterministic bypass strategies

# 6. Render governance-ready advisories (Markdown + PDF)
python3 -m advisories.generate_advisory

# — or run the whole loop end-to-end —
python3 -m orchestrator.run                    # full attack→guard→advisory loop on the mocks
python3 -m orchestrator.run --target multipli  # advisory-only recon vs real Multipli Base contracts

# 7. Demo UI: open frontend/index.html (polls orchestrator/state/state.json).
#    orchestrator/server.py can serve it with a /api/start hook if you want the live "start" button.
```

---

## 6. Results (from this build)

All numeric figures below are filled from the committed state files under `orchestrator/state/` at build time
(markers are `<!--NUM:...-->`). The headline story is **v1 (a max-delta entry guard) → v2 (an anchored
conversion-integrity chokepoint)**.

### 6.1 Attack (rational economics)

- **Contracts & PoCs.** 6 mock contracts (plus supporting mocks/interface) compile under solc 0.8.24; the
  repository ships 3 reference exploit PoCs (`test/ExploitVulnA/B/C.t.sol`) reproducing Vuln A/B/C. The
  deterministic `FallbackAgent` finds every embedded vuln with **0 LLM calls, $0.00 cost**.
- **Vuln A (`adapter_donation`) — the economics matter.** The naive PoC (donate a huge amount, deposit dust) is
  *irrational*: donate <!--NUM:attack.irrational.donation--> and deposit <!--NUM:attack.irrational.deposit-->
  and the attacker nets <!--NUM:attack.irrational.attacker_net_usd--> (a large **loss** — the donation is
  unrecoverable). Under **rational** parameters (donate <!--NUM:attack.economics.donation-->, deposit
  <!--NUM:attack.economics.deposit--> against a pool of <!--NUM:attack.economics.pool_balance_before-->), the
  attack mints <!--NUM:attack.economics.minted_usd--> and the attacker nets
  <!--NUM:attack.economics.attacker_net_usd-->, leaving <!--NUM:attack.economics.bad_debt_usd--> of protocol
  **bad debt**. Profit condition: `<!--NUM:attack.economics.profit_condition-->` — in plain terms, **the attack
  pays when the deposit exceeds the pool**, and the attacker can exit via rwaUSD redeemable near \$1.
- **Vuln C (`stale_price_multicall`)** — same bad-debt class via `depositAndMint()`.
- **Vuln B (`unit_composition_error`)** — a **depositor-loss** finding (attacker profit **$0**), reported as a
  valuation gap only, never as attack impact. See §3.
- A fourth pattern (`accrual_type_mismatch`) reports a type inconsistency (0 profit — the finding *is* the
  inconsistency).

### 6.2 v1 — the max-delta guard (Multipli's existing PriceGuard class) is INSUFFICIENT

The differ flags `GoldAdapter.exchangeRate` as the top anomaly and synthesizes **ExchangeRateDeltaBound**, an
opt-in `deposit()`-scoped wrapper with a 1-block window — the same max-delta class Multipli's documented
PriceGuards already specify. Its "re-attack reverts" claim holds **only** when an honest deposit pre-warms the
checkpoint in the same block. Red Queen's bypass analyzer confirms **<!--NUM:bypass_v1.n_bypassed--> bypasses**
in the normal case:

1. **First-in-fresh-block atomic** — the checkpoint is taken *after* the donation, so a first guarded call in a
   fresh block sees no movement.
2. **Direct-call-around-guard** — the guard is an opt-in wrapper; calling `AccountManager.deposit()` directly skips it.
3. **`depositAndMint` multicall path** — not behind the `deposit()`-scoped guard at all.
4. **20-block spread** — a 1-block window re-checkpoints at the already-inflated rate.

- **v1 validation is VACUOUS.** The fitted threshold (`<!--NUM:validation_v1.threshold_bps-->` bps, the reported
  "0 false positives") is not a real bound: the benign exchange rate never moves off `1e18`, so the number is
  ~10× a rounding artifact, not a measured benign deviation. We flag this rather than tout it.

### 6.3 v2 — anchored conversion-integrity chokepoint (the fix)

The v2 remediation (`src/remediated/AccountManagerV2.sol`) enforces an **AdapterConversionIntegrity** check at
the single value-crediting chokepoint (`_creditPrincipal`), anchoring credited value to the **independent** raw
USD-per-collateral-token feed (`priceRouter.usdFeedOf(adapter).latestPrice()`) rather than the pool-derived
`getPrice()`. It runs in **every** path (deposit + depositAndMint), so it is not opt-in.

- **Bypass resistance.** Against the same suite, v2 leaves **<!--NUM:bypass_v2.n_bypassed--> bypasses** and
  blocks **<!--NUM:bypass_v2.n_blocked-->** — including the fresh-block, multicall, and multi-block-spread
  attacks that defeated v1.
- **Validation is now real.** v2 measures actual benign conversion-ratio deviation: max observed
  **<!--NUM:validation_v2.max_observed_bps--> bps**, threshold **<!--NUM:validation_v2.threshold_bps--> bps**,
  **<!--NUM:validation_v2.false_positives--> false positives** across
  <!--NUM:validation_v2.applicable_traces_checked--> applicable traces.
- **Gas.** Measured overhead **<!--NUM:guard_v2.gas_overhead--> gas (~<!--NUM:guard_v2.gas_overhead_pct-->% of a
  plain deposit)**; plain deposit <!--NUM:guard_v2.gas_plain_deposit--> gas vs. guarded
  <!--NUM:guard_v2.gas_guarded_deposit--> gas.
- **Legit deposits pass**; only over-crediting (bad-debt direction) reverts.

---

## 7. Security advisories

Two complete, governance-ready advisories are generated (Markdown + styled PDF):

- **`advisories/RQ-2026-0001`** — Vuln A (Adapter Conversion Integrity, GoldAdapter), impact reported as
  protocol bad debt under rational economics (<!--NUM:attack.economics.bad_debt_usd-->).
- **`advisories/RQ-2026-0002`** — Vuln C (stale-read multicall, AccountManager), same bad-debt class.

Each advisory includes: exploit summary, reproducible Foundry PoC, an **Economics** block (pool / donation /
deposit / minted / attacker-net / bad-debt / profit-condition), candidate guard (Solidity) with **measured**
gas overhead, validation report (corpus size / violations / max observed / threshold / margin / coverage
warnings), a **v1→v2 History** block, **Residual Risks**, bypass-resistance results, recommended actions, and a
**Governance Path** section (emergency-role tighten-only mitigation vs. governance-timelock permanent fix).

A read-only recon against Multipli's real Base contracts is documented in
**`advisories/MULTIPLI-BASE-RECON.md`**.

---

## 8. Limitations & honesty notes

This project's credibility rests on saying plainly what it does and does not do.

- **Empirical validation is not formal proof.** Thresholds are fitted to a bounded benign corpus. Every advisory
  ships max-observed value, threshold margin, and coverage warnings instead of a proof claim. The corpus itself
  documents its gaps (no whale deposits > ~$1M; derived exchange rates never move off `1e18` under benign
  proportional deposits, so *any* nonzero rate movement looks maximally anomalous by construction; feeds held
  constant so there is no market-volatility ground truth; no reverted-tx samples; withdrawals are a documented
  extrapolation; single-seed synthetic addresses).
- **The autonomous agent is wired and reasons, but is not the guaranteed path.** `agent/hf_agent.py` drives its
  own recon → PoC → exploit loop over the six tools against an OpenAI-compatible router
  (`config.autonomous_endpoint()` resolves NVIDIA NIM → Groq → Hugging Face DeepSeek-R1). In recorded runs it
  performs recon and tool-calls reliably, but did not converge on a working exploit PoC within the
  iteration/time budget (DeepSeek-R1 on the HF/Novita router is very slow — minutes per round-trip — and tends
  to stall in recon; the recorded NVIDIA run got stuck on the harness's PoC format). **The deterministic
  `FallbackAgent` guarantees the vulns are found regardless of LLM.** A fast backend with reliable native
  tool-calling (Groq / NVIDIA NIM / OpenAI / Anthropic) is recommended for a practical autonomous run.
- **CrossChainSupplyConservation is built and documented but not exercised live** — the demo runs on a
  single-chain Base fork; standing up a cross-chain testbed was out of scope for the hackathon window.
- **The "donation" is a flash-loan stand-in** (a free mint of collateral on the fork). Impact is therefore
  reported as unbacked-mint / bad-debt, not net attacker profit after loan repayment.
- **Tolerance-riding residual risk.** The v2 chokepoint permits over-crediting up to `TOLERANCE_BPS`. An
  attacker who keeps each credit just under the tolerance can still extract value slowly; the tolerance is a
  tunable trade-off against benign false positives, not a hard zero.
- **The anchor trusts the raw feed.** v2 anchors credited value to the independent USD-per-collateral-token
  feed. If *that* feed is manipulated or stale, the anchor moves with it — **feed integrity is the job of the
  PriceGuard layer** (staleness / divergence), which v2 assumes but does not itself provide.
- **v2 is a guard, not the root-cause fix.** The underlying defect is the valuation *formula* (crediting value
  off a pool-derived rate). The clean fix is to credit `shares × price-per-share` or `tokensIn × unit price`
  directly; v2 is a defensive check we recommend **alongside** that formula change, because a guard ships
  faster through an emergency role than a formula rewrite ships through governance.
- **Vuln B is a depositor-loss finding, not an attack** (attacker profit $0; no liquidation engine in the
  mocks). It is excluded from all attack-impact headlines.

---

## 9. Team & license

Built by **Team YVL** for the **Multipli Hackathon 2026** (19–20 September, 36 hours). Design and scope
decisions are recorded in `../Red_Queen_Final_Implementation.md`.

This is a hackathon prototype. The contracts embed deliberate vulnerabilities for demonstration and **must not be
deployed to any production or value-bearing environment.** No license file is currently included; treat the code
as all-rights-reserved by the authors pending an explicit license.
