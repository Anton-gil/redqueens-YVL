# Red Queen — Continuous RWA Security Advisor for DeFi

> _"It takes all the running you can do, to keep in the same place."_

**Red Queen** is a continuous security advisor for real-world-asset (RWA) DeFi protocols. It runs a full,
closed pipeline over a small but real system — **attack → synthesize → validate → bypass-check → advise** —
and emits governance-ready security advisories.

An autonomous/agentic attack layer finds exploits in mock RWA stablecoin contracts; a synthesizer turns each
exploit into a candidate on-chain invariant (a Solidity guard); the guard is empirically validated against a
benign-transaction corpus; a bypass analyzer tries to defeat it; the guard is deployed and the re-attack is
proven to **revert**; and a governance-ready advisory (Markdown + styled PDF) is produced. The novel
contribution is **RWA-specific invariant classes + an RWA attack playbook + an advisory format that plugs into
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
| **Vuln B** | Unit-composition error (cbETH misconfig, Feb 2026) | `PriceRouter` xStock path | Prices xStock off the **raw feed** and omits the rebase / corporate-action multiplier → mispricing. |
| **Vuln C** | Stale-read multicall | `AccountManager.depositAndMint()` | Reads `priceRouter.getPrice()` **once** and reuses it across the deposit + mint sub-operations. |

Impact is reported honestly as **unbacked value minted (protocol bad debt)**, not naive attacker profit.

---

## 4. The five RWA invariant classes

`invariants/generators.py` is a parametric library — each entry emits a deployable Solidity guard plus metadata;
`invariants/validators.py` holds the empirical validators. Guards constrain the **outcome** of an operation, not
the method, so an attacker cannot route around one by changing *how* they manipulate state (only by finding an
unguarded call site — which is exactly what the bypass analyzer probes).

1. **AdapterConversionIntegrity** — Ledger-recorded value for a deposit must equal `tokensIn × oraclePrice`
   within a tolerance. Catches Vuln A / Vuln C directly.
2. **AccrualSemanticConsistency** — observed price/supply/balance behavior must match a declared accrual type
   (`PriceAccrual`, `Rebase`, `MintedDividend`, `FixedNAV`).
3. **CrossChainSupplyConservation** — per-epoch cross-chain supply must not exceed collateral value less a
   safety margin. _(Built + documented; not exercised live — see limitations.)_
4. **OracleCompositionTypeSafety** — the unit chain of composed feeds must type-check to `USD / collateral_unit`.
   Catches Vuln B.
5. **ExchangeRateDeltaBound** — `|rate(t) − rate(t−window)| / rate(t−window) ≤ max_delta_bps`, checkpointed per
   adapter. General-purpose form of #1; this is the guard synthesized and deployed in the live demo.

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

All figures below are taken from the committed state files under `orchestrator/state/`.

- **Contracts & PoCs.** 6 mock contracts (plus supporting mocks/interface) compile under solc 0.8.24; the
  repository ships 3 reference exploit PoCs (`test/ExploitVulnA/B/C.t.sol`) reproducing Vuln A/B/C.
- **Deterministic attack agent** (`agent/attacker.py`, `FallbackAgent`) confirms:
  - **Vuln A** (`adapter_donation`) → **$46,000 unbacked** (rate 1e18 → 24e18, a 24× spike).
  - **Vuln C** (`stale_price_multicall`) → **$46,000 unbacked** via `depositAndMint()`.
  - **Vuln B** (`unit_composition_error`) → flagged as a **$950,000 mispricing** finding.
  - A fourth pattern (`accrual_type_mismatch`) reports the type inconsistency (0 profit — the finding *is* the
    inconsistency). LLM calls: 0, cost: $0.00.
- **Synthesis.** The differ flags `GoldAdapter.exchangeRate` as the top anomaly and pattern-matches it to
  **ExchangeRateDeltaBound**.
- **Validation.** Threshold fitted to **15.9%** (`1590 bps` = 10× the **1.59%** benign dust-rounding maximum);
  **0 violations** across the 2,000-trace corpus (907 applicable traces checked); the exploit sits **144×** over
  threshold. Confidence: "HIGH within covered scenarios," shipped with 9 explicit coverage warnings.
- **Guard.** Compiled, deployed via a thin wrapper, and the **re-attack reverts**. Measured invariant gas
  overhead: **~11,257 gas steady-state (~8.6% of a plain deposit)**; plain deposit 131,421 gas vs. guarded full
  path 236,010 gas (first-call checkpoint init adds ~53,076 gas).
- **Bypass analysis** (`orchestrator/state/bypass_report.json`). 4 strategies run; **2 real bypasses found**:
  the `depositAndMint` multicall path (guard scoped to `deposit()` only), and spreading the donation across
  blocks to defeat the 1-block window. Split-into-10 and gas-variance did **not** bypass. Resistance:
  **MEDIUM — requires layered defense.** Finding real bypasses is a feature of the honesty story, not a bug.

---

## 7. Security advisories

Two complete, governance-ready advisories are generated (Markdown + styled PDF):

- **`advisories/RQ-2026-0001`** — Vuln A (Adapter Conversion Integrity, GoldAdapter), $46,000 impact.
- **`advisories/RQ-2026-0002`** — Vuln C (stale-read multicall, AccountManager), $46,000 impact.

Each advisory includes: exploit summary, reproducible Foundry PoC, candidate guard (Solidity) with **measured**
gas overhead, validation report (corpus size / violations / max observed / threshold / margin / coverage
warnings), bypass-resistance results, recommended actions, and a **Governance Path** section (emergency-role
compatible? timelock required? full vote?).

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

---

## 9. Team & license

Built by **Team YVL** for the **Multipli Hackathon 2026** (19–20 September, 36 hours). Design and scope
decisions are recorded in `../Red_Queen_Final_Implementation.md`.

This is a hackathon prototype. The contracts embed deliberate vulnerabilities for demonstration and **must not be
deployed to any production or value-bearing environment.** No license file is currently included; treat the code
as all-rights-reserved by the authors pending an explicit license.
