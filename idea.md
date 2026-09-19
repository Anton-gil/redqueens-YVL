Red Queen  — Full Refined Idea
THE PROBLEM
The macro picture

Crypto exploits topped a billion dollars across 200-plus incidents in H1 2026 — a record half-year by attack volume (industry trackers put the total in the ~$1.0B–$1.3B range depending on methodology). But here's the thing most people miss: much of the money lost around RWA collateral in 2026 wasn't lost in the smart contracts themselves. It was lost one layer out. In the configuration of the price oracles that lending protocols read. In the wrapper mechanisms that convert between token representations. In the off-chain businesses that were supposed to service the underlying assets.

Three incidents tell the story:

February 2026, $1.78M: A governance proposal on a Base lending deployment misconfigured an oracle wrapper. The oracle used raw cbETH/ETH exchange rate without multiplying by ETH/USD. cbETH got priced at $1.12 instead of $2,200. Monitoring caught it within minutes. A five-day governance timelock blocked the fix. Liquidations continued for five days.

July 2026, Edel Finance, $403K: An attacker manipulated the wrapping mechanism for tokenized Google stock. Chainlink correctly reported Alphabet's share price. The vulnerability was in how GOOGLx converted to and from wGOOGLx, inflating collateral value 78x. Every price check passed. Every access control passed. The composition of valid components produced theft.

November 2025, Stream Finance, $93M → $285M contagion: An external fund manager lost $93M. Their xUSD stablecoin crashed 77%. Researchers found $285M in cascading debt exposure across Euler, Silo, Morpho, and Gearbox. An anonymous trader had flagged the 4x leverage through recursive looping days earlier. The warning signal was on-chain, but no deployed monitoring was tuned to act on that specific pattern.

Why existing tools don't solve this

The security tool landscape in 2026 is mature but generic:

Monitoring tools (Hypernative, Forta, BlockSec, Defimon) watch transactions and alert you. Hypernative monitors 75+ chains and detected the Balancer exploit. But detection after execution is too late when $128M drains in 30 minutes.

Runtime guards (Phylax Credible Layer, SphereX Protect, CrossGuard) enforce invariants at the transaction or sequencer level. Phylax is integrated into Linea's sequencer. SphereX is in production. These are real and good. But their invariant templates are designed for generic DeFi: reentrancy guards, balance conservation, slippage bounds, control-flow integrity.

Invariant synthesis tools (Trace2Inv, InvCon, FLAMES) try to automatically generate invariants from transaction traces. Published evaluations report strong results on curated exploit sets but sharply lower recall when applied to large, general-purpose invariant sets — the technology works well in focused applications but does not yet scale to arbitrary protocols. (Specific benchmark percentages from these papers are not restated here; see CLAIMS_AUDIT.md.)

AI exploit agents (A1, EvoPoC, PoCo, ReX) can generate working exploits. A1 achieved 63% on its benchmark. EvoPoC reached 96.6% using a hierarchical knowledge graph. These prove that AI-driven exploit discovery works.

What none of them do:

None of these tools understand RWA-specific failure modes. They don't know what an adapter conversion error looks like. They don't know that a NAV-based token and a rebasing token and a minted-dividend token have fundamentally different accrual semantics and that misconfiguring one as the other is a pricing time bomb. They don't know that a tokenized stock's rebasing multiplier can change during a corporate action and that a multicall that spans that change can mint against a stale balance. They don't know that cross-chain RWA supply must satisfy conservation constraints that generic ERC-20s don't have.

RWA protocols are a different beast from AMMs and lending pools. The attack surface isn't reentrancy or sandwich attacks. It's unit composition errors, accrual-semantic mismatches, adapter conversion manipulation, NAV staleness across market-hours boundaries, and cross-chain supply inflation. These RWA-specific failure modes are what Red Queen targets, and they are not the primary focus of the general-purpose DeFi tooling above.

Why this matters for Multipli specifically

Mapped onto Multipli's documented architecture, there are five RWA surface *classes* worth guarding. Important caveat (see README "Mocks vs Multipli reality"): Multipli's documented v2 design already specifies PriceGuards (max-delta, staleness, divergence) on these surfaces, and its adapters custody tokens rather than deriving an exchange rate from a pool balance. We do **not** claim Multipli is vulnerable. We inject these bugs into faithful mocks to study the guard classes themselves. The five surface classes:

Asset Adapters normalize different token types (gold, T-bills, stablecoins, xStocks) into a standard interface. Each adapter has a conversion function (like exchangeRate()). If an attacker can manipulate that conversion within a single transaction, they inflate their collateral value and mint excess rwaUSD. This is the exact Edel pattern.
The PriceRouter composes multiple feeds into a final USD price per collateral unit. Each feed has different units ([USD/ETH], [ETH/cbETH], [XAU_oz/USD]). If the composition path has a unit error, the final price is wrong by orders of magnitude. This is the exact February 2026 pattern.
The SignedFeedVerifier accepts EIP-712 signed price messages with an optional nonce and a validity window. Any still-valid signed price can be submitted. If a relayer can choose which valid price to submit, they can cherry-pick prices that benefit their position.
AccountManager multicalls bundle deposit + mint or repay + withdraw into single transactions. If the price read happens before a state change that affects the price, the mint uses a stale value.
rwaUSDi's multi-chain supply depends on cross-chain messaging for mint-and-release operations. If supply on one chain inflates without corresponding collateral elsewhere, the system is insolvent. This is the class of failure behind the KelpDAO cross-chain release (~$290M).

The 2026 RWA losses came largely from the configuration, adapter-composition, and cross-chain supply-consistency layers rather than from classic code bugs. Those layers are exactly what Red Queen's invariant classes are written to constrain — as a continuous, runtime-oriented complement to point-in-time code audits, not a claim about any specific protocol's audit coverage.

THE SOLUTION
What Red Queen is

Red Queen is a continuous security advisor built specifically for RWA protocols. It combines three things:

An attack agent with an RWA-specific playbook that knows exactly what to look for in collateral adapter systems
An invariant synthesizer with RWA-specific invariant classes
A validation pipeline that checks every candidate invariant against the protocol's own transaction history and outputs actionable security advisories

It runs in a loop: the agent attacks a forked copy of the protocol, the synthesizer generates and validates a defense, the defense deploys on the fork, and the agent attacks again. Each iteration produces a security advisory with a reproducible exploit PoC, a candidate guard in Solidity, and a validation report.

Red Queen does NOT autonomously deploy guards to production. It generates validated findings that the protocol team reviews and deploys through their existing governance process. This is intentional. Production deployment requires human judgment on thresholds and governance approval, and we don't pretend otherwise.

What Red Queen is NOT

It's not a novel attack agent. We follow the A1 architecture (LLM + domain-specific tools) and openly acknowledge that EvoPoC's knowledge-graph approach achieves higher success rates on generic benchmarks.

It's not a formal verification tool. Our invariant validation is empirical (checking against historical transaction corpus), not a mathematical proof. We report the validation margin alongside every invariant so the protocol team can judge confidence.

It's not the first attack-then-defend loop. The RvB paper (January 2026) formalized this architecture. We cite it.

It's not the first runtime guard system. Phylax, SphereX, CrossGuard, and HoneyPause all deploy on-chain invariant enforcement. Several are in production.

What Red Queen IS (our contribution)

Our contribution 1: RWA-Specific Invariant Classes

We define five invariant classes written specifically for RWA collateral systems:

Adapter Conversion Integrity:
"The value the Ledger records for a deposit must equal the deposited tokens × the oracle price ± a configurable tolerance, regardless of the adapter's internal conversion path."

This catches the Edel pattern. The wrapper conversion inflated value 78x while the oracle was correct. The adapter told the Ledger the collateral was worth 78x its actual value. This invariant constrains the OUTPUT of the conversion, not the method, so an attacker can't circumvent it by changing HOW they manipulate the rate. The result still has to be within tolerance.

Accrual-Semantic Consistency:
"A token's price change behavior must match its declared accrual type."

NAV-based tokens like BUIDL maintain a fixed $1 price and mint new tokens as dividends. Rebasing tokens like USDY increase holder balances. Price-accrual tokens like USYC increase in price. If a BUIDL-style token is configured as PriceAccrual in the PriceRouter, the system expects its price to go up, but it doesn't, so valuation breaks. This invariant rejects configurations where the observed price behavior doesn't match the declared accrual type.

Cross-Chain Supply Conservation:
"Total rwaUSDi supply across all monitored chains in any epoch must not exceed total backing collateral value minus a safety margin, and single-epoch releases must not exceed a budget derived from historical normal flow."

This catches the KelpDAO pattern: a large rsETH release (~$290M) on a cross-chain message that should not have authorized it. A conservation invariant would have flagged a release that exceeded the epoch's normal flow budget.

Oracle Composition Type Safety:
"The unit chain of feeds in a price path must compose to [USD / collateral_unit]. Every intermediate conversion (wrapper ratios, rebasing multipliers, decimal normalization) must be an explicit term in the composition."

This catches the February 2026 pattern. The oracle used [ETH/cbETH] where it needed [USD/cbETH]. A type-checked composition would reject this before the config enters the governance timelock.

Exchange Rate Delta Bounding:
"For any adapter, the exchange rate between its input token and its internal representation must not change by more than X% within a single transaction or within a configurable time window."

This is a general form of the Edel guard but scoped to every adapter type. The threshold X is derived from the historical maximum observed delta plus a safety margin.

Our contribution 2: RWA-Specific Attack Playbook

Instead of generic LLM prompting (A1) or a generic knowledge graph (EvoPoC), the attack agent follows a playbook specialized for RWA collateral systems:

Attack Pattern 1 — Adapter Donation (Edel-style):
  For each adapter, check if exchangeRate() or the conversion
  function reads from a pool whose balance can be influenced
  by direct token transfers. If yes, flash loan tokens,
  donate to pool, deposit at inflated rate, mint excess rwaUSD.

Attack Pattern 2 — Unit Composition Error (Feb 2026-style):
  For each price path in PriceRouter, trace the unit chain
  from raw feed to final USD price. Check if any intermediate
  conversion is missing, doubled, or inverted. If yes,
  construct a transaction that mints rwaUSD against the
  mispriced collateral.

Attack Pattern 3 — Stale Price in Multicall:
  For each multicall bundle in AccountManager, check if the
  price is read once and used for multiple operations. If a
  state change in an earlier operation affects the price
  but the later operation uses the stale read, construct
  a multicall that exploits the gap.

Attack Pattern 4 — Multiplier Manipulation (xStock-style):
  For rebasing/multiplier tokens, check if a corporate action
  (dividend, split) can be triggered or front-run mid-transaction
  to change the effective balance between deposit and mint.

Attack Pattern 5 — Cross-Chain Supply Inflation (KelpDAO-style):
  For cross-chain mint/release operations, check if supply
  on one chain can increase without corresponding lock on
  another. Check bridge verifier configuration (1-of-1 DVN
  patterns, missing redundancy).

Our contribution here is the RWA-specific attack playbook. A1, EvoPoC, PoCo, and ReX target generic smart-contract vulnerabilities (reentrancy, integer overflow, access control); our playbook targets the five failure modes that actually caused losses in RWA protocols in 2025-2026.

Our contribution 3: Advisory Output Format

Red Queen doesn't pretend to autonomously deploy guards. It generates structured security advisories:

ADVISORY: RQ-2026-001
Severity: HIGH
Pattern: Adapter Donation Attack
Target: GoldAdapter.exchangeRate()

EXPLOIT:
  Reproducible PoC (Foundry test file)
  Validated profit: $47,000 on fork at block 12345678
  Attack vector: flash loan → direct transfer to pool →
    exchangeRate inflates 3.4x → deposit at inflated rate →
    mint excess rwaUSD → repay flash loan

CANDIDATE GUARD:
  Invariant: |exchangeRate_post - exchangeRate_pre| /
             exchangeRate_pre < 0.01
  Solidity: [full modifier code]
  Gas overhead: ~8,000 gas per deposit operation

VALIDATION:
  Historical transactions checked: 14,000
  Max observed exchangeRate delta: 0.08%
  Threshold margin: 12.5x above historical max
  Trace diversity: deposits (8,200), withdrawals (4,100),
    mints (1,200), repays (500)
  WARNING: No whale deposits >$5M in historical corpus.
    Recommend manual review of threshold for large deposits.

RECOMMENDED ACTION:
  Deploy as post-condition check on GoldAdapter.deposit()
  Compatible with emergency role (tighten-only)
  Does not require full governance proposal

This format is honest about limitations (the whale deposit warning), actionable (specific Solidity code), and compatible with Multipli's existing governance model (emergency roles can tighten risk without a timelock).

HOW IT WORKS (the technical flow)
Phase 1: Environment Setup

Fork Multipli's contracts from mainnet (or deploy mock contracts matching their published architecture). Replay all historical transactions to build a benign transaction corpus with full execution traces.

Phase 2: Attack Agent Runs

The agent (Claude API with six domain-specific tools) follows the RWA attack playbook against the forked contracts. It reads the adapter code, identifies potential manipulation points, writes exploit contracts in Solidity, executes them on the fork, and validates profitability.

The six tools: decompile, trace, fork-and-execute, storage-read, price-query, compile-and-validate. Same as A1's architecture, not novel, not claimed to be.

Phase 3: Invariant Synthesis

When the agent finds a profitable exploit, the synthesizer:

Captures the exploit's execution trace
Diffs it against the benign corpus to find anomalous state changes
Generates candidate invariants from the RWA-specific invariant classes
Validates each candidate against the full historical corpus
Reports the validation margin and any coverage gaps
Compiles surviving candidates into Solidity post-condition checks

The validation is empirical, not formal. We say "validated against N transactions with X margin" not "mathematically proven."

Phase 4: Guard Deployment (on fork only)

The candidate guard deploys to the fork. This shows the concept works but doesn't claim autonomous production deployment.

Phase 5: Re-Attack

The agent runs again against the guarded fork. Its previous exploit reverts. It tries alternative approaches from the playbook. If it finds another exploit, the cycle repeats.

Phase 6: Advisory Generation

All findings compile into structured security advisories. Each advisory includes the PoC, the candidate guard, the validation report with coverage gaps, and a recommended action compatible with Multipli's governance model.

THE DEMO

Split screen. Left is red (attacker). Right is green (defender).

Beat 1: Agent reads the gold adapter. Follows playbook pattern 1 (adapter donation). Discovers exchangeRate() reads from a manipulable pool. Writes a flash loan PoC. Executes. "$47,000 extracted" appears on screen.

Beat 2: Synthesizer activates. Diffs traces. Finds exchange rate delta of 340% versus historical max of 0.08%. Generates candidate invariant. Validates against 14,000 transactions. Reports: "Validated. Max observed: 0.08%. Threshold: 1%. Margin: 12.5x." Guard deploys to fork.

Beat 3: Agent retries. Same exploit reverts: INVARIANT_VIOLATION: exchangeRate_delta_exceeded. Agent pivots to playbook pattern 3 (stale price in multicall). Finds a different exploit. Synthesizer generates a second invariant. Second guard deploys.

Bottom bar: Shows invariant count, total historical transactions validated, coverage gaps flagged.

Final slide: The structured advisory output. "Here's what Red Queen would hand to Multipli's security team. A reproducible PoC, a validated guard, and an honest assessment of its limitations."