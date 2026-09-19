Red Queen — Complete Implementation Plan
PHASE 1: Foundation & Ground Truth

The whole system rests on this phase. Target contracts, transaction corpus, and the RWA playbook that makes our agent different from generic exploit finders.

1.1 Multipli Mock Contracts

Full Solidity implementation of Multipli's architecture from their public docs. Every contract in their suite:

rwaUSDToken — ERC-20 with mint/burn restricted to Ledger
Ledger — accounting kernel with lock, unlock, increasePrincipal, decreasePrincipal, applyIndex, startUnwind, settleUnwind
AccountManager — user-facing orchestration with openAccount, deposit, withdraw, mint, repay, depositAndMint, repayAndWithdraw, plus operator permission scoping
GoldAdapter — normalizes tokenized gold, has exchangeRate() derived from an internal pool
TBillAdapter — handles NAV-based tokens with signed feed input
StablecoinAdapter — handles USDC/USDT-like tokens with depeg detection
xStockAdapter — handles rebasing multiplier for corporate actions
PriceRouter — single read interface returning (price, status)
SignedFeedVerifier — accepts EIP-712 signed price messages with N-of-M quorum, validity windows, optional nonce
PriceGuards — max delta, staleness, cross-source divergence, depeg detection
RiskRegistry — per-profile params (safetyFactor, haircut, mintCap, penaltyFactor), timelock on changes
FeeAccumulator — lazy per-second growth factor with RATE precision
UnwindEngine + AuctionHouse — liquidation flow
Mock tokens — GLD, TBILL, USDC, xAAPL for realistic testing

Total mock contracts: ~15 Solidity files, hundreds of lines each, faithful to Multipli's published interfaces.

Embedded vulnerabilities (buried naturally in realistic code, not signposted):

Vuln A (Edel pattern): GoldAdapter's exchangeRate() reads from pool.balanceOf(address(this)) divided by totalShares. Anyone can transfer() gold directly to the pool, inflating the rate without going through deposit(). Buried in normal pool accounting logic.
Vuln B (Feb 2026 pattern): PriceRouter's composition for xStockAdapter reads the raw stock price feed but doesn't multiply by the rebasing multiplier. When the multiplier changes (dividend), the price path silently returns the wrong value. Buried in a switch statement handling multiple adapter types.
Vuln C (stale price pattern): AccountManager's depositAndMint calls priceRouter.getPrice(profileId) at the start, then does adapter.deposit(), then does ledger.increasePrincipal() using the price read at the start. If the deposit changes the pool state affecting the price, the mint uses stale valuation.
1.2 Foundry Fork Setup

Foundry project structure with:

foundry.toml configured for Base mainnet forking
Anvil launch scripts (--fork-url for Base at a fixed block for reproducibility)
Deploy scripts that put the mock contracts on the fork
Helper library with vm.deal, vm.prank, snapshot/revert utilities
Cheatcode wrappers for time manipulation (needed for FeeAccumulator testing)
1.3 Benign Transaction Corpus Generator

Synthetic transaction generator producing ~15,000 realistic transactions across all contract interactions:

Deposits: 8,000 transactions across all adapters, sizes from $10 to $10M, various user profiles
Withdrawals: 3,000 transactions with realistic hold times
Mints (borrow rwaUSD): 2,000 transactions at various collateralization ratios
Repays: 800 full and partial repayments
Multicalls: 500 depositAndMint and repayAndWithdraw bundles
Liquidations: 200 legitimate liquidations of underwater positions
Edge cases: dust amounts, near-cap deposits, rapid sequential ops
Corporate action simulations: xStock multiplier changes (dividends, splits)
Price updates: ~1000 SignedFeedVerifier updates across all profiles
Governance actions: RiskRegistry parameter changes through timelock

Each transaction runs on the fork and gets:

Full execution trace captured (all opcodes, state reads/writes)
Pre-state and post-state snapshots
Gas usage
Return values

Stored as structured JSON on disk. This is our ground truth for invariant validation.

1.4 Corpus Coverage Report

Analyzer that produces honest coverage documentation:

Transaction type breakdown
Size distribution (min, max, percentiles)
Interaction diversity (how many unique user profiles)
Temporal distribution (rapid vs spaced-out txs)
Gaps flagged: "no whale deposits >$5M," "no multi-year hold positions," "no cross-adapter liquidation cascades"

This report gets included in every advisory the system produces, so the protocol team knows what our validation actually covered.

1.5 RWA Attack Playbook (Structured)

The playbook lives as a YAML file, not just a system prompt string. Each pattern:

yaml
- name: adapter_donation
  reference_incident: "Edel Finance, July 2026, $403K loss"
  target_type: adapter
  preconditions:
    - adapter has exchangeRate() or conversion function
    - conversion reads from pool with public balance
    - pool accepts direct transfer without callback
  attack_template:
    - flash_loan(collateral_token, amount=1M)
    - transfer_direct(pool, amount)
    - deposit(adapter, small_amount) # gets inflated rate
    - mint(rwaUSD, max_allowed)
    - withdraw(adapter, small_amount) # gets back inflated value
    - repay_flash_loan()
  success_criteria:
    - profit > 0
    - adapter.exchangeRate() delta > 10x

- name: unit_composition_error
  reference_incident: "cbETH misconfig, Feb 2026, $1.78M loss"
  ...

- name: stale_price_multicall
  reference_incident: "generic multicall class, ongoing"
  ...

- name: multiplier_manipulation
  reference_incident: "xStock corporate action class"
  ...

- name: cross_chain_supply_inflation
  reference_incident: "KelpDAO, April 2026, $292M loss"
  ...

Playbook is version-controlled, extensible, and gives the agent structured guidance instead of vague prompts.

End of Phase 1: Working Foundry environment, faithful Multipli mocks with three embedded vulnerabilities, 15K validated benign traces, honest coverage report, structured attack playbook.

PHASE 2: The Attack Agent

Playbook-driven agent that finds exploits by systematic testing, not blind guessing.

2.1 Tool Harness

Six wrappers around Foundry that the LLM calls:

decompile(address)

If verified: pull Solidity from Basescan/Etherscan API
If unverified: use Heimdall or Panoramix to decompile bytecode
Return structured output: function signatures, storage layout, control flow summary
Cache results per address

trace(txHash_or_calldata)

Run transaction on fork with --trace
Parse output into structured trace: call tree, state changes, events
Return JSON with each opcode's context
Cache results

fork_and_execute(solidity_code, block_number)

Compile provided Solidity via forge build
Deploy to fork
Call attack() function
Capture profit (delta in attacker's balance), state changes, trace
Return structured result: {success, profit_usd, revert_reason?, trace}
60-second timeout per execution

storage_read(address, slot_or_variable_name)

Read storage slot from fork
Optionally decode using contract ABI if available
Return raw value + decoded value

price_query(adapter_or_token)

Call PriceRouter.getPrice()
Return {price, status, staleness, source_feeds}

compile_and_validate(solidity_code)

Run forge build on provided code
Return {success, errors, warnings, bytecode?}
Catches syntax errors before wasting a fork execution
2.2 Agent Runtime

Agent brain: Gemini 2.5 Pro (or Claude Sonnet 4 if you switch). Runtime is Python with structured output enforcement.

System prompt includes:

Overview of Multipli's architecture (from Phase 1 mocks)
Full RWA attack playbook (from 1.5)
Tool schemas
Output format spec
Explicit "you are a security researcher, not an attacker" framing
2.3 Playbook-Driven Loop
For each pattern in playbook:
    1. Check preconditions:
       - Read target contracts via decompile
       - Match structural requirements
       - Skip if pattern doesn't apply

    2. Instantiate attack template:
       - Fill in specific addresses, amounts, tokens
       - Adapt template to target's specific interface

    3. Write PoC:
       - Generate Foundry test contract
       - Include attack() function with all steps
       - Validate compilation

    4. Execute on fork:
       - Run via fork_and_execute
       - Capture result

    5. On failure:
       - Analyze revert reason
       - Adjust parameters (amounts, sequencing)
       - Max 5 retries per pattern

    6. On success:
       - Record validated exploit
       - Move to next pattern

    7. On no exploits found across all patterns:
       - Return "no exploits found" (valid result)
2.4 Cost & Safety Guards
Max 15 tool calls per pattern
Max 4K output tokens per LLM call
Total run budget: $2 (kill switch)
5-minute timeout per pattern
Auto-retry with exponential backoff on rate limits
Trace every LLM call to disk for debugging
2.5 Attack Output Format

Per successful exploit, structured JSON:

json
{
  "finding_id": "RQ-2026-0001",
  "pattern_name": "adapter_donation",
  "target_contract": "0xGoldAdapter",
  "poc_solidity": "// full Foundry test file...",
  "profit_usd": 47000,
  "execution_trace": { "call_tree": [...], "state_changes": [...] },
  "state_delta": {
    "exchangeRate_before": "1.0",
    "exchangeRate_after": "3.4",
    "delta_percent": 240.0
  },
  "reasoning_log": [
    "Read GoldAdapter, exchangeRate() reads from pool.balanceOf",
    "Tried direct transfer to pool, balance updated without going through deposit",
    "Constructed flash loan → transfer → deposit → mint sequence",
    "Executed, profit $47K"
  ]
}

End of Phase 2: Agent that reliably discovers all three seeded vulnerabilities by systematically testing playbook patterns, produces validated PoCs with full reasoning logs, stays within cost/time bounds.

PHASE 3: Invariant Synthesis, Validation & Advisory Generation

The core novel contribution. RWA-specific invariant classes, honest empirical validation, bypass analysis, and actionable advisories.

3.1 RWA Invariant Class Library

Five parametric invariant templates. Each is a Solidity code generator plus a validation function.

AdapterConversionIntegrity(adapter, oracle, tolerance_bps)

Property: For every deposit into adapter, the value the Ledger records must equal deposited_tokens × oracle.getPrice() ± tolerance_bps.

Generated Solidity:

solidity
modifier assertConversionIntegrity(uint256 tokensIn, uint256 valueRecorded) {
    _;
    uint256 oraclePrice = priceRouter.getPrice(profileId).price;
    uint256 expected = tokensIn * oraclePrice / 1e18;
    uint256 delta = valueRecorded > expected ? valueRecorded - expected : expected - valueRecorded;
    require(delta * 10000 / expected <= tolerance_bps, "CONVERSION_INTEGRITY_VIOLATION");
}

AccrualSemanticConsistency(profileId, expected_accrual_type)

Types: PriceAccrual, Rebase, MintedDividend, FixedNAV.

Property: The observed price behavior over time must match the declared accrual type. MintedDividend tokens should have flat price with supply growth. Rebase tokens should have flat price with balance growth per holder. PriceAccrual tokens should have monotonically increasing price.

Validated by comparing observed feed updates against expected pattern.

CrossChainSupplyConservation(chains, epoch_length, safety_margin_bps)

Property: Σ supply_across_chains(epoch) ≤ total_collateral_value(epoch) × (1 - safety_margin_bps/10000)

Enforced as per-epoch release budget: single-epoch release must not exceed budget derived from historical normal flow.

Generated Solidity uses a ReleaseBudget contract that tracks per-epoch flows and reverts if exceeded.

OracleCompositionTypeSafety(pricePath)

Property: The unit chain of feeds must compose to [USD / collateral_unit]. Static analysis at config time, runtime check that intermediate values match expected dimensional ranges.

ExchangeRateDeltaBound(adapter, max_delta_bps, window_blocks)

Property: For any adapter, |exchangeRate(t) - exchangeRate(t - window)| / exchangeRate(t - window) ≤ max_delta_bps / 10000.

Generated Solidity uses a checkpoint pattern storing rate at end of previous block.

3.2 Trace Differ

Input: exploit trace + benign corpus.

Algorithm:

Extract all state variable changes from exploit trace
For each variable, compute benign distribution (mean, std, percentiles 50/95/99/99.9)
Compare exploit's per-variable delta to benign distribution
Rank variables by z-score (how many standard deviations the exploit deviates)
Output ranked list of anomalous state changes with statistics
3.3 Candidate Invariant Generator

Input: ranked anomalies from trace differ.

For each anomaly, pattern-match against invariant class library:

Anomaly on exchangeRate() delta → generate ExchangeRateDeltaBound
Anomaly on Ledger.locked[] / oracle.price ratio → generate AdapterConversionIntegrity
Anomaly on cross-chain supply → generate CrossChainSupplyConservation
Config-level anomaly → generate OracleCompositionTypeSafety
Accrual behavior anomaly → generate AccrualSemanticConsistency

Multiple candidates can be generated per exploit. Thresholds are set at max observed benign value × safety factor (typically 2x-10x).

3.4 Empirical Validation Pipeline

For each candidate invariant:

Historical corpus check: Run invariant against every trace in the benign corpus. Count violations. If any, invariant is REJECTED (would break legitimate usage).
Statistical margin analysis:
Max observed value of the constrained variable in benign corpus
Threshold value
Margin ratio (threshold / max_observed)
Confidence interval based on corpus size
Coverage warnings: Cross-reference with Phase 1.4 coverage report. Flag any transaction types the corpus doesn't cover well.

Output structured validation report:

json
{
  "invariant": "ExchangeRateDeltaBound(GoldAdapter, 100_bps, 1_block)",
  "corpus_size": 14834,
  "violations_in_corpus": 0,
  "max_observed_value": 0.0008,
  "threshold": 0.01,
  "margin_ratio": 12.5,
  "coverage_warnings": [
    "No historical deposits > $5M — threshold may need review for whale txs",
    "No cross-adapter arbitrage flows in corpus"
  ],
  "validation_confidence": "HIGH within covered scenarios"
}

Directly addresses gap 2. Never called a "proof."

3.5 Bypass Resistance Analyzer

For each candidate invariant, spawn a smaller "bypass agent" (short-loop LLM run) that tries to circumvent it:

Split attack: Break the exploit into N smaller transactions to stay under per-tx thresholds
Gas manipulation: Change gas passed to specific calls (for gas-based invariants)
Timing manipulation: Spread operations across blocks (for windowed invariants)
Alternative path: Find a different contract function that achieves same state change but isn't guarded
Composition attack: Chain the invariant-triggering call inside a callback

For each bypass attempt, check if it succeeds. Output:

json
{
  "bypass_attempts": [
    {
      "method": "split_into_10_subtransactions",
      "success": false,
      "reason": "Per-block invariant catches accumulated delta"
    },
    {
      "method": "spread_across_20_blocks",
      "success": false,
      "reason": "Cumulative delta over window still exceeds threshold"
    },
    {
      "method": "use_alternate_deposit_path_via_multicall",
      "success": true,
      "reason": "Multicall bypasses per-function guard",
      "mitigation_required": "Add invariant at multicall boundary"
    }
  ],
  "resistance_score": "MEDIUM — requires layered defense"
}

Directly addresses gap 3. Honest about bypass surface.

3.6 Guard Compiler

Takes validated invariant + parameters, emits deployable Solidity:

Post-condition modifier for the target function
Storage additions if needed (checkpoint variables)
Deployment script that either:
Deploys a wrapper contract calling the original
Uses vm.etch to inject bytecode (fork only)
Generates upgrade proposal for governance (production)

Includes gas estimation via forge test --gas-report.

3.7 Gas & Composability Analysis

For each guard:

Measured gas overhead per protected function call
Cumulative overhead estimate for typical user flow
Composability check: does this guard block any known integration pattern?
Whitelist mechanism for trusted intra-protocol calls (CrossGuard-style)

Output included in advisory.

3.8 Advisory Generator

The final deliverable. Structured JSON + rendered Markdown per finding:

markdown
# Security Advisory RQ-2026-0001

**Severity:** HIGH
**Category:** Adapter Conversion Integrity
**Reference Pattern:** Edel Finance, July 2026 ($403K loss)
**Discovered:** 2026-09-19 14:32 UTC

## Exploit Summary
The GoldAdapter's exchangeRate() reads from pool.balanceOf...
[full narrative]

## Reproducible PoC
[Foundry test file]

## Candidate Guard
**Invariant:** ExchangeRateDeltaBound(GoldAdapter, 1%, 1 block)

**Solidity:**
[modifier code]

**Gas Overhead:** 8,234 gas per deposit operation (+2.1%)

## Validation Report
- Corpus size: 14,834 transactions
- Violations in corpus: 0
- Max observed rate delta: 0.08%
- Threshold: 1%
- Margin: 12.5× above max observed
- **Coverage warnings:**
  - No historical deposits > $5M in corpus
  - No cross-adapter arbitrage in corpus

## Bypass Resistance
- Split attack: BLOCKED
- Gas manipulation: BLOCKED
- Alternate path via multicall: **BYPASS FOUND** — requires layered guard at multicall boundary
- **Resistance Score:** MEDIUM

## Recommended Actions
1. **Immediate:** Deploy as post-condition on GoldAdapter.deposit()
   - Compatible with emergency role (tighten-only)
   - No governance vote required
2. **Follow-up:** Deploy layered guard at AccountManager.multicall boundary
   - Requires governance approval
3. **Review:** Manual review of threshold before whale deposit deployment

## Governance Path
- **Emergency role compatible:** YES (tighten-only)
- **Timelock required:** NO
- **Full governance vote required:** For layered multicall guard only

Directly addresses gap 5. This IS the value proposition. Red Queen produces production-ready security advisories, not autonomous protocol modifications.

End of Phase 3: Complete pipeline that turns exploits into validated, bypass-analyzed, governance-compatible security advisories.

PHASE 4: The Loop, The Demo, The Pitch

Wire everything together, build the visualization that wins the room, prepare responses to every gap.

4.1 Loop Orchestrator

Python orchestrator that runs the full iteration:

python
state = {
    "iteration": 0,
    "deployed_guards": [],
    "advisories": [],
    "target_contracts": load_multipli_mocks()
}

while state["iteration"] < 5:
    write_state("attacking", state)
    exploit = attacker.run(
        target=state["target_contracts"],
        active_guards=state["deployed_guards"]
    )

    if not exploit:
        write_state("hardened", state)
        break

    write_state("synthesizing", state, exploit=exploit)
    advisory = synthesizer.process(
        exploit=exploit,
        corpus=benign_corpus
    )

    write_state("deploying_guard", state, advisory=advisory)
    deploy_guard_to_fork(advisory.guard)

    state["deployed_guards"].append(advisory.guard)
    state["advisories"].append(advisory)
    state["iteration"] += 1

    write_state("iteration_complete", state)

write_state("run_complete", state)

State written to disk at every step. Frontend polls the state file.

4.2 Split-Screen Demo Frontend

Next.js app, deployed on Vercel. Reads state file via API endpoint that streams updates.

Left panel (attacker, red theme):

Current pattern being tested (playbook progress bar)
Live agent reasoning log (streamed line by line)
Tool call timeline (which tool, when, what returned)
PoC code editor showing the exploit being written character by character
Execution result banner: EXPLOIT FOUND: $47,000 or REVERTED

Right panel (defender, green theme):

Trace diff visualization (spotlight the anomalous variables)
Candidate invariant generation
Corpus validation progress: 1,247 / 14,834 transactions checked with tick counter
Threshold visualization: Max observed: 0.08% | Threshold: 1.00% | Margin: 12.5x
Bypass analysis results with pass/fail per attempt
Guard deployment confirmation

Bottom bar (always visible):

Iteration counter: Iteration 2 of ∞
Total advisories generated: 3
Total corpus validated: 44,502 transactions across 3 invariants
Coverage warnings flagged: 7

Header:

"Red Queen — Continuous RWA Security Advisor"
Multipli logo (subtle)
Live status indicator
4.3 Real Multipli Contract Run

Separate script that runs the pipeline against actual Multipli mainnet contracts:

bash
python red_queen.py --target=multipli-mainnet --mode=advisory-only --no-deploy

Fetches Multipli's deployed contract addresses from their docs. Forks Base at latest block. Runs the full pipeline. Outputs advisory report.

Two possible outcomes:

Findings: Screenshot the advisory, share with Multipli team, use in demo
No findings: "Consistent with a hardened protocol post 10 audits. System correctly identifies no exploitable patterns."

Either way, we have a real-contract data point for the demo.

4.4 Demo Rehearsal Setup
Backup fork state saved so demo starts from known state instantly
Pre-warmed API responses (cache agent's known-good responses for demo reliability)
Local backup of the frontend in case Vercel has issues
Terminal-only fallback demo if frontend breaks
Screenshot deck as ultimate fallback
4.5 Pitch Deck & Responses

Slide 1: The Problem (30 sec)
"$1B lost in H1 2026. RWA protocols lost $200M+ specifically to configuration and adapter errors, not code bugs. Existing security tools target generic DeFi. Nobody targets RWA."

Slide 2: What Red Queen Is (30 sec)
"Continuous security advisor for RWA protocols. Attack agent + invariant synthesizer + advisory pipeline. Purpose-built for RWA failure modes."

Slide 3-4: Live Demo (2 min)
Split-screen visualization running.

Slide 5: Comparison Table (30 sec)

	SentinelCRE	Phylax	SphereX	A1	Trace2Inv	Red Queen
RWA-specific invariants	✗	✗	✗	✗	✗	✓
Attack + defense loop	✗	✗	✗	✗	✗	✓
Bypass resistance analysis	✗	✗	✗	✗	✗	✓
Advisory format (governance-ready)	✗	✗	✗	✗	✗	✓
Empirical validation with coverage warnings	✗	✗	✗	✗	Partial	✓
Multi-layer defense integration	✗	✓	✓	✗	✗	✓

Slide 6: Multipli Application (30 sec)
"Applied to Multipli's five attack surfaces: adapter conversion, oracle composition, multicall staleness, xStock multipliers, cross-chain supply. All addressed."

4.6 Locked Gap Responses

Memorize these for Q&A:

Gap 1 — "The agent won't find novel exploits"
"Correct, and we don't claim it will. We follow the A1 architecture with an RWA-specific playbook. The agent systematically tests known RWA failure modes against target contracts, which is what a security auditor does. Novelty is in the playbook and invariant classes, not the agent."

Gap 2 — "Your 'zero false positive proof' is empirical, not formal"
"You're right. We call it empirical validation, not mathematical proof. Each advisory reports max observed value, threshold margin, and coverage warnings. For production deployment, we recommend additional headroom and human review of flagged coverage gaps."

Gap 3 — "On-chain guards can be read and bypassed"
"Correct. Our bypass resistance analyzer specifically tests this. Each advisory includes attempted bypasses and their results. State-level invariants like our exchange rate bound constrain outcomes rather than methods. When bypasses are found, we recommend layered defenses at additional boundaries."

Gap 4 — "Gas overhead and composability"
"Our guards add 5-15K gas per protected call, roughly 2-5% overhead. We scope invariants to multicall boundaries following CrossGuard's approach, with whitelist support for trusted intra-protocol calls. Every advisory includes measured gas overhead and composability analysis."

Gap 5 — "The loop doesn't close autonomously"
"By design. Red Queen is an advisory system, not an autonomous deployer. Production deployment requires human judgment on thresholds and governance approval. The advisory format is compatible with Multipli's existing RiskRegistry timelock and emergency role model."

Gap 6 — "Not enough benign traces for new protocols"
"We generate synthetic transaction corpora covering realistic usage patterns, and every advisory reports coverage gaps explicitly. For a new protocol with limited history, we recommend deploying with additional threshold headroom and phased rollout by transaction size."

Gap 7 — "The combination has a name (RvB paper, ACM multi-layer)"
"Cited in our references. Our contribution isn't the loop architecture. It's the RWA-specific invariant classes and attack playbook, plus the advisory output format that integrates with real governance processes. Every existing tool targets generic DeFi. We target RWA."

End of Phase 4: Working demo, real Multipli contract run, split-screen frontend, memorized pitch with locked gap responses, positioning comparison table.

Deliverables at the End
Full source: red_queen/ monorepo with contracts, agent, synthesizer, orchestrator, frontend
Foundry test suite proving all three seeded vulnerabilities and all three generated guards work
Three complete security advisories in Markdown + JSON
Real Multipli mainnet run report
Working split-screen demo
Pitch deck
Public GitHub repo
Demo video for submission
README with reproducible run instructions