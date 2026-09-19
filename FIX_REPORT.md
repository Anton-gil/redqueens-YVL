# Red Queen v2 — Fix Report

Branch: `fix/red-queen-v2`. Rule: never touch `src/*.sol` (except `src/remediated/`); all verdicts from executed forge tests.

## Phase 0.1 — Baseline (executed)
- `forge build`: Compiler run successful.
- `forge test`: 5 passed, 0 failed, 1 skipped (fork test `RealFlashDonation` skipped without RPC env).
  - Passing: ExploitVulnA/B/C testExploit, GuardFalsePositiveProof (2).

## Phase 0.2 — Reproduced findings (executed forge, then repro files deleted)
| Finding | Reproduction | Result |
|---|---|---|
| **F1** fresh-block atomic bypass | legit guarded deposit warms checkpoint; `vm.roll(+1)`; attacker donates 230k then guardedDeposit(1) as first guarded call in the new block | **BYPASSED** — no revert; exchangeRate 1.0 → 23.77; principal 247,544e18 credited. Checkpoint is taken AFTER the donation. |
| **F2** opt-in guard | attacker donates then calls `AccountManager.deposit()` directly (skips wrapper) | **BYPASSED** — 48,000e18 principal credited, no revert |
| **F4** irrational economics | donate 230,000 gold, deposit 1 gold | minted $48,000; attacker **net = −$459,954,000** (−$459.95M) |
| **F4** rational economics | donate 10,000 gold, deposit 100,000 gold | minted **$400,000,000**; attacker **net = +$180,000,000** |

Profit condition confirmed: net ≈ D·usd·(deposit/poolBefore − 1); the attack pays when **deposit > pool**.

## Decisions log
- (0.2) Reproductions match the external review exactly. Proceeding to build V2 remediation (anchored conversion-integrity chokepoint) in `src/remediated/`.

## Cross-agent requests
_(agents append here; lead applies)_

## Phase 0.3 — Shared reference files (executed + committed)
- `src/remediated/AccountManagerV2.sol`: identical API + same vulnerable valuation as AccountManager; single chokepoint `_creditPrincipal` (increasePrincipal appears exactly once) anchored to `priceRouter.usdFeedOf(adapter).latestPrice()` (independent of pool rate); XSTOCK folds in `rebaseMultiplier`. `TOLERANCE_BPS` via constructor (provisional 100 bps, set from Agent D).
- `test/SetupV2.t.sol`: mirrors Setup with AccountManagerV2 + TOLERANCE_BPS_V2.
- `orchestrator/state/SCHEMA.md`: added-fields schema for v2.
- **Proven (executed forge, temp tests then deleted):** legit deposit passes; donation+deposit and donation+depositAndMint both revert with `ConversionIntegrityViolation(expected=2000e18, recorded=48000e18)`; selector = `0x608e7eb0` matches `AccountManagerV2.ConversionIntegrityViolation.selector`.

### Decision — expectRevert form (Foundry 1.8.3)
Bare `vm.expectRevert(<Error>.selector)` does NOT match an error WITH arguments in forge 1.8.3 (it requires exactly 4 bytes of revert data). Verified working forms: `vm.expectPartialRevert(<Error>.selector)` (selector-only) and `vm.expectRevert(abi.encodeWithSelector(sel, args...))`. **All v2/bypass tests use `vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector)`** — still asserts the specific selector (Rule 4 satisfied), never a bare `expectRevert()`. This is the "genuinely-wrong test guidance, fixed with reason" allowed by Rule 5.

## Phase 1 — Agents A/B/C (executed forge; committed)
- **A (guard v2):** test/GuardV2.t.sol — 8 tests green: legit gold/stock/depositAndMint pass; donation, donation+multicall, fresh-block-atomic, 20-block-spread, rational-economics all revert (ConversionIntegrityViolation). Gas: v2 deposit 134,596 vs v1 131,421 → +3,175 (2.4%); dAM +3,233 (2.1%). guard_report.json written. v1 re-attack test renamed `testReAttackReverts_prewarmedCheckpointOnly`.
- **B (bypass):** synthesis/bypass.py + test/bypass/BypassV1|V2.t.sol. Verdicts from executed forge. v1 = 5 BYPASSED (spread, multicall, first-in-block, direct-call, rational), 1 BLOCKED (split), 0 ERROR. v2 = 0 BYPASSED, 7 BLOCKED, 0 ERROR; tolerance_riding RESIDUAL = $20,000,000 extractable; unguarded_call_site_scan BLOCKED (increasePrincipal appears once, both paths route through _creditPrincipal). gas_variance = NOT_APPLICABLE.
- **C (economics):** ExploitVulnA/C rewritten — RATIONAL (donate 5,000 = 50% pool, deposit 100,000 = 10x pool) nets **+$90,000,000** (minted $300M, bad debt $100M), forge-confirmed; irrational reference (230,000 / 1) nets **-$459,954,000** (kept as labelled test). 15/25 grid points profitable; profit condition deposit>pool. Vuln B relabelled MISPRICING_FINDING (depositor_loss $950,000, attacker_profit 0). attack_result.json economics blocks written.

### Decision — attacker.py FallbackAgent
The rational economics + grid are computed and, at the chosen point, FORGE-CONFIRMED via test/ExploitVulnA|C.t.sol; attack_result.json carries the economics blocks. The attacker.py FallbackAgent demo bodies were left as invariant-violation demonstrators (still true) rather than surgically re-parameterized, to avoid destabilizing the shared agent near deadline. Numbers that docs/frontend read come from attack_result.json (forge-confirmed).

### Cross-agent request — Agent F (Docs & Claims), Phase 4 NUM fill map
Docs are done. README.md / PITCH_NOTES.md contain `<!--NUM:key-->` markers the lead must fill from
`orchestrator/state/*.json` (per SCHEMA.md). Distinct keys used → source field:

- `attack.economics.{pool_balance_before,donation,deposit,minted_usd,attacker_net_usd,bad_debt_usd,profit_condition}`
  → attack_result.json patterns[adapter_donation].economics.{...} (rational params).
- `attack.irrational.{donation,deposit,attacker_net_usd}`
  → attack_result.json patterns[adapter_donation].irrational_reference.{...}.
- `bypass_v1.n_bypassed`, `bypass_v2.n_bypassed`, `bypass_v2.n_blocked` → bypass_report.json {v1,v2}.{n_bypassed,n_blocked}.
- `validation_v1.threshold_bps` → validation.json v1.threshold_bps (this marker sits next to prose that calls v1 VACUOUS — keep that).
- `validation_v2.{max_observed_bps,threshold_bps,false_positives,applicable_traces_checked}` → validation.json v2.{...}.
- `guard_v2.{gas_plain_deposit,gas_guarded_deposit,gas_overhead,gas_overhead_pct}` → guard_report.json v2.{...}.

Notes for the fill: (1) Vuln B must stay a depositor-loss finding (attacker profit $0) — do NOT wire it to an
attack-impact marker. (2) If `bypass_v1.n_bypassed` resolves to 4, the README/PITCH prose already enumerates the
4 named bypasses; if the executed count differs, ping Agent F to reconcile the enumerated list. (3) Advisory
JSON can now carry optional `economics`, `guard_history` ({v1,v2}), `residual_risks`, and extended
`governance_path` ({immediate_mitigation,permanent_fix,root_cause_fix}) fields — generate_advisory.py renders
them if present and skips gracefully if absent. No files outside Agent F's ownership were modified.

## Phase 1 — Agent D (validation honesty) + Agent F (docs) [executed/committed]
- **D:** TOLERANCE_BPS resolved. EVM ground truth (test/ValidationV2.t.sol, 40 varied benign deposits incl. dust): max conversion-ratio deviation = **0 bps, 0 false positives**. Corpus SIM shows up to 1240 bps (p99 1176) but that is a coarse share-rounding artifact NOT reproduced on the EVM — this resolves the F6 contradiction. TOLERANCE_BPS kept at **100** (safe absolute margin over EVM rounding; not a fit to the sim). v1 validation labelled VACUOUS_FOR_RATE_DELTAS. validation.json written per-version.
- **F (subagent):** README (Mocks-vs-reality §, v1→v2 reframe, limitations), idea.md/implementation.md claim deletions/softening, advisories/generate_advisory.py templates (economics/history/residual/governance), PITCH_NOTES.md, advisories/CLAIMS_AUDIT.md. 34 NUM markers (22 keys), 0 hardcoded pipeline numbers in docs; 5 verified / 5 softened / 8 deleted claims. Filed a Phase-4 NUM fill map.

### Decision — TOLERANCE_BPS = 100 (unchanged)
EVM benign deviation is 0, so the provisional 100 bps in AccountManagerV2/SetupV2 is correct; no constructor change needed. Documented that the root-cause formula fix would allow ~0 tolerance and remove the tolerance-riding residual.

## Phase 2/4 — Integration + verification (lead, executed)
- **Full `forge test`: 31 passed, 0 failed, 1 skipped** (fork test needs RPC). All A/B/C/D suites green together.
- `git diff main -- src/*.sol` (top-level vulnerable contracts): **EMPTY** — only `src/remediated/AccountManagerV2.sol` is new. Deliberately-vulnerable src untouched.
- Stale-metric grep: only remaining hits are the v1 VACUOUS threshold (`1590` bps / `15.9%`) cited to DEBUNK it (README §results, PITCH Q7) — explained, matches validation.json v1.threshold_bps. No stale headline numbers.
- "first/novel/nobody" grep: all hits are sequence-"first" (v1→v2), honesty DISCLAIMERS ("not novel, not claimed"), gap-response quotes, or CLAIMS_AUDIT documenting deletions. No superiority claims remain.
- NUM markers: all filled from state (0 unfilled). state.json carries real attacker($90M)/defender(0 violations, guard deployed) blocks + iterations[] (v1: 5 bypassed → v2: 0).
- `demo.sh`: deterministic offline demo (forge test → synthesis.bypass → state summary), no API keys.

### Agent E — scope note
state.json is frontend-compatible (real attacker/defender blocks) so the existing verified frontend renders TRUE numbers, plus a new `iterations[]` block for the v1→v2 story. A dedicated iterations-table UI in frontend/index.html is a remaining enhancement (data is present in state); the full iterative orchestrator/loop.py rewrite was not done (correctness-first prioritization near deadline).

## Phase 3 — Red team findings (Agent R)
Files: `test/redteam/RedTeam.t.sol` (11 tests), `test/redteam/UnitBugFalsePositive.t.sol` (3). All 14 executed & green, each asserting the stated outcome.

1. **tolerance_riding — HELD (documented residual is live).** Donate 100e18 (rate→exactly 1.01), deposit 1e6 tokens: credited $2.02B vs fair $2.00B → extractable **$20,000,000**, net **+$19,800,000** after the $200k donation. Over-mint is bounded by ≤1% of deposit (confirmed), but the absolute residual scales unbounded with deposit size and is net-profitable. Matches the claim's carve-out.
2. **rounding — HELD.** Dust 1..1e12 wei and 1e30 deposits: no wrong revert, no over-credit past tolerance (flooring only lowers value).
3. **dominant shareholder — HELD.** Attacker as majority holder, then donate+deposit, still reverts (guard re-anchors to feed).
4. **xStock — HELD.** Pool donation is inert (XSTOCK price ignores pool); credit = amt*feed. After `applyCorporateAction(2x)`, `expected` folds the multiplier → value<expected, no over-credit.
5. **reentrancy — N/A.** No callback (MockERC20), adapters fixed; `_creditPrincipal` re-reads the anchor feed with no external call before `increasePrincipal`. No vector (reasoning + access-control test).
6. **unguarded mint path / access control — HELD.** `increasePrincipal` appears once (in `_creditPrincipal`); both paths route through it. Direct `ledger.increasePrincipal`/`mint` and `adapter.deposit` revert (onlyAccountManager); mint>principal underflow-reverts.
8. **tests-for-wrong-reason — HELD.** Blocked attack reverts with EXACTLY selector `0x608e7eb0`; a non-guard revert (missing approval) does NOT match. `bypass.py` parses forge logs, not hardcoded.
7 + **"benign deposits pass" — BROKEN (VALID; lead must fix).** `depositAndMint` forwards `pd.price` (USD/share ≈2000e18) into `GoldAdapter.depositAtPrice` as the collateral `rate` (≈1e18) → mints ~2000x too few shares (0.5e18 vs 1000e18), corrupting `exchangeRate` to 1.0999e18. Then ANY subsequent benign gold deposit — plain or depositAndMint — reverts with `ConversionIntegrityViolation`. One benign `depositAndMint` bricks the gold adapter; the claim "benign deposits pass" is false. Root cause = the unit bug in depositAndMint/depositAtPrice (pass rate, not price). Note: `ValidationV2.t.sol` never mixes `depositAndMint` with a following deposit, so it missed this.
9. **frontend — advisory.** Live path reads `orchestrator/state/*.json` (real numbers). But the fallback `SAMPLE_STATE` in `frontend/index.html` is fully hardcoded/fabricated ($47,000 profit; contracts VaultRouter/PriceOracleAdapter that don't exist; ExchangeRateDeltaBound invariant; 1247/1850 corpus) — a different exploit than the real one. Badged "MOCK DATA" honestly, but rendered whenever fetch fails (e.g. `file://`).

## Phase 3 — Red team (fresh agent) results
- **1 VALID break found + FIXED:** #7 depositAndMint forwarded pd.price (USD/share) into depositAtPrice as the collateral rate → ~2000x wrong shares → corrupted exchangeRate → anchored guard reverted the NEXT benign deposit ("benign deposits pass" was false in a realistic sequence). FIX: AccountManagerV2.depositAndMint routes shares through IAdapter.deposit() (re-derives rate); valuation unchanged so donation is still blocked. Regression: test/redteam/UnitBugFalsePositive.t.sol (now asserts fixed behavior) + test/RegressionV2.t.sol. Re-ran Phases 2-3: v1=5 bypassed, v2=0 unchanged.
- **Everything else HELD** (executed asserts, test/redteam/RedTeam.t.sol, 11 tests): tolerance_riding (documented residual, net-profitable, bounded ≤~1% of deposit but absolute value scales with deposit size), rounding (dust..1e30), dominant-shareholder, xStock, reentrancy (no callback surface), single-mint-path/access-control, tests-not-passing-for-wrong-reason (guard selector 0x608e7eb0 exact; non-guard reverts don't match; bypass.py parses logs not hardcoded).
- **Advisory (#9):** frontend offline SAMPLE_STATE was fabricated ($47k, fake contracts) — FIXED: replaced with the real committed state.json; stale comment updated; both script blocks syntax-valid.

## Phase 4 — Final verification checklist
- [x] `forge test`: **46 passed, 0 failed, 1 skipped** (fork test needs RPC). 
- [x] v1 bypass report: first_in_block_atomic, direct_call_around_guard, multicall_path, spread_across_20_blocks all BYPASSED (bypass_report.json v1; evidence test/bypass/BypassV1.t.sol).
- [x] v2: 0 BYPASSED, 0 ERROR; unguarded_call_site_scan BLOCKED; tolerance_riding residual quantified ($20M at 100 bps; scales with deposit).
- [x] Legit deposit + depositAndMint pass on v2; 0 false positives on EVM benign sequence incl. after depositAndMint (GuardV2 + RegressionV2 + ValidationV2).
- [x] Vuln A/C attacker_net > 0 at chosen params (+$90M), forge-confirmed; irrational reference (-$459.95M) recorded.
- [x] Vuln B shown as depositor-loss ($950k, attacker profit $0); not in any attack headline.
- [x] `git diff main -- src/*.sol` (excluding remediated): EMPTY.
- [x] Stale-metric grep: only the v1 VACUOUS threshold cited to debunk it; no stale headline numbers; no fabricated frontend numbers.
- [x] `demo.sh`: runs offline, no keys, in ~11.5s; frontend renders v1→v2 from committed state.
- [x] CLAIMS_AUDIT.md complete; no "first/novel/nobody" superiority claims remain (only honesty disclaimers).

## Before / after
| Claim / property | Before (v1) | After (v2) |
|---|---|---|
| "re-attack reverts" (normal case) | FALSE (bypassed fresh-block/direct/multicall/spread) | TRUE — anchored chokepoint blocks all attack classes |
| Guard scope | opt-in wrapper (skippable) | protocol chokepoint, every credit path |
| Bypasses | 5 (of 6 tested) | 0 (+ 1 quantified residual: tolerance-riding) |
| Reference for the check | getPrice() (contains manipulated rate) | raw usdFeed (independent) |
| Exploit economics | irrational PoC (-$459.95M) | rational, forge-confirmed (+$90M; bad debt $100M) |
| Vuln B | "$950k impact" (implied attacker gain) | depositor loss $950k, attacker profit $0 |
| Validation | vacuous (rate never moves; 15.9% = 10x rounding) | measured EVM conversion-ratio (0 bps benign, tol 100 bps) |
| Guard gas | ~11.3k (2.4% deposit) delta-guard | anchored: +3,175 (2.4%) deposit, +4,451 (2.9%) depositAndMint |
| Docs/frontend numbers | hardcoded | all from orchestrator/state/*.json |

## Remaining limitations (honest)
- **Tolerance-riding residual:** donating just under TOLERANCE_BPS + a huge deposit extracts up to ~1% of deposit value (bounded ratio, but absolute value scales with deposit). Mitigation: tighter tolerance / TWAP anchor / the root-cause valuation fix.
- **Guard vs root cause:** v2 is a guard; the root-cause fix is the valuation formula (credit tokensIn × raw unit price directly), which removes the pool-rate dependence and the residual.
- **Anchor trusts the raw feed:** feed integrity is PriceGuards' job (staleness/divergence), out of scope here.
- **Cross-chain supply-conservation** invariant class: built + documented, not exercised on a single-chain fork.
- **Scope cuts (logged):** attacker.py FallbackAgent bodies left as invariant demonstrators (economics forge-confirmed via ExploitVuln tests + attack_result.json); dedicated v1→v2 iterations-table UI + full iterative orchestrator/loop.py rewrite not done (data present in state.json; existing frontend renders real numbers). Correctness-first per the directive.
