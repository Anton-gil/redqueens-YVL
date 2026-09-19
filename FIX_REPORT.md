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
