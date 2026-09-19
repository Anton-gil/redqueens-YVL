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
