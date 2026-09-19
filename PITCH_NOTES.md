# Red Queen — Pitch Notes

Speaker notes for the demo. Every pipeline number is a `<!--NUM:...-->` marker filled from
`orchestrator/state/*.json` at build time — never read a hardcoded figure off this page.

---

## 60-second pitch

> In H1 2026 crypto lost over a billion dollars across 200-plus exploits — a record. The RWA-collateral losses
> mostly didn't come from the smart-contract code; they came one layer out, in the *configuration* and *adapter*
> layer. Edel Finance: a wrapper exchange rate inflated tokenized-Google collateral ~78× while the price feed was
> perfectly correct. Moonwell: an oracle priced cbETH off the raw cbETH/ETH rate and skipped ETH/USD.
>
> **Red Queen is a continuous security advisor built for exactly that layer.** It runs a closed loop over a
> faithful RWA mock system — attack, synthesize a guard, validate it against a benign corpus, try to bypass it,
> and emit a governance-ready advisory. Our contribution is RWA-specific: an attack playbook, five RWA invariant
> classes, and an advisory format that plugs into an emergency-role / timelock / vote model.
>
> Here's the honest headline. Our *first* guard was the max-delta class that protocols already specify — and we
> proved it is **insufficient**: <!--NUM:bypass_v1.n_bypassed--> bypasses in the normal case. Our *fix* moves the
> check to the single value-crediting chokepoint and anchors it to an independent price feed. Against the same
> attacks it leaves <!--NUM:bypass_v2.n_bypassed--> bypasses, at ~<!--NUM:guard_v2.gas_overhead_pct-->% gas
> overhead, with **real** validation — <!--NUM:validation_v2.false_positives--> false positives on measured
> benign deviation. We don't claim any live protocol is broken. We show a guard *class* is weak and ship the
> stronger one.

---

## The 12 hardest judge questions (honest answers)

**1. Is Multipli vulnerable?**
No, and we don't claim it is. Live rwaUSD is a MakerDAO-style fork on Ethereum; on Base there's only the token
plus a CCIP burn/mint pool — no adapter/oracle surface (we confirmed this with a read-only on-chain recon,
`advisories/MULTIPLI-BASE-RECON.md`). Our mocks follow Multipli's *documented* v2 design, which already specifies
PriceGuards. Vuln A is a bug we *injected* to study the guard class. Our finding is about the class — a max-delta
guard at an entry point is insufficient — not about a live deployment.

**2. Isn't this just Trace2Inv / FLAMES / InvCon?**
Those are general-purpose invariant miners over transaction traces, and they work well on curated exploit sets
but don't scale to arbitrary protocols. We're not competing on general invariant recovery. Our contribution is
narrow and RWA-specific: five invariant classes written in the vocabulary of adapters, accrual semantics, oracle
unit-composition and cross-chain supply, plus an attack playbook and an advisory format. We follow the A1 agent
architecture and say so — our contribution is the RWA domain modeling, not the miner or the agent.

**3. Why did your first guard fail?**
Because a max-delta bound on `exchangeRate()` at the `deposit()` entry point checks the wrong thing in the wrong
place. It's an opt-in wrapper, it checkpoints *after* the donation, and it's scoped to one function. We
demonstrated <!--NUM:bypass_v1.n_bypassed--> concrete bypasses: (1) first-in-fresh-block atomic — the checkpoint
is taken after the donation; (2) direct call around the opt-in wrapper; (3) the `depositAndMint` multicall path,
which the guard never covered; (4) spreading the donation across ~20 blocks to beat the 1-block window. That
failure is the point of the project — it's why the fix has to be an anchored check at the value-crediting
chokepoint, enforced on every path.

**4. So what's the actual fix, and why is it better?**
`AccountManagerV2` routes all principal credit through one chokepoint, `_creditPrincipal`, and anchors credited
value to the **independent** raw USD-per-collateral-token feed (`priceRouter.usdFeedOf(...).latestPrice()`),
not the pool-derived `getPrice()` that carries the manipulation. It's on deposit *and* depositAndMint, so it's
not opt-in. Result: <!--NUM:bypass_v2.n_bypassed--> bypasses vs <!--NUM:bypass_v1.n_bypassed--> for v1, at
~<!--NUM:guard_v2.gas_overhead_pct-->% overhead. We're also honest that v2 is still a *guard*; the root-cause fix
is the valuation formula itself (credit shares×price-per-share).

**5. Where's the AI?**
Two places, and we're precise about it. The attack agent (`agent/hf_agent.py`) drives a recon→PoC→exploit loop
over six domain tools against an OpenAI-compatible router (NVIDIA NIM → Groq → Hugging Face). It reasons and
tool-calls, but on slow backends it didn't always converge in the time budget — so a deterministic
`FallbackAgent` guarantees the vulns are found regardless of LLM (0 LLM calls, $0.00). We show the AI path but
don't hide behind it. The synthesis/validation/bypass logic is deterministic by design — you want a guard
recommendation to be reproducible.

**6. Why mocks instead of the real protocol?**
Because the real Base deployment has no adapter/oracle surface to attack (see Q1), and standing up the Ethereum
Maker-fork with real liquidity was out of scope for a 36-hour window. The mocks are faithful to Multipli's
documented interfaces and let us embed vulns *unsignposted* so the agent has to find them like an auditor would.
We ran the real-contract recon anyway and reported the honest "no applicable surface on Base" result.

**7. What's your false-positive evidence?**
For v1, we're blunt: the "0 false positives at a 15.9% threshold" number is **vacuous**. The benign exchange
rate never moves off `1e18`, so that threshold is ~10× a rounding artifact, not a fitted bound. For v2 the
validation is real — we measure benign *conversion-ratio* deviation: max observed
<!--NUM:validation_v2.max_observed_bps--> bps, threshold <!--NUM:validation_v2.threshold_bps--> bps,
<!--NUM:validation_v2.false_positives--> false positives over <!--NUM:validation_v2.applicable_traces_checked-->
applicable traces. Every advisory still ships coverage warnings; empirical is not formal proof.

**8. Isn't "$47,000 profit" from a huge donation obviously irrational?**
Yes — and we fixed the framing. The naive PoC (donate <!--NUM:attack.irrational.donation-->, deposit
<!--NUM:attack.irrational.deposit-->) actually nets the attacker <!--NUM:attack.irrational.attacker_net_usd-->,
a loss. Under rational parameters (donate <!--NUM:attack.economics.donation-->, deposit
<!--NUM:attack.economics.deposit--> against a <!--NUM:attack.economics.pool_balance_before--> pool) the attack
nets <!--NUM:attack.economics.attacker_net_usd--> and leaves <!--NUM:attack.economics.bad_debt_usd--> of protocol
bad debt. The profit condition is simple: **the attack pays when the deposit exceeds the pool**, and the attacker
exits via rwaUSD redeemable near $1. We report bad debt, not gross mint.

**9. Vuln B is worth $950K — why isn't that your headline?**
Because Vuln B *under*-prices collateral. It doesn't let an attacker mint unbacked value — attacker profit is
**$0**. It's a depositor-loss finding, and in the mocks there's no liquidation engine to turn it into extractable
profit. Putting it in an attack headline would be dishonest, so we report it as a valuation finding only.

**10. Can the attacker just ride the tolerance?**
Yes — that's our top residual risk and we list it. The chokepoint allows over-crediting up to `TOLERANCE_BPS`, so
an attacker keeping each credit just under tolerance can extract value slowly. The tolerance trades off against
benign false positives; it's a tunable, not a hard zero. That's exactly why we recommend the formula fix
*alongside* the guard, and staleness/divergence PriceGuards under it.

**11. Doesn't v2 just move trust to the raw feed?**
Correct. v2 anchors to the independent USD-per-token feed, so if *that* feed is manipulated or stale the anchor
moves with it. Feed integrity is the PriceGuard layer's job (staleness, divergence) — v2 assumes it and doesn't
re-implement it. We say this in the limitations, and it's why we frame v2 as one layer, not a silver bullet.

**12. How would a protocol actually deploy this?**
It matches the emergency-role / timelock / vote model. **Immediate mitigation** is tighten-only via the emergency
role — conservative pause profile, cut the mint cap — which loosens nothing and needs no timelock. The
**permanent fix** is the guard shipped as a code change through the governance timelock. And we recommend the
**root-cause formula fix** (credit shares×price-per-share) alongside it. Every advisory carries that Governance
Path section, plus an Economics block, a v1→v2 history, and residual risks.

---

## Landmines to avoid on stage
- Don't say "novel", "first", or "nobody" — say "our contribution".
- Don't quote a pipeline number from memory — the deck reads them from state files.
- Don't call Multipli vulnerable. Say "we injected the bug to study the guard class."
- Don't headline Vuln B as attack impact. It's depositor loss, attacker profit $0.
- If asked for the profit figure, give it with the bad-debt framing and the deposit>pool condition.
