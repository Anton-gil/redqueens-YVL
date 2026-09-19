# Claims Audit — Red Queen

One row per factual claim that appears (or appeared) in `README.md` and `idea.md` (with a few from
`implementation.md`). Verdict is one of **VERIFIED** (kept, with a source URL), **SOFTENED** (kept but the
precise/unverifiable part was weakened), or **DELETED** (removed from files we own; flagged for the lead to
remove anywhere else).

Pipeline metrics in `README.md` / `PITCH_NOTES.md` are **not** in this table: they are written as
`<!--NUM:...-->` markers and are sourced from `orchestrator/state/*.json` at build time, not asserted as prose.

Audited by Agent F (Docs & Claims). Incident facts cross-checked against the sources below on 2026-09-20.

## External incident claims

| Claim | Where | Verdict | Source / note |
| --- | --- | --- | --- |
| Edel Finance, **Jul 1 2026**, wGOOGLx exchange-rate manipulation inflated collateral **~78×**, **~$403K** bad debt; Chainlink price was correct, the wrapper rate was the flaw. | README §3 (Vuln A ref); idea.md incident 2 | **VERIFIED** | CoinDesk 2026-07-01 <https://www.coindesk.com/tech/2026/07/01/tokenized-google-stock-inflated-7-700-in-rare-defi-lending-exploit>; Edel Finance statement <https://x.com/edeldotfinance/status/2072154468058022033> (wGOOGLx/GOOGLx rate, ~78×). |
| Moonwell, **Feb 2026**, **MIP-X43**: cbETH priced via **raw cbETH/ETH** feed instead of composing with ETH/USD → cbETH valued ~$1.12 vs ~$2,200; **~$1.78M** bad debt. | README §3 (Vuln B ref); idea.md incident 1 | **VERIFIED** | Moonwell governance forum, MIP-X43 incident summary <https://forum.moonwell.fi/t/mip-x43-cbeth-oracle-incident-summary/2068>; The Block <https://www.theblock.co/post/390302/defi-lending-protocol-moonwell-hit-with-1-8-million-bad-debt-after-oracle-misconfiguration>. Note: reporting dates the execution Feb 15–16 2026; idea.md said "Feb 2026" — consistent. |
| Stream Finance, **Nov 4 2025**, **$93M** loss; **~$285M** cascading contagion across Euler/Morpho/Silo/Gearbox; xUSD depeg ~77–90%. | idea.md incident 3 | **VERIFIED** | BlockEden "$285M DeFi Contagion" <https://blockeden.xyz/blog/2025/11/08/m-defi-contagion/>; QuillAudits <https://x.com/QuillAudits_AI/status/1986377632926273796>. ($93M loss and $285M contagion figure both corroborated.) |
| KelpDAO cross-chain release cost **$292M**; **116,500 rsETH = 74% of the bridge's escrow** released on a message that never existed. | idea.md §problem + invariant-class 3; implementation.md playbook | **SOFTENED** → "~$290M" | Magnitude corroborated as a major 2026 incident (~$290M) per H1-2026 roundup, The Block <https://www.theblock.co/news/ecosystems/2026-07-28-crypto-hacks-hit-record-high-in-h1-2026-as-losses-top-1-billion-blockaid-says-409944>. Exact $292M, the 116,500 rsETH figure and the "74% of escrow" breakdown were **not** independently verified; specifics removed, month claim ("April 2026") also softened. |
| "DeFi protocols lost over **$1 billion in H1 2026 across 212 confirmed exploits**, most-hacked half-year on record." | idea.md §problem; implementation.md pitch | **SOFTENED** | Magnitude and "record half-year" corroborated but sources disagree on the exact figure: Immunefi ~$972M/207 incidents; CertiK ~$1.3B; Onchain Lens ~$1.32B/224. Rewritten to "topped a billion dollars across 200-plus incidents (~$1.0B–$1.3B by methodology)". The precise "212" is unsupported. Source: The Block/Blockaid (above); Immunefi <https://www.theblock.co/news/ecosystems/2026-07-09-crypto-hack-losses-fall-below-1-billion-in-h1-2026-even-as-attack-volume-hits-record-immunefi-407707>. |

## Tooling / academic claims

| Claim | Where | Verdict | Source / note |
| --- | --- | --- | --- |
| "Trace2Inv blocked **23 of 27** historical exploits with a **0.28%** false-positive rate." | idea.md §"why existing tools" | **SOFTENED** | Trace2Inv is a real tool; the exact 23/27 and 0.28% figures were not independently re-verified for this audit. Precise numbers removed; qualitative claim ("strong on curated exploit sets") retained. |
| "The **August 2026 InvariantEval** paper found automated tools recovered only **2 of 2,828** ground-truth invariants at scale." | idea.md §"why existing tools" | **SOFTENED** | Could not independently locate/verify the paper or the 2/2,828 figure. Specific numbers removed; qualitative "does not yet scale to arbitrary protocols" retained. Flag for lead if a citation exists. |
| A1 63% benchmark; EvoPoC 96.6%; Phylax/SphereX/CrossGuard in production; RvB paper (Jan 2026). | idea.md §"why existing tools" / §"what it is NOT" | **SOFTENED (not re-verified)** | Left in place as background; not load-bearing to any Red Queen result. Not independently verified in this audit; no superiority claim attached, so low risk. Recommend the lead cite or drop if challenged. |

## Multipli / architecture claims

| Claim | Where | Verdict | Source / note |
| --- | --- | --- | --- |
| Live rwaUSD is a MakerDAO-style fork on **Ethereum** (Vat/Spotter/OSM/GemJoin, PAXG); on **Base** only the token + a CCIP `BurnMintTokenPool`. | README §3a (new) | **VERIFIED** | Our read-only on-chain recon `advisories/MULTIPLI-BASE-RECON.md` (Blockscout-verified bytecode) + docs.multipli.fi contract-addresses page cited therein. |
| Vuln A is a bug **injected into the mocks**; the max-delta guard class already exists in Multipli's documented PriceGuards; **we do not claim Multipli is vulnerable**. | README §3a (new); idea.md §Multipli | **VERIFIED** | Multipli documented v2 design (PriceGuards: max-delta/staleness/divergence); adapters custody-only. This is the corrected framing that replaces the deleted claims below. |
| "Multipli has completed 10 security audits. Those audits **checked the code for bugs. They didn't check the configuration layer**…" | idea.md §Multipli (was line 43) | **DELETED** | Unsupportable and needlessly adversarial toward Multipli. Removed from idea.md and reframed as "runtime complement to point-in-time audits, not a claim about any protocol's audit coverage." No other occurrences found in owned files. |
| "**No published system has** an RWA-specific attack playbook." | idea.md (was line 134) | **DELETED** | Unfalsifiable "nobody" claim. Replaced with "Our contribution here is the RWA-specific attack playbook." |
| Invariant classes "**that don't exist in any published tool** because **no existing tool targets** RWA protocols"; "**No existing tool targets these**." | idea.md (was lines 31, 51, 72) | **DELETED** | Superiority "nobody/no existing tool" clauses removed; replaced with neutral "written specifically for RWA collateral systems" / "not the primary focus of general-purpose tooling." |
| "The **novel** contribution is…"; "**Novel Contribution** 1/2/3"; "the actual **novel** contributions." | README §intro (was line 12); idea.md (was 68/70/99/136); implementation.md (was 245) | **DELETED (rephrased)** | Every "novel/first/nobody" superiority phrasing in owned files replaced with **"our contribution"**. Honest *disclaimers* of novelty ("It's not a novel attack agent", "not the first attack-then-defend loop", "not novel, not claimed to be") were intentionally **kept** — they are the honesty framing, not a claim. |
| "**Nobody** was watching for it in the right way." (Stream Finance) | idea.md (was line 13) | **DELETED (rephrased)** | Reworded to "no deployed monitoring was tuned to act on that specific pattern." |
| "**Nobody** targets RWA." | implementation.md pitch (was line 573) | **DELETED (rephrased)** | Reworded to "targeting RWA-specific failure modes is our contribution." |

## Impact-framing claims

| Claim | Where | Verdict | Source / note |
| --- | --- | --- | --- |
| Vuln B reported as a "$950,000 mispricing" attack finding. | README §6 (old) | **DELETED / reframed** | Vuln B *under*-prices → **depositor-loss**, attacker profit **$0**, no liquidation engine in the mocks. Now stated as a depositor-loss finding and **excluded from attack-impact headlines** (README §3, §6). |
| Vuln A/C impact stated as flat "$46,000 unbacked" / "24× spike"; v1 "15.9% threshold / 0 false positives / 144× over"; guard gas "~11,257 / 8.6%"; "2 real bypasses". | README §6 (old) | **DELETED / reframed to NUM markers** | Replaced with rational-economics + bad-debt framing and `<!--NUM:...-->` markers. The v1 "0 false positives / 15.9%" is called out as **vacuous** (benign rate never moves off 1e18), per F6. |
