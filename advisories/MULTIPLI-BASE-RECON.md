# Multipli — Real-Contract Advisory Run (Base)

**Mode:** advisory-only, read-only (no deploy, no state mutation)  
**Chain:** Base (chain-id 8453)  
**RPC:** https://mainnet.base.org  
**Source of addresses:** https://docs.multipli.fi/technical-architecture/rwausd-contract-addresses.md  
**Verified source:** Blockscout (https://base.blockscout.com/api), keyless

## Inspected contracts

| Address | Label | Deployed | Bytecode | Verified name | Proxy → impl |
| --- | --- | --- | --- | --- | --- |
| `0x272Ec977f4575df41cD47b1b254954E1C7972789` | rwaUSD Token (Base) | yes | 176 B | ERC1967Proxy | 0xe1824bf952bb2e8414d12de8a9fc2cbc666d6758 (rwaUSD) |
| `0x7Dc0496016d88c3EbA6d54D1514F24B3C9872894` | CCIP BurnMintPool (Base) | yes | 16134 B | BurnMintTokenPool | — |

## Structural surface found

Union of structural flags across all inspected source: `(none of the playbook-relevant surfaces)`

## Playbook pattern evaluation

| Pattern | Required surface | Verdict |
| --- | --- | --- |
| `adapter_donation` | has_exchangeRate, rate_reads_pool_balance | not applicable — required surface not found in inspected source |
| `unit_composition_error` | has_rebase_multiplier, has_getPrice | not applicable — required surface not found in inspected source |
| `stale_price_multicall` | has_multicall_depositAndMint, price_passed_in_not_rederived | not applicable — required surface not found in inspected source |

## Result

**No exploitable pattern within the checked classes** on Multipli's Base-deployed set. The inspected contracts do not expose the adapter conversion / oracle composition / stale-multicall surfaces the RWA playbook probes. This is a legitimate result, not a failure — see coverage below for what that does and does not establish.

## Inspection coverage (what was and wasn't checked)

- Inspected 2 contract(s) actually published for Base by Multipli (rwaUSD token proxy + CCIP bridge pool). Deployment and bytecode confirmed on-chain via `cast code`.
- Verified source pulled from Blockscout (keyless); ERC1967 proxies resolved to their EIP-1967 implementation and that source reconned too.
- NOT covered: Multipli's full protocol (Vat/Spotter/Jug/GemJoin/Clipper adapters, price feeds) is deployed on ETHEREUM as a MakerDAO fork, not on Base — a different architecture from the v2 adapter suite this playbook's patterns target. Running those patterns against a Maker-fork would require Ethereum RPC access and patterns tuned to Vat/urn accounting.
- This run checks STRUCTURAL preconditions only (does the adapter-donation / multiplier / stale-multicall surface exist in verified source). It does not execute PoCs against mainnet and makes no claim about economic exploitability of contracts outside the checked classes.
