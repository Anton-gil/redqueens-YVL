"""Real Multipli target recon — advisory-only, read-only, no deploy, no mocks.

This is the Section 4.3 "Real Multipli Contract Run." It pulls Multipli's ACTUAL deployed contracts
on Base and runs the playbook's structural precondition checks against their VERIFIED on-chain
source. Everything here is grounded in real sources — nothing is fabricated:

  * Addresses come from Multipli's own docs:
    https://docs.multipli.fi/technical-architecture/rwausd-contract-addresses.md
  * Deployment is confirmed on-chain via `cast code` against a public Base RPC (keyless).
  * Verified source is pulled from Blockscout's public API (keyless). Proxies are resolved to their
    EIP-1967 implementation and that source is reconned too.

Honest scope (stated plainly in the report): on Base, Multipli publishes only the rwaUSD token
(an ERC1967 proxy) and a CCIP bridge pool. The full adapter / ledger / price-router suite the RWA
playbook targets is NOT deployed on Base — the complete protocol lives on Ethereum as a MakerDAO
fork (Vat/Spotter/Jug/Clipper…), a different architecture from the v2 "contract suite" our mocks
model. So a Base run is expected to find no adapter-pattern surface; that is a legitimate,
reportable outcome, and the report says exactly what was and wasn't inspectable.
"""

import json
import os
import re
import subprocess

from agent import config
from agent import tools

config.ensure_foundry_on_path()

BASE_RPC = os.environ.get("BASE_RPC_URL") or "https://mainnet.base.org"      # public, keyless
BLOCKSCOUT = os.environ.get("BASE_BLOCKSCOUT_API") or "https://base.blockscout.com/api"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Real, published Multipli Base deployments (docs contract-addresses page). Override with the
# MULTIPLI_TARGET_ADDRESSES env var (comma-separated 0x addresses) for a custom target set.
DEFAULT_TARGETS = [
    {"address": "0x272Ec977f4575df41cD47b1b254954E1C7972789", "label": "rwaUSD Token (Base)"},
    {"address": "0x7Dc0496016d88c3EbA6d54D1514F24B3C9872894", "label": "CCIP BurnMintPool (Base)"},
]

# Playbook pattern -> the structural flags its preconditions require (mirrors
# agent.attacker._PATTERN_IMPL, made chain-agnostic so it matches real source the same way).
_PATTERN_FLAGS = {
    "adapter_donation": ["has_exchangeRate", "rate_reads_pool_balance"],
    "unit_composition_error": ["has_rebase_multiplier", "has_getPrice"],
    "stale_price_multicall": ["has_multicall_depositAndMint", "price_passed_in_not_rederived"],
}


def _cast(args, timeout=40):
    p = subprocess.run(["cast"] + args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _code_size(addr):
    rc, out, _ = _cast(["code", addr, "--rpc-url", BASE_RPC])
    if rc != 0 or not out.startswith("0x"):
        return 0
    return (len(out) - 2) // 2


def _blockscout_source(addr):
    # Use curl (system CA bundle) rather than urllib: on some hosts Python's SSL has no local CA
    # store and urllib fails cert verification while curl succeeds.
    url = "%s?module=contract&action=getsourcecode&address=%s" % (BLOCKSCOUT, addr)
    try:
        p = subprocess.run(["curl", "-fsS", "--max-time", "30", url],
                           capture_output=True, text=True, timeout=35)
        if p.returncode != 0 or not p.stdout.strip():
            return {"ok": False, "error": (p.stderr or "empty response").strip()[:200]}
        data = json.loads(p.stdout)
    except Exception as e:  # noqa: BLE001 - network best-effort; recon degrades to bytecode-only
        return {"ok": False, "error": str(e)}
    res = (data.get("result") or [{}])[0]
    src = res.get("SourceCode") or ""
    return {
        "ok": bool(src),
        "name": res.get("ContractName") or None,
        "source": src,
        "verified": bool(src),
    }


def _resolve_impl(addr):
    """EIP-1967 implementation slot -> impl address (or None if not a standard proxy)."""
    rc, out, _ = _cast(["storage", addr, EIP1967_IMPL_SLOT, "--rpc-url", BASE_RPC])
    if rc != 0 or not out.startswith("0x") or len(out) < 42:
        return None
    impl = "0x" + out[-40:]
    if int(impl, 16) == 0:
        return None
    return impl


def _functions(src):
    sigs = re.findall(r"function\s+(\w+)\s*\(([^)]*)\)", src or "")
    return ["%s(%s)" % (n, a.strip()) for n, a in sigs]


def recon_target(t):
    addr, label = t["address"], t["label"]
    size = _code_size(addr)
    rec = {"address": addr, "label": label, "deployed": size > 0, "bytecode_bytes": size,
           "verified": False, "contract_name": None, "proxy_impl": None, "impl_name": None,
           "structural_flags": [], "functions": []}
    if size == 0:
        rec["note"] = "no code at address on Base"
        return rec

    top = _blockscout_source(addr)
    rec["verified"] = top.get("verified", False)
    rec["contract_name"] = top.get("name")
    combined_src = top.get("source", "") or ""

    impl = _resolve_impl(addr)
    if impl:
        rec["proxy_impl"] = impl
        impl_src = _blockscout_source(impl)
        rec["impl_name"] = impl_src.get("name")
        rec["impl_verified"] = impl_src.get("verified", False)
        combined_src += "\n" + (impl_src.get("source", "") or "")

    rec["structural_flags"] = tools._structural_flags(combined_src)
    rec["functions"] = _functions(combined_src)[:60]
    return rec


def evaluate_patterns(union_flags):
    out = []
    for name, req in _PATTERN_FLAGS.items():
        missing = [f for f in req if f not in union_flags]
        out.append({
            "pattern": name,
            "required_flags": req,
            "missing_flags": missing,
            "applicable": len(missing) == 0,
            "verdict": ("surface present — would attempt PoC" if not missing
                        else "not applicable — required surface not found in inspected source"),
        })
    return out


def _render_report(summary):
    L = []
    L.append("# Multipli — Real-Contract Advisory Run (Base)")
    L.append("")
    L.append("**Mode:** advisory-only, read-only (no deploy, no state mutation)  ")
    L.append("**Chain:** Base (chain-id 8453)  ")
    L.append("**RPC:** %s  " % BASE_RPC)
    L.append("**Source of addresses:** https://docs.multipli.fi/technical-architecture/rwausd-contract-addresses.md  ")
    L.append("**Verified source:** Blockscout (%s), keyless" % BLOCKSCOUT)
    L.append("")
    L.append("## Inspected contracts")
    L.append("")
    L.append("| Address | Label | Deployed | Bytecode | Verified name | Proxy → impl |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for r in summary["targets"]:
        proxy = ("%s (%s)" % (r["proxy_impl"], r.get("impl_name") or "?")) if r.get("proxy_impl") else "—"
        L.append("| `%s` | %s | %s | %s B | %s | %s |" % (
            r["address"], r["label"], "yes" if r["deployed"] else "NO",
            r["bytecode_bytes"], r.get("contract_name") or ("(unverified)" if r["deployed"] else "—"), proxy))
    L.append("")
    L.append("## Structural surface found")
    L.append("")
    L.append("Union of structural flags across all inspected source: `%s`" %
             (", ".join(summary["union_flags"]) or "(none of the playbook-relevant surfaces)"))
    L.append("")
    L.append("## Playbook pattern evaluation")
    L.append("")
    L.append("| Pattern | Required surface | Verdict |")
    L.append("| --- | --- | --- |")
    for p in summary["pattern_eval"]:
        L.append("| `%s` | %s | %s |" % (p["pattern"], ", ".join(p["required_flags"]), p["verdict"]))
    L.append("")
    L.append("## Result")
    L.append("")
    L.append(summary["headline"])
    L.append("")
    L.append("## Inspection coverage (what was and wasn't checked)")
    L.append("")
    for c in summary["coverage"]:
        L.append("- %s" % c)
    L.append("")
    return "\n".join(L)


def run(targets=None):
    env_addrs = os.environ.get("MULTIPLI_TARGET_ADDRESSES", "").strip()
    if targets is None and env_addrs:
        targets = [{"address": a.strip(), "label": "env-supplied"} for a in env_addrs.split(",") if a.strip()]
    targets = targets or DEFAULT_TARGETS

    recons = [recon_target(t) for t in targets]
    union = sorted({f for r in recons for f in r["structural_flags"]})
    pattern_eval = evaluate_patterns(union)
    applicable = [p for p in pattern_eval if p["applicable"]]

    if applicable:
        headline = ("**Surface found for %d playbook pattern(s)** on the inspected Base set: %s. "
                    "A full PoC attempt against these real contracts is the next step." %
                    (len(applicable), ", ".join(p["pattern"] for p in applicable)))
    else:
        headline = ("**No exploitable pattern within the checked classes** on Multipli's Base-deployed "
                    "set. The inspected contracts do not expose the adapter conversion / oracle "
                    "composition / stale-multicall surfaces the RWA playbook probes. This is a "
                    "legitimate result, not a failure — see coverage below for what that does and "
                    "does not establish.")

    coverage = [
        "Inspected %d contract(s) actually published for Base by Multipli (rwaUSD token proxy + CCIP "
        "bridge pool). Deployment and bytecode confirmed on-chain via `cast code`." % len(recons),
        "Verified source pulled from Blockscout (keyless); ERC1967 proxies resolved to their EIP-1967 "
        "implementation and that source reconned too.",
        "NOT covered: Multipli's full protocol (Vat/Spotter/Jug/GemJoin/Clipper adapters, price "
        "feeds) is deployed on ETHEREUM as a MakerDAO fork, not on Base — a different architecture "
        "from the v2 adapter suite this playbook's patterns target. Running those patterns against a "
        "Maker-fork would require Ethereum RPC access and patterns tuned to Vat/urn accounting.",
        "This run checks STRUCTURAL preconditions only (does the adapter-donation / multiplier / "
        "stale-multicall surface exist in verified source). It does not execute PoCs against mainnet "
        "and makes no claim about economic exploitability of contracts outside the checked classes.",
    ]

    summary = {
        "chain": "base", "chain_id": 8453, "rpc": BASE_RPC,
        "address_source": "https://docs.multipli.fi/technical-architecture/rwausd-contract-addresses.md",
        "targets": recons, "union_flags": union, "pattern_eval": pattern_eval,
        "applicable_patterns": [p["pattern"] for p in applicable],
        "headline": headline, "coverage": coverage,
    }

    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    (config.STATE_DIR / "multipli_run.json").write_text(json.dumps(summary, indent=2))
    report_path = config.PROJECT_ROOT / "advisories" / "MULTIPLI-BASE-RECON.md"
    report_path.write_text(_render_report(summary))
    summary["report_path"] = str(report_path)
    return summary


def main():
    print("Pulling real Multipli contracts on Base (read-only) ...")
    s = run()
    print("=" * 70)
    for r in s["targets"]:
        print("  %-22s %s  deployed=%s  name=%s  impl=%s  flags=%s" % (
            r["label"], r["address"], r["deployed"], r.get("contract_name"),
            r.get("impl_name") or "-", r["structural_flags"] or "-"))
    print("-" * 70)
    for p in s["pattern_eval"]:
        print("  [%-22s] %s" % (p["pattern"], p["verdict"]))
    print("-" * 70)
    print(s["headline"])
    print("\njson  -> orchestrator/state/multipli_run.json")
    print("report-> %s" % s["report_path"])


if __name__ == "__main__":
    main()
