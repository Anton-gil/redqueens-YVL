#!/usr/bin/env bash
# Red Queen end-to-end demo — deterministic, offline, NO API keys. Runs in well under 3 minutes.
set -e
export PATH="$PATH:$HOME/.foundry/bin:/home/anton/.foundry/bin"
cd "$(dirname "$0")"

echo "=================================================================="
echo " Red Queen — attack -> synthesize -> validate -> bypass -> advise"
echo "=================================================================="

echo; echo "[1/3] PROOFS: forge test (contracts, exploits, v2 guard, bypass suites, validation)"
forge test

echo; echo "[2/3] BYPASS ANALYSIS (verdicts from executed forge; v1 vs v2)"
python3 -m synthesis.bypass

echo; echo "[3/3] ITERATION SUMMARY (from orchestrator/state/state.json)"
python3 - <<'PY'
import json
s = json.load(open("orchestrator/state/state.json"))
print("  headline:", s.get("headline"))
for it in s["iterations"]:
    print("  %-3s | %-40s | scope=%-28s | bypassed=%d blocked=%d"
          % (it["version"], it["guard_class"], it["scope"], it["n_bypassed"], it["n_blocked"]))
e = s["economics"]
print("  attacker net (rational): $%s | bad debt: $%s | condition: %s"
      % (f"{int(e['attacker_net_usd']):,}", f"{int(e['bad_debt_usd']):,}", e["profit_condition"]))
print("  Vuln B:", s["vuln_b"]["classification"], "depositor_loss $%s, attacker_profit $%d"
      % (f"{int(s['vuln_b']['depositor_loss_usd']):,}", s["vuln_b"]["attacker_profit_usd"]))
PY

echo; echo "Done. Open frontend/index.html in a browser (it polls orchestrator/state/state.json)."
