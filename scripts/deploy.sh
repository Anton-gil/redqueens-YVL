#!/usr/bin/env bash
#
# Red Queen deployment driver (runs inside WSL2).
#   1. Starts anvil forking Base mainnet at the pinned block on :8545 (reuses one if already up).
#   2. Runs forge script scripts/Deploy.s.sol --broadcast.
#   3. Parses deployed addresses and writes orchestrator/state/deployment.json in the hard-contract
#      schema the Python attack agent parses.
#
# Anvil is left RUNNING after the script finishes so the Python agent can query it.

set -euo pipefail

export PATH="$PATH:/home/anton/.foundry/bin"

# --- Locate project root (scripts/ -> project root) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RPC_URL="http://127.0.0.1:8545"
FORK_URL="https://mainnet.base.org"
FORK_BLOCK="20000000"
PORT="8545"
ANVIL_LOG="/tmp/red-queen-anvil.log"
ANVIL_PID_FILE="/tmp/red-queen-anvil.pid"
# anvil default account 0
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

OUT_DIR="orchestrator/state"
OUT_FILE="$OUT_DIR/deployment.json"
FORGE_LOG="/tmp/red-queen-forge.log"

# --- 1. Start anvil if not already listening on 8545 ---
if cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    echo "[deploy] anvil already listening on $PORT -- reusing it."
else
    echo "[deploy] starting anvil (fork Base @ block $FORK_BLOCK) on port $PORT ..."
    # setsid + nohup fully detaches anvil into its own session so it survives this script exiting.
    setsid nohup anvil \
        --fork-url "$FORK_URL" \
        --fork-block-number "$FORK_BLOCK" \
        --port "$PORT" \
        >"$ANVIL_LOG" 2>&1 &
    echo $! >"$ANVIL_PID_FILE"
    echo "[deploy] anvil PID $(cat "$ANVIL_PID_FILE") (log: $ANVIL_LOG)"

    # Poll until it responds (up to ~30s)
    ready=0
    for i in $(seq 1 30); do
        if cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1; then
            ready=1
            echo "[deploy] anvil ready after ${i}s (block $(cast block-number --rpc-url "$RPC_URL"))."
            break
        fi
        sleep 1
    done
    if [ "$ready" -ne 1 ]; then
        echo "[deploy] ERROR: anvil did not become ready within 30s. See $ANVIL_LOG:" >&2
        tail -n 40 "$ANVIL_LOG" >&2 || true
        exit 1
    fi
fi

# --- 2. Run the deploy script ---
echo "[deploy] running forge script ..."
# --slow sends txs one at a time (waits for each receipt), avoiding the anvil/forge
# "nonce too low" race that can occur when many txs are broadcast back-to-back.
forge script scripts/Deploy.s.sol \
    --broadcast \
    --slow \
    --rpc-url "$RPC_URL" \
    --private-key "$DEPLOYER_KEY" \
    2>&1 | tee "$FORGE_LOG"

# --- 3. Parse deployed addresses from the console output ---
extract() {
    # $1 = label (without trailing '='); prints the first 0x... address on the labelled line.
    grep -E "${1}=" "$FORGE_LOG" | grep -oE '0x[0-9a-fA-F]{40}' | head -1
}

rwaUSDToken=$(extract "rwaUSDToken")
Ledger=$(extract "Ledger")
PriceRouter=$(extract "PriceRouter")
AccountManager=$(extract "AccountManager")
goldToken=$(extract "goldToken")
goldPool=$(extract "goldPool")
goldAdapter=$(extract "goldAdapter")
goldUsdFeed=$(extract "goldUsdFeed")
stockToken=$(extract "stockToken")
stockPool=$(extract "stockPool")
xstockAdapter=$(extract "xstockAdapter")
stockUsdFeed=$(extract "stockUsdFeed")

# --- Validate: every address must be present and non-zero ---
missing=0
for name in rwaUSDToken Ledger PriceRouter AccountManager goldToken goldPool goldAdapter goldUsdFeed stockToken stockPool xstockAdapter stockUsdFeed; do
    val="${!name}"
    if [ -z "$val" ] || [ "$val" = "0x0000000000000000000000000000000000000000" ]; then
        echo "[deploy] ERROR: address for '$name' is missing or zero ('$val')." >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    echo "[deploy] ERROR: could not parse all 12 addresses from forge output. See $FORGE_LOG." >&2
    exit 1
fi

# --- Write deployment.json (hard-contract schema) ---
mkdir -p "$OUT_DIR"
cat >"$OUT_FILE" <<JSON
{
  "network": "base-fork",
  "chain_id": 8453,
  "fork_block": ${FORK_BLOCK},
  "rpc_url": "${RPC_URL}",
  "deployer": "${DEPLOYER_ADDR}",
  "contracts": {
    "rwaUSDToken": "${rwaUSDToken}", "Ledger": "${Ledger}", "PriceRouter": "${PriceRouter}", "AccountManager": "${AccountManager}",
    "goldToken": "${goldToken}", "goldPool": "${goldPool}", "goldAdapter": "${goldAdapter}", "goldUsdFeed": "${goldUsdFeed}",
    "stockToken": "${stockToken}", "stockPool": "${stockPool}", "xstockAdapter": "${xstockAdapter}", "stockUsdFeed": "${stockUsdFeed}"
  },
  "adapters": {
    "goldAdapter":  {"kind": "GOLD",   "token": "${goldToken}", "pool": "${goldPool}", "usdFeed": "${goldUsdFeed}"},
    "xstockAdapter":{"kind": "XSTOCK", "token": "${stockToken}", "pool": "${stockPool}", "usdFeed": "${stockUsdFeed}"}
  }
}
JSON

echo "[deploy] wrote $OUT_FILE"
echo "[deploy] anvil is still running on $PORT (PID: $(cat "$ANVIL_PID_FILE" 2>/dev/null || echo 'reused/unknown'))."
echo "[deploy] done."
