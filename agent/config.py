"""Red Queen attack-agent configuration.

Runs inside WSL (Foundry lives there). Centralizes paths, the Foundry-on-PATH fixup so every
subprocess call finds forge/cast/anvil, cost/safety guards, and .env loading.
"""

import os
from pathlib import Path

# agent/ -> project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

SRC_DIR = PROJECT_ROOT / "src"
TEST_DIR = PROJECT_ROOT / "test"
PLAYBOOK_PATH = PROJECT_ROOT / "playbook" / "rwa_attack_playbook.yaml"
STATE_DIR = PROJECT_ROOT / "orchestrator" / "state"
DEPLOYMENT_PATH = STATE_DIR / "deployment.json"
LOGS_DIR = PROJECT_ROOT / "logs"

FOUNDRY_BIN = "/home/anton/.foundry/bin"


def _load_dotenv():
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def ensure_foundry_on_path():
    """Make forge/cast/anvil discoverable to subprocess regardless of how Python was launched."""
    if FOUNDRY_BIN not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{os.environ.get('PATH','')}:{FOUNDRY_BIN}"


_load_dotenv()
ensure_foundry_on_path()

# --- Cost / safety guards (kept from the v2 plan) ---
MAX_TOOL_CALLS_PER_PATTERN = 15
MAX_OUTPUT_TOKENS_PER_CALL = 4096
TOTAL_BUDGET_USD = float(os.environ.get("RED_QUEEN_BUDGET_USD", "2.00"))
PATTERN_TIMEOUT_SECONDS = 300          # 5-minute kill switch per pattern
FORK_EXEC_TIMEOUT_SECONDS = 60         # forge test per PoC
MAX_RETRIES_PER_PATTERN = 5

# --- LLM ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ATTACK_MODEL = os.environ.get("RED_QUEEN_ATTACK_MODEL", "claude-sonnet-5")

# Rough per-token USD prices for the budget guard (input, output). Deliberately conservative;
# the guard is a runaway-bill kill switch, not accounting.
MODEL_PRICE_PER_MTOK = {
    "input": float(os.environ.get("RED_QUEEN_PRICE_IN", "3.0")),
    "output": float(os.environ.get("RED_QUEEN_PRICE_OUT", "15.0")),
}

# --- Fork / RPC ---
DEFAULT_RPC_URL = os.environ.get("RED_QUEEN_RPC_URL", "http://127.0.0.1:8545")
FORK_BLOCK_NUMBER = int(os.environ.get("FORK_BLOCK_NUMBER", "20000000"))

# Anvil account 0 (deterministic dev key) — used for cast sends against the local fork only.
DEV_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def has_llm():
    return bool(ANTHROPIC_API_KEY)
