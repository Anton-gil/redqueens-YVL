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

# Candidate locations for the Foundry bin dir, across the machines this has run on.
# Overridable with FOUNDRY_BIN env var. First existing dir wins; the WSL/original path is kept
# last so the repo still runs unchanged there.
_FOUNDRY_BIN_CANDIDATES = [
    os.environ.get("FOUNDRY_BIN", ""),
    os.path.join(os.path.expanduser("~"), ".foundry", "bin"),
    "/home/anton/.foundry/bin",
]
FOUNDRY_BIN = next((p for p in _FOUNDRY_BIN_CANDIDATES if p and os.path.isdir(p)),
                   os.path.join(os.path.expanduser("~"), ".foundry", "bin"))


# Common misspellings mapped to the canonical env var the code + SDKs expect.
_ENV_ALIASES = {"OPEN_AI_KEY": "OPENAI_API_KEY", "OPENAI_KEY": "OPENAI_API_KEY",
                "ANTHROPIC_KEY": "ANTHROPIC_API_KEY", "CLAUDE_API_KEY": "ANTHROPIC_API_KEY",
                "GROQ_KEY": "GROQ_API_KEY", "GROK_API_KEY": "GROQ_API_KEY"}


def _load_dotenv():
    # Search the repo root first, then its parent (e.g. red/.env). NOT the home dir — avoid slurping
    # unrelated home secrets. First value for a key wins (setdefault).
    for env_path in (PROJECT_ROOT / ".env", PROJECT_ROOT.parent / ".env"):
        if not env_path.exists():
            continue
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            os.environ.setdefault(k, v)
            if k in _ENV_ALIASES:
                os.environ.setdefault(_ENV_ALIASES[k], v)


def ensure_foundry_on_path():
    """Make forge/cast/anvil discoverable to subprocess regardless of how Python was launched."""
    if FOUNDRY_BIN not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{os.environ.get('PATH','')}:{FOUNDRY_BIN}"


_load_dotenv()
ensure_foundry_on_path()

# --- Cost / safety guards (kept from the v2 plan) ---
MAX_TOOL_CALLS_PER_PATTERN = 8      # conservative: caps LLM round-trips per pattern
MAX_OUTPUT_TOKENS_PER_CALL = 2048   # conservative output cap per call
TOTAL_BUDGET_USD = float(os.environ.get("RED_QUEEN_BUDGET_USD", "2.00"))
PATTERN_TIMEOUT_SECONDS = 300          # 5-minute kill switch per pattern
FORK_EXEC_TIMEOUT_SECONDS = 60         # forge test per PoC
MAX_RETRIES_PER_PATTERN = 5

# --- LLM ---
# Two providers supported. If OPENAI_API_KEY is set it takes precedence (the OpenAI tool-calling
# agent runs); else ANTHROPIC_API_KEY runs the Claude agent; else the deterministic FallbackAgent.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ATTACK_MODEL = os.environ.get("RED_QUEEN_ATTACK_MODEL", "claude-sonnet-5")
# Conservative + cheap by default: gpt-4o-mini is more than enough for playbook-driven tool-calling
# and costs a fraction of the larger models. Override with RED_QUEEN_OPENAI_MODEL if needed.
OPENAI_MODEL = os.environ.get("RED_QUEEN_OPENAI_MODEL", "gpt-4o-mini")

# --- Autonomous agent (OpenAI client -> Hugging Face router -> DeepSeek-R1 via Novita) ---
# A separate, open-ended attack agent (agent/hf_agent.py): given the full target context and all six
# tools, it drives its own recon -> hypothesis -> PoC -> exploit loop rather than following the
# per-pattern playbook. Uses the OpenAI SDK against HF's OpenAI-compatible router.
HF_TOKEN = os.environ.get("HF_TOKEN", "") or os.environ.get("HUGGINGFACE_API_KEY", "")
HF_BASE_URL = os.environ.get("HF_BASE_URL", "https://router.huggingface.co/v1")
HF_MODEL = os.environ.get("HF_MODEL", "deepseek-ai/DeepSeek-R1:novita")
# DeepSeek-R1 (a reasoning model) does native OpenAI tool-calling unreliably on Novita - it degrades
# to emitting tool calls as free text - so the default is a strict JSON text-protocol, which R1 drives
# reliably. Set RED_QUEEN_HF_MODE=native to force the OpenAI function-calling path instead.
HF_TOOL_MODE = os.environ.get("RED_QUEEN_HF_MODE", "text")
MAX_AUTONOMOUS_ITERATIONS = int(os.environ.get("RED_QUEEN_MAX_ITERS", "24"))
AUTONOMOUS_RUN_TIMEOUT_SECONDS = int(os.environ.get("RED_QUEEN_AUTON_TIMEOUT", "1200"))


def has_hf():
    return bool(HF_TOKEN)


# --- Autonomous agent backend: Groq preferred (reliable native tool-calling + generous free tier) ---
# Groq is OpenAI-compatible; unlike DeepSeek-R1 on the HF router it drives native function-calling
# reliably. When GROQ_API_KEY is set it takes precedence over HF for the autonomous agent.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

# NVIDIA NIM (build.nvidia.com) — OpenAI-compatible, generous free credits, and (verified) does
# reliable NATIVE tool-calling with nemotron-3-ultra, unlike the HF-router reasoning models.
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")


def has_autonomous():
    return bool(NVIDIA_API_KEY or GROQ_API_KEY or HF_TOKEN)


def autonomous_endpoint():
    """Resolve the autonomous-agent backend as a dict, or None. NVIDIA NIM first (verified native
    tool-calling), then Groq, then the HF router."""
    if NVIDIA_API_KEY:
        return {"api_key": NVIDIA_API_KEY, "base_url": NVIDIA_BASE_URL, "model": NVIDIA_MODEL,
                "tool_mode": os.environ.get("RED_QUEEN_NVIDIA_MODE", "native"), "label": "nvidia"}
    if GROQ_API_KEY:
        return {"api_key": GROQ_API_KEY, "base_url": GROQ_BASE_URL, "model": GROQ_MODEL,
                "tool_mode": os.environ.get("RED_QUEEN_GROQ_MODE", "native"), "label": "groq"}
    if HF_TOKEN:
        return {"api_key": HF_TOKEN, "base_url": HF_BASE_URL, "model": HF_MODEL,
                "tool_mode": HF_TOOL_MODE, "label": "hf"}
    return None

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


def llm_provider():
    """Which LLM backend the attack agent should use, or None for the deterministic fallback."""
    if OPENAI_API_KEY:
        return "openai"
    if ANTHROPIC_API_KEY:
        return "anthropic"
    return None


def has_llm():
    return bool(OPENAI_API_KEY or ANTHROPIC_API_KEY)
