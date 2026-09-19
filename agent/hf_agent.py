"""Autonomous attack agent: OpenAI client -> Hugging Face router -> DeepSeek-R1 (Novita).

Unlike the per-pattern FallbackAgent/LLMAgent in attacker.py, this agent is open-ended: it is handed
the full target context and all six Foundry tools, and drives its OWN recon -> hypothesis ->
PoC -> exploit loop to discover vulnerabilities. It talks to DeepSeek-R1 through Hugging Face's
OpenAI-compatible router using the openai SDK.

Robustness: DeepSeek-R1 is a reasoning model and providers vary in native tool-calling support, so
this runs native OpenAI function-calling when available and automatically falls back to a strict
JSON text-protocol (the model emits one action object per turn) when the endpoint rejects `tools`.
Either way the model reaches the same six tools via tools.dispatch().
"""

import json
import re
import time

from openai import OpenAI

from . import config, tools

config.ensure_foundry_on_path()


def _safe_dispatch(name, args):
    try:
        return tools.dispatch(name, args)
    except Exception as e:  # a bad tool call must not abort the whole run
        return {"ok": False, "summary": "tool %s errored: %s" % (name, str(e)[:200])}


def _openai_tool_schemas():
    return [{"type": "function",
             "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools.TOOL_SCHEMAS]


def _target_context():
    dep = tools.load_deployment()
    contracts = dep.get("contracts", {})
    lines = ["Deployed target system (RWA stablecoin protocol) on a Base fork:"]
    for name, addr in contracts.items():
        lines.append("  - %s @ %s" % (name, addr))
    if not contracts:
        lines.append("  (no live deployment.json; use contract NAMES with the tools, e.g. 'goldAdapter')")
    return "\n".join(lines)


SYSTEM_PROMPT = """You are Red Queen, an autonomous smart-contract exploit agent auditing an RWA \
(real-world-asset) stablecoin protocol. Your job is to FIND VULNERABILITIES by writing and running \
real exploit transactions on a forked chain, then report them honestly.

The protocol has six contracts:
- rwaUSDToken: the stablecoin; mint/burn gated to the Ledger.
- Ledger: tracks locked collateral shares and mintable `principal` per account.
- AccountManager: user entry point - deposit(adapter, amount), mint(amount), and a multicall \
depositAndMint(adapter, amount).
- PriceRouter: getPrice(adapter) composes feeds into a USD price per adapter share.
- GoldAdapter: exchangeRate() derives a share price from a reserve pool balance.
- xStockAdapter: a tokenized-equity adapter with a rebase/corporate-action multiplier.

You have six tools. Use them:
- decompile(target): read a contract's function signatures + structural flags (by name, e.g. 'goldAdapter').
- price_query(adapter): live getPrice() and exchangeRate().
- storage_read(target, slot): raw storage.
- trace(tx_hash): replay a tx.
- compile_and_validate(solidity_code): check a Solidity snippet compiles.
- fork_and_execute(exploit_body): THE KEY TOOL. Provide the BODY of a Solidity testExploit() function. \
It is wrapped in a contract inheriting a Setup test fixture, so you can use these already-deployed \
objects directly: accountManager, goldAdapter, xstockAdapter, goldToken, stockToken, goldPool, \
stockPool, token (the rwaUSD token), ledger, priceRouter, admin, plus Foundry's vm and console2. \
You can mint yourself collateral for free (goldToken.mint(addr, amt)) as a flash-loan stand-in. \
Approve the ADAPTER (not accountManager) before depositing. End your body with require(...) assertions \
that PASS only if the exploit succeeded, and console2.log("PROFIT_USD", <uint 1e18-scaled>) to report \
the unbacked value minted (rwaUSD minted beyond fair collateral value = protocol bad debt).

Strategy: recon the adapters and the price path with decompile/price_query, form a hypothesis about \
how the recorded value can diverge from the true collateral value (oracle/rate manipulation, stale \
reads, multicall boundaries, composition/multiplier errors), then write a fork_and_execute PoC and \
iterate on revert reasons. A confirmed exploit is one where fork_and_execute returns passed=true with \
a positive PROFIT_USD. When you have found what you can, give a final written report of the \
vulnerabilities, their PoCs, and the honest dollar impact. Do not overstate: if a donation costs more \
than it yields, report the finding as unbacked-mint / bad-debt, not net attacker profit."""

TASK_PROMPT = """Autonomously test this system and find its vulnerabilities. %s

Begin recon now, then produce at least one confirmed fork_and_execute exploit. Iterate as needed \
(you have a bounded number of tool calls). Finish with a concise report of every vulnerability you \
confirmed, each with its impact."""


class HFDeepSeekAgent:
    name = "hf-deepseek-r1"

    def __init__(self):
        if not config.HF_TOKEN:
            raise RuntimeError("HF_TOKEN not set (put it in .env or the environment)")
        self.client = OpenAI(base_url=config.HF_BASE_URL, api_key=config.HF_TOKEN)
        self.model = config.HF_MODEL
        self.tool_calls = []
        self.reasoning_log = []
        self.confirmed = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}

    # --- shared helpers ---
    def _log(self, msg):
        self.reasoning_log.append(msg)

    def _record_tool(self, name, args, result):
        self.tool_calls.append({"name": name, "input": args,
                                "summary": result.get("summary", ""), "ok": result.get("ok", False),
                                "ts": time.time()})
        if name == "fork_and_execute" and result.get("passed"):
            self.confirmed.append({"summary": result.get("summary"),
                                   "profit_usd": result.get("profit_usd"),
                                   "poc_solidity": result.get("poc_solidity")})

    def _add_usage(self, resp):
        u = getattr(resp, "usage", None)
        if u:
            self.usage["prompt_tokens"] += getattr(u, "prompt_tokens", 0) or 0
            self.usage["completion_tokens"] += getattr(u, "completion_tokens", 0) or 0

    def _tool_result_payload(self, result):
        # keep the PoC out of the context we feed back (it's large); the agent already wrote it
        return json.dumps({k: v for k, v in result.items() if k != "poc_solidity"})[:6000]

    # --- native OpenAI tool-calling loop ---
    def _run_tools_mode(self, deadline):
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": TASK_PROMPT % _target_context()}]
        oai_tools = _openai_tool_schemas()
        final = ""
        for it in range(config.MAX_AUTONOMOUS_ITERATIONS):
            if time.time() > deadline:
                self._log("timeout reached; stopping")
                break
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=oai_tools, tool_choice="auto",
                max_tokens=config.MAX_OUTPUT_TOKENS_PER_CALL * 2, temperature=0.4)
            self._add_usage(resp)
            msg = resp.choices[0].message
            reasoning = getattr(msg, "reasoning_content", None)
            if reasoning:
                self._log("[think] " + reasoning[:600])
            if msg.content:
                self._log(msg.content[:1200])
                final = msg.content
            assistant = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls]
            messages.append(assistant)
            if not msg.tool_calls:
                break
            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = _safe_dispatch(name, args)
                self._record_tool(name, args, result)
                self._log("-> %s: %s" % (name, result.get("summary", "")))
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": self._tool_result_payload(result)})
        return final

    # --- JSON text-protocol (primary for DeepSeek-R1) ---
    _PROTOCOL = (
        "ACTION PROTOCOL: think privately, then END your reply with exactly ONE JSON object as your "
        "action - nothing after it. Do NOT prefix it with !function_call or any label.\n"
        'To call a tool: {"tool": "<name>", "args": { ... }}\n'
        'When finished: {"final": "<your vulnerability report>"}\n'
        "Tool arg shapes:\n"
        '  {"tool":"decompile","args":{"target":"goldAdapter"}}\n'
        '  {"tool":"price_query","args":{"adapter":"goldAdapter"}}\n'
        '  {"tool":"storage_read","args":{"target":"goldAdapter","slot":"1"}}\n'
        '  {"tool":"compile_and_validate","args":{"solidity_code":"..."}}\n'
        '  {"tool":"fork_and_execute","args":{"exploit_body":"<Solidity statements; use \\n and escape quotes>"}}\n'
        "The exploit_body is the BODY of a testExploit() function; log console2.log(\"PROFIT_USD\", x) "
        "and end with require(...) that passes only on success. Emit ONE action per message.")

    def _run_text_mode(self, deadline):
        messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + self._PROTOCOL},
                    {"role": "user", "content": TASK_PROMPT % _target_context()}]
        final = ""
        for it in range(config.MAX_AUTONOMOUS_ITERATIONS):
            if time.time() > deadline:
                self._log("timeout reached; stopping")
                break
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages,
                max_tokens=config.MAX_OUTPUT_TOKENS_PER_CALL * 2, temperature=0.4)
            self._add_usage(resp)
            msg = resp.choices[0].message
            content = msg.content or ""
            reasoning = getattr(msg, "reasoning_content", None)
            if reasoning:
                self._log("[think] " + reasoning[:600])
            messages.append({"role": "assistant", "content": content})
            action = _extract_action(content)
            if action is None:
                self._log(content[:1200])
                messages.append({"role": "user", "content": 'No valid action found. Reply with exactly one '
                                 'JSON object: {"tool": "...", "args": {...}} or {"final": "..."}.'})
                continue
            if "final" in action:
                final = action["final"]
                self._log("[final] " + str(final)[:1200])
                break
            name, args = action.get("tool"), action.get("args", {})
            result = _safe_dispatch(name, args)
            self._record_tool(name, args, result)
            self._log("-> %s: %s" % (name, result.get("summary", "")))
            messages.append({"role": "user", "content": "TOOL RESULT %s:\n%s" % (name, self._tool_result_payload(result))})
        return final

    def run(self):
        deadline = time.time() + config.AUTONOMOUS_RUN_TIMEOUT_SECONDS
        start = time.time()
        if config.HF_TOOL_MODE == "native":
            mode = "tools"
            try:
                final = self._run_tools_mode(deadline)
            except Exception as e:
                self._log("native tool-calling failed (%s); falling back to JSON text-protocol" % str(e)[:200])
                mode = "text-protocol"
                final = self._run_text_mode(deadline)
        else:
            # Default for DeepSeek-R1: the JSON text-protocol, which this reasoning model drives far
            # more reliably than native OpenAI function envelopes on Novita.
            mode = "text-protocol"
            final = self._run_text_mode(deadline)
        return self._result(mode, final, time.time() - start)

    def _result(self, mode, final, elapsed):
        result = {
            "agent": self.name,
            "model": self.model,
            "endpoint": config.HF_BASE_URL,
            "mode": mode,
            "found": bool(self.confirmed),
            "confirmed_exploits": self.confirmed,
            "confirmed_count": len(self.confirmed),
            "iterations_with_tools": len(self.tool_calls),
            "tool_calls": self.tool_calls,
            "reasoning_log": self.reasoning_log,
            "final_report": final,
            "usage": self.usage,
            "elapsed_s": round(elapsed, 1),
            "ts": time.time(),
        }
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (config.STATE_DIR / "hf_attack_result.json").write_text(json.dumps(result, indent=2))
        config.LOGS_DIR.mkdir(exist_ok=True)
        (config.LOGS_DIR / ("hf_attack_%d.json" % int(time.time()))).write_text(json.dumps(result, indent=2))
        return result


def _iter_json_objects(text):
    """Yield balanced {...} substrings, string/escape aware, so braces inside a Solidity body (a
    JSON string value) don't break matching."""
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                yield text[start:i + 1]
                start = -1


def _normalize_action(obj):
    if not isinstance(obj, dict):
        return None
    for k in ("final", "answer", "report", "done"):
        if k in obj:
            return {"final": obj[k] if isinstance(obj[k], str) else json.dumps(obj[k])}
    name = obj.get("tool") or obj.get("call") or obj.get("name") or obj.get("function")
    if not name:
        return None
    args = obj.get("args") or obj.get("arguments") or obj.get("params") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    return {"tool": name, "args": args if isinstance(args, dict) else {}}


def _fenced_solidity(text):
    m = re.search(r"```(?:solidity|sol)?\s*(.+?)```", text, re.DOTALL)
    return m.group(1).strip() if m else None


def _extract_action(content):
    """Turn a DeepSeek-R1 message into a normalized action {tool,args} or {final}. Ignores the
    <think> scratchpad, tolerates R1's call-key variants and the `!function_call:` prefix, and, for
    fork_and_execute with no inline body, falls back to a fenced Solidity code block."""
    answer = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL)
    answer = answer.replace("!function_call:", " ")
    actions = []
    for src in (answer, content):
        for blob in _iter_json_objects(src):
            try:
                obj = json.loads(blob)
            except json.JSONDecodeError:
                continue
            norm = _normalize_action(obj)
            if norm:
                actions.append(norm)
        if actions:
            break
    if not actions:
        return None
    action = actions[-1]  # the model's final decision, not a reasoning draft
    if action.get("tool") == "fork_and_execute" and not action["args"].get("exploit_body"):
        body = _fenced_solidity(content)
        if body:
            action["args"]["exploit_body"] = body
    return action


def run_hf_attack():
    return HFDeepSeekAgent().run()


def main():
    if not config.has_hf():
        print("HF_TOKEN not set. Add HF_TOKEN=hf_... to red-queen/.env or the environment.")
        return
    print("Autonomous agent: %s via %s" % (config.HF_MODEL, config.HF_BASE_URL))
    result = run_hf_attack()
    print("\n" + "=" * 70)
    print("mode=%s | tool calls=%d | confirmed exploits=%d | %.0fs" % (
        result["mode"], result["iterations_with_tools"], result["confirmed_count"], result["elapsed_s"]))
    for c in result["confirmed_exploits"]:
        print("  CONFIRMED: %s" % c.get("summary"))
    print("-" * 70)
    print((result["final_report"] or "(no final report)")[:2000])
    print("=" * 70)
    print("full result -> orchestrator/state/hf_attack_result.json")


if __name__ == "__main__":
    main()
