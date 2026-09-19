"""Attack an UPLOADED / arbitrary contract with the live autonomous LLM agent (NVIDIA Nemotron).

This is the real-discovery path: the user supplies any Solidity contract; the LLM is given its source
and ONE tool - run_test(full_foundry_test) - and must write a Foundry test that deploys the contract
and demonstrates an exploit (assertions that only hold if the contract is genuinely broken). A test
that PASSES on the EVM = a concretely validated finding, not a claim. The model iterates on failures.

Honest limits (surfaced in the report):
  * Self-contained contracts work; ones needing external libs (OpenZeppelin, etc.) may fail to compile
    in the sandbox - reported as such.
  * "Exploit confirmed" means the model's own demonstration test passed on a fresh EVM deploy.
  * Discovery is best-effort (LLM), not exhaustive.

Streams progress to orchestrator/state/state.json so the existing frontend animates the live attack.

Run:  python3 -m agent.custom_attack <source.sol path> [ContractName]
"""

import json
import os
import re
import subprocess
import sys
import time
import uuid

from . import config

config.ensure_foundry_on_path()

UPLOAD_DIR = config.SRC_DIR / "uploads"
STATE = config.STATE_DIR / "state.json"
MAX_ITERS = int(os.environ.get("RED_QUEEN_CUSTOM_ITERS", "10"))


def _write_state(s):
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def _blank_state(name):
    return {
        "status": "attacking", "iteration": 0, "target_contracts": ["uploads/%s.sol" % name],
        "advisories_generated": 0, "coverage_warnings_flagged": 0,
        "attacker": {"pattern_name": "custom: %s" % name, "progress": {"current": 0, "total": MAX_ITERS},
                     "log": [], "tool_calls": [], "poc_code": "",
                     "result": {"found": False, "profit_usd": 0}},
        "defender": {"trace_diff": [], "candidate_invariant": {"name": "", "solidity": ""},
                     "validation": {"checked": 0, "total": 0, "violations": 0},
                     "threshold": {"max_observed_pct": 0, "threshold_pct": 0, "margin_ratio": 0},
                     "bypass_results": [], "guard_deployed": False},
    }


def _detect_contract_name(source):
    m = re.findall(r"\bcontract\s+(\w+)", source)
    return m[-1] if m else "Target"


def _run_test(full_source):
    """Compile+run a full Foundry test the model wrote. Returns (passed, output)."""
    tag = "_CustomExploit_%s" % uuid.uuid4().hex[:8]
    path = config.TEST_DIR / ("%s.t.sol" % tag)
    path.write_text(full_source)
    try:
        p = subprocess.run(["forge", "test", "--match-path", "test/%s" % path.name, "-vv"],
                           capture_output=True, text=True, timeout=90, cwd=str(config.PROJECT_ROOT))
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        passed = "[PASS]" in out
        return passed, out[-3500:]
    except subprocess.TimeoutExpired:
        return False, "timeout after 90s"
    finally:
        try:
            path.unlink()
        except OSError:
            pass


_TOOL_DESC = ("Compile and run a COMPLETE Foundry test file on a fresh EVM. Provide the full .sol "
              "source (SPDX + pragma + imports + a contract inheriting forge-std Test with a test "
              "function). Import the target with: import \"../src/uploads/%s.sol\"; Returns whether it "
              "PASSED and the forge output. A passing test that asserts the exploited outcome is your proof.")


def attack_custom(source, name=None):
    name = name or _detect_contract_name(source)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / ("%s.sol" % name)).write_text(source)

    ep = config.autonomous_endpoint()
    s = _blank_state(name)
    if not ep:
        s["attacker"]["log"].append("no LLM backend configured (set NVIDIA_API_KEY / GROQ_API_KEY / HF_TOKEN)")
        s["status"] = "hardened"
        _write_state(s)
        print("no autonomous backend set."); return {"contract": name, "found": False, "iterations": 0}

    from openai import OpenAI
    client = OpenAI(base_url=ep["base_url"], api_key=ep["api_key"])
    tools_schema = [{"type": "function", "function": {
        "name": "run_test", "description": _TOOL_DESC % name,
        "parameters": {"type": "object", "properties": {"test_source": {"type": "string"}},
                       "required": ["test_source"]}}}]

    system = ("You are Red Queen, an autonomous smart-contract exploit agent. You are given the full "
              "source of a Solidity contract named %s. FIND A VULNERABILITY and PROVE it by writing a "
              "Foundry test that deploys the contract and demonstrates the exploit with assertions that "
              "only pass if the contract is genuinely broken. Use the run_test tool; iterate on failures. "
              "Import the target with: import \"../src/uploads/%s.sol\"; use forge-std (import "
              "\"forge-std/Test.sol\";) and cheatcodes (vm.deal, vm.prank, deal). When a test PASSES, "
              "state the vulnerability class and impact plainly. If after several tries you cannot, say "
              "so honestly." % (name, name))
    user = "Target contract source (src/uploads/%s.sol):\n\n%s" % (name, source[:12000])

    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    s["attacker"]["log"].append("uploaded %s.sol (%d bytes) -> handing to %s" % (name, len(source), ep["label"]))
    s["attacker"]["log"].append("agent: reading source, writing exploit tests, running on fork ...")
    _write_state(s)

    confirmed = None
    for it in range(1, MAX_ITERS + 1):
        s["attacker"]["progress"] = {"current": it, "total": MAX_ITERS}
        _write_state(s)
        try:
            resp = client.chat.completions.create(
                model=ep["model"], messages=messages, tools=tools_schema, tool_choice="auto",
                max_completion_tokens=config.MAX_OUTPUT_TOKENS_PER_CALL)
        except Exception as e:  # noqa: BLE001
            s["attacker"]["log"].append("LLM error: %s" % str(e)[:160]); _write_state(s); break
        m = resp.choices[0].message
        if m.content and m.content.strip():
            s["attacker"]["log"].append(m.content.strip()[:400]); _write_state(s)
        asst = {"role": "assistant", "content": m.content or ""}
        if m.tool_calls:
            asst["tool_calls"] = [{"id": tc.id, "type": "function",
                                   "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                  for tc in m.tool_calls]
        messages.append(asst)
        if not m.tool_calls:
            break
        for tc in m.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            test_src = args.get("test_source", "")
            s["attacker"]["poc_code"] = test_src[:4000]
            s["attacker"]["log"].append("run_test: compiling + running on fork ...")
            _write_state(s)
            passed, out = _run_test(test_src)
            verdict = "PASSED - exploit demonstrated" if passed else "reverted/failed"
            s["attacker"]["log"].append("  -> %s" % verdict)
            s["attacker"]["tool_calls"].append({"name": "run_test", "args": "(%d chars)" % len(test_src),
                                                "result": verdict})
            _write_state(s)
            if passed:
                confirmed = test_src
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": ("PASSED\n" if passed else "FAILED\n") + out[-2500:]})
        if confirmed:
            break

    s["attacker"]["result"] = {"found": bool(confirmed), "profit_usd": 0}
    if confirmed:
        s["attacker"]["log"].append("EXPLOIT CONFIRMED on %s (demonstration test passed on fresh EVM)" % name)
    else:
        s["attacker"]["log"].append("no exploit demonstrated within %d iterations (best-effort)" % MAX_ITERS)
    s["status"] = "hardened"
    _write_state(s)

    result = {"contract": name, "found": bool(confirmed), "poc": confirmed,
              "iterations": s["attacker"]["progress"]["current"], "backend": ep["label"], "ts": time.time()}
    (config.STATE_DIR / "custom_attack_result.json").write_text(json.dumps(result, indent=2))
    return result


def main():
    if len(sys.argv) < 2:
        print("usage: python3 -m agent.custom_attack <source.sol> [ContractName]"); return
    src = open(sys.argv[1]).read()
    name = sys.argv[2] if len(sys.argv) > 2 else None
    r = attack_custom(src, name)
    print("contract=%s | found=%s | iterations=%s" % (r["contract"], r["found"], r["iterations"]))


if __name__ == "__main__":
    main()
