"""Red Queen - six agent tools, each wrapping a Foundry CLI call via subprocess.

    decompile(target)                 structural recon of a contract (source/ABI aware)
    trace(tx_hash)                    replay a tx's call trace on the fork
    fork_and_execute(exploit_body)    critical path: wrap body in a Setup-inheriting Foundry test,
                                      run it, return pass/fail + parsed profit
    storage_read(target, slot)        raw storage slot read
    price_query(adapter)              live getPrice() + exchangeRate() for an adapter
    compile_and_validate(code)        does this Solidity compile?

Every tool returns a dict with at least {"ok": bool, "summary": str}. The same functions back
both the deterministic FallbackAgent (direct Python calls) and the LLM agent (via TOOL_SCHEMAS +
dispatch()).
"""

import json
import re
import subprocess
import uuid

from . import config

config.ensure_foundry_on_path()

# deployment contract-name -> (source filename, solidity contract name)
_SOURCE_MAP = {
    "rwaUSDToken": ("rwaUSDToken.sol", "rwaUSDToken"),
    "Ledger": ("Ledger.sol", "Ledger"),
    "PriceRouter": ("PriceRouter.sol", "PriceRouter"),
    "AccountManager": ("AccountManager.sol", "AccountManager"),
    "goldToken": ("MockERC20.sol", "MockERC20"),
    "stockToken": ("MockERC20.sol", "MockERC20"),
    "goldAdapter": ("GoldAdapter.sol", "GoldAdapter"),
    "xstockAdapter": ("xStockAdapter.sol", "xStockAdapter"),
    "goldUsdFeed": ("MockPriceFeed.sol", "MockPriceFeed"),
    "stockUsdFeed": ("MockPriceFeed.sol", "MockPriceFeed"),
}

_deployment_cache = None


def load_deployment():
    global _deployment_cache
    if _deployment_cache is None:
        if config.DEPLOYMENT_PATH.exists():
            _deployment_cache = json.loads(config.DEPLOYMENT_PATH.read_text())
        else:
            _deployment_cache = {}
    return _deployment_cache


def _rpc():
    return load_deployment().get("rpc_url", config.DEFAULT_RPC_URL)


def _resolve(target):
    """name-or-address -> (address_or_None, contract_name_or_None)."""
    dep = load_deployment()
    contracts = dep.get("contracts", {})
    if isinstance(target, str) and target.startswith("0x") and len(target) == 42:
        for name, addr in contracts.items():
            if addr.lower() == target.lower():
                return target, name
        return target, None
    if target in contracts:
        return contracts[target], target
    return None, (target if target in _SOURCE_MAP else None)


def _run(cmd, timeout, cwd=None):
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd or config.PROJECT_ROOT),
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    except FileNotFoundError as e:
        return 127, "", "command not found: %s" % e


# --- Tool 1: decompile -------------------------------------------------------
def decompile(target):
    """Structural recon. For contracts we have source for (our mocks), returns function
    signatures + structural flags used for precondition matching. For an unknown on-chain address
    (the real-Multipli stretch), falls back to on-chain bytecode size via `cast code`."""
    addr, name = _resolve(target)
    if name in _SOURCE_MAP:
        fname, cname = _SOURCE_MAP[name]
        src = (config.SRC_DIR / fname).read_text()
        sigs = re.findall(r"function\s+(\w+)\s*\(([^)]*)\)", src)
        signatures = ["%s(%s)" % (n, a.strip()) for n, a in sigs]
        flags = _structural_flags(src)
        return {
            "ok": True,
            "target": target,
            "address": addr,
            "contract": cname,
            "functions": signatures,
            "structural_flags": flags,
            "summary": "%s: %d functions; flags=%s" % (cname, len(signatures), flags),
        }
    if addr and addr.startswith("0x"):
        rc, out, err = _run(["cast", "code", addr, "--rpc-url", _rpc()], timeout=30)
        code = out.strip()
        size = (len(code) - 2) // 2 if code.startswith("0x") else 0
        return {
            "ok": rc == 0,
            "target": target,
            "address": addr,
            "contract": None,
            "bytecode_size": size,
            "summary": "unknown address %s: %d bytes of code (bytecode-only recon)" % (addr, size),
        }
    return {"ok": False, "summary": "cannot resolve target '%s'" % target}


def _structural_flags(src):
    # Match function DEFINITIONS, not comment mentions, so flags reflect real capabilities.
    flags = []
    if "function exchangeRate" in src:
        flags.append("has_exchangeRate")
    if "balanceOf(pool)" in src or "balanceOf(address(this))" in src:
        flags.append("rate_reads_pool_balance")
    if "function getPrice" in src:
        flags.append("has_getPrice")
    if "function depositAtPrice" in src:
        flags.append("price_passed_in_not_rederived")
    if "rebaseMultiplier" in src:
        flags.append("has_rebase_multiplier")
    if "function depositAndMint" in src:
        flags.append("has_multicall_depositAndMint")
    return flags


# --- Tool 2: trace -----------------------------------------------------------
def trace(tx_hash):
    """Replay a transaction's call trace on the fork via `cast run`."""
    if not (isinstance(tx_hash, str) and tx_hash.startswith("0x") and len(tx_hash) == 66):
        return {"ok": False, "summary": "trace() needs a 32-byte tx hash (0x + 64 hex). "
                "Calldata simulation is out of scope for the demo."}
    rc, out, err = _run(["cast", "run", tx_hash, "--rpc-url", _rpc()], timeout=60)
    return {
        "ok": rc == 0,
        "tx_hash": tx_hash,
        "trace": out[-4000:] if out else "",
        "summary": "trace %s for %s..." % ("ok" if rc == 0 else "failed", tx_hash[:12]),
        "error": err[-500:] if rc != 0 else "",
    }


# --- Tool 3: fork_and_execute (critical path) --------------------------------
_TEST_WRAPPER = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Setup.t.sol";

contract {cls} is Setup {{
    function testExploit() public {{
{body}
    }}
{extra}
}}
'''


def fork_and_execute(exploit_body, extra_code="", block_number=None):
    """Wrap the agent's exploit body in a Setup-inheriting Foundry test and run it.

    The body may use every Setup fixture (accountManager, goldAdapter, xstockAdapter, goldToken,
    stockToken, goldPool, stockPool, token, ledger, priceRouter, admin, vm, console2). To report a
    profit machine-readably, log console2.log("PROFIT_USD", <uint 1e18-scaled>).
    """
    cls = "_AgentExploit_%s" % uuid.uuid4().hex[:10]
    body = "\n".join("        " + ln for ln in exploit_body.strip("\n").splitlines())
    contents = _TEST_WRAPPER.format(cls=cls, body=body, extra=extra_code)
    path = config.TEST_DIR / ("%s.t.sol" % cls)
    path.write_text(contents)
    try:
        cmd = ["forge", "test", "--match-path", "test/%s" % path.name,
               "--match-test", "testExploit", "-vvv"]
        if block_number is not None:
            cmd += ["--fork-url", config.DEFAULT_RPC_URL, "--fork-block-number", str(block_number)]
        rc, out, err = _run(cmd, timeout=config.FORK_EXEC_TIMEOUT_SECONDS)
        parsed = _parse_forge_test(out + "\n" + err)
        parsed["ok"] = parsed["passed"]
        parsed["poc_solidity"] = contents
        return parsed
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def _parse_forge_test(output):
    passed = "[PASS]" in output and "testExploit" in output
    fail_m = re.search(r"\[FAIL[:\]]([^\]]*)\]", output)
    reason = fail_m.group(1).strip() if fail_m else ("" if passed else "no PASS marker")
    logs = re.findall(r"^\s{2,}(.+)$", output, re.MULTILINE)
    profit = _grep_int(output, r"PROFIT_USD\s+(\d+)")
    rate_before = _grep_int(output, r"rateBefore\s+(\d+)")
    rate_after = _grep_int(output, r"rateAfter\s+(\d+)")
    if passed and profit:
        summary = "EXPLOIT CONFIRMED (profit $%s)" % format(profit / 1e18, ",.0f")
    elif passed:
        summary = "EXPLOIT CONFIRMED"
    else:
        summary = "REVERTED: %s" % reason
    return {
        "passed": passed,
        "revert_reason": reason,
        "profit_wei": profit,
        "profit_usd": (profit / 1e18) if profit is not None else None,
        "rate_before": rate_before,
        "rate_after": rate_after,
        "logs": logs[-30:],
        "summary": summary,
    }


def _grep_int(output, pattern):
    m = re.search(pattern, output)
    return int(m.group(1)) if m else None


# --- Tool 4: storage_read ----------------------------------------------------
def storage_read(target, slot):
    addr, _ = _resolve(target)
    if not (addr and addr.startswith("0x")):
        return {"ok": False, "summary": "cannot resolve '%s' to an address" % target}
    slot_arg = slot if isinstance(slot, str) else str(slot)
    rc, out, err = _run(["cast", "storage", addr, slot_arg, "--rpc-url", _rpc()], timeout=30)
    return {
        "ok": rc == 0,
        "address": addr,
        "slot": slot_arg,
        "value": out.strip(),
        "summary": ("slot %s of %s... = %s" % (slot_arg, addr[:10], out.strip())) if rc == 0
                   else "failed: %s" % err[-200:],
    }


# --- Tool 5: price_query -----------------------------------------------------
def price_query(adapter):
    dep = load_deployment()
    contracts = dep.get("contracts", {})
    adapter_addr, name = _resolve(adapter)
    router = contracts.get("PriceRouter")
    if not adapter_addr or not router:
        return {"ok": False, "summary": "need a live deployment (PriceRouter + adapter address) - "
                "run scripts/deploy.sh first"}
    rc1, out1, _ = _run(
        ["cast", "call", router, "getPrice(address)((uint256,uint256))", adapter_addr,
         "--rpc-url", _rpc()], timeout=30)
    rc2, out2, _ = _run(
        ["cast", "call", adapter_addr, "exchangeRate()(uint256)", "--rpc-url", _rpc()], timeout=30)
    price = _first_uint(out1)
    rate = _first_uint(out2)
    return {
        "ok": rc1 == 0 and rc2 == 0,
        "adapter": name or adapter,
        "address": adapter_addr,
        "router_price": price,
        "exchange_rate": rate,
        "summary": "%s: getPrice=%s, exchangeRate=%s" % (name or adapter, price, rate),
    }


def _first_uint(out):
    m = re.search(r"(\d+)", out or "")
    return int(m.group(1)) if m else None


# --- Tool 6: compile_and_validate --------------------------------------------
def compile_and_validate(solidity_code):
    """Write the code to a temp .sol under test/ (not a .t.sol, so it isn't run) and forge build."""
    tag = "_AgentCompile_%s" % uuid.uuid4().hex[:10]
    path = config.TEST_DIR / ("%s.sol" % tag)
    path.write_text(solidity_code)
    try:
        # The project baseline compiles cleanly, so any build failure after adding this file is
        # attributable to this snippet.
        rc, out, err = _run(["forge", "build"], timeout=90)
        combined = out + "\n" + err
        errors = [ln.strip() for ln in combined.splitlines() if "Error" in ln or "error[" in ln]
        return {
            "ok": rc == 0,
            "compiles": rc == 0,
            "errors": errors[:10],
            "summary": "compiles cleanly" if rc == 0 else "compile FAILED: %s" % (errors[0] if errors else "see errors"),
        }
    finally:
        try:
            path.unlink()
        except OSError:
            pass


# --- LLM tool schemas + dispatch ---------------------------------------------
TOOL_SCHEMAS = [
    {"name": "decompile",
     "description": "Structural recon of a contract by name (e.g. 'goldAdapter') or address. Returns function signatures and structural flags (has_exchangeRate, rate_reads_pool_balance, price_passed_in_not_rederived, has_rebase_multiplier, has_multicall_depositAndMint).",
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "price_query",
     "description": "Live getPrice() from the PriceRouter and exchangeRate() from the adapter, by adapter name or address.",
     "input_schema": {"type": "object", "properties": {"adapter": {"type": "string"}}, "required": ["adapter"]}},
    {"name": "storage_read",
     "description": "Read a raw storage slot of a contract (name or address).",
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}, "slot": {"type": "string"}}, "required": ["target", "slot"]}},
    {"name": "trace",
     "description": "Replay a transaction's call trace on the fork by 32-byte tx hash.",
     "input_schema": {"type": "object", "properties": {"tx_hash": {"type": "string"}}, "required": ["tx_hash"]}},
    {"name": "compile_and_validate",
     "description": "Check whether a full Solidity source string compiles.",
     "input_schema": {"type": "object", "properties": {"solidity_code": {"type": "string"}}, "required": ["solidity_code"]}},
    {"name": "fork_and_execute",
     "description": "CRITICAL: run an exploit. Provide the BODY of a testExploit() function (Solidity). It is wrapped in a contract inheriting the Setup test fixture, so you can use accountManager, goldAdapter, xstockAdapter, goldToken, stockToken, goldPool, stockPool, token, ledger, priceRouter, admin, vm, and console2 directly. Approve the ADAPTER (not accountManager) before depositing. Log console2.log(\"PROFIT_USD\", <uint 1e18-scaled>) to report profit. Returns pass/fail, revert reason, and parsed profit.",
     "input_schema": {"type": "object", "properties": {"exploit_body": {"type": "string"}, "extra_code": {"type": "string"}}, "required": ["exploit_body"]}},
]

_DISPATCH = {
    "decompile": lambda i: decompile(i["target"]),
    "price_query": lambda i: price_query(i["adapter"]),
    "storage_read": lambda i: storage_read(i["target"], i["slot"]),
    "trace": lambda i: trace(i["tx_hash"]),
    "compile_and_validate": lambda i: compile_and_validate(i["solidity_code"]),
    "fork_and_execute": lambda i: fork_and_execute(i["exploit_body"], i.get("extra_code", "")),
}


def dispatch(name, tool_input):
    fn = _DISPATCH.get(name)
    if not fn:
        return {"ok": False, "summary": "unknown tool %s" % name}
    return fn(tool_input)
