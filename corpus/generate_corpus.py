"""Synthetic benign-transaction corpus generator for Red Queen.

Pure-Python re-implementation of the arithmetic in src/{AccountManager,GoldAdapter,
xStockAdapter,PriceRouter,Ledger,rwaUSDToken}.sol, run against an in-memory state
object instead of a live Foundry/anvil fork (none is reachable from this sandbox).
Every state mutation a real transaction would cause is transcribed faithfully,
including the embedded PriceRouter/xStockAdapter composition bug (Vuln-B: the
XSTOCK price branch returns the raw per-share feed price and never folds in
rebaseMultiplier) — that omission is load-bearing for later pipeline stages and
must not be "fixed" here.

Only NORMAL user activity is generated: no donation attacks, no price
manipulation, no exploitation of Vuln-B. This is the ground truth a later stage
uses to compute statistical bounds on how state normally moves.

TraceSource seam: `SimTraceSource` is the only implementation today. A future
`ForkTraceSource` backed by real anvil traces could implement the same
`.run(spec) -> record` contract and be swapped in without touching the
generation/aggregation logic below.
"""
from __future__ import annotations

import json
import math
import random
import statistics
from dataclasses import dataclass, field
from pathlib import Path

ONE = 10**18
GOLD = "GoldAdapter"
XSTOCK = "xStockAdapter"

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"

SEED = 20260919
random.seed(SEED)


# ---------------------------------------------------------------------------
# State — mirrors Setup.t.sol's deployment (gold feed $2000/oz, stock $190/sh)
# ---------------------------------------------------------------------------

@dataclass
class State:
    gold_total_shares: int = 0
    gold_pool_balance: int = 0
    xstock_total_shares: int = 0
    xstock_pool_balance: int = 0
    xstock_rebase_multiplier: int = ONE
    gold_feed_price: int = 2000 * ONE
    stock_feed_price: int = 190 * ONE
    rwausd_total_supply: int = 0
    principal: dict = field(default_factory=dict)
    locked_shares: dict = field(default_factory=dict)  # (user, adapter) -> shares
    gold_balance: dict = field(default_factory=dict)
    stock_balance: dict = field(default_factory=dict)
    rwausd_balance: dict = field(default_factory=dict)


def exchange_rate(s: State, adapter: str) -> int:
    if adapter == GOLD:
        ts, pb = s.gold_total_shares, s.gold_pool_balance
    else:
        ts, pb = s.xstock_total_shares, s.xstock_pool_balance
    if ts == 0:
        return ONE
    return (pb * ONE) // ts


def price_for_adapter(s: State, adapter: str) -> int:
    if adapter == GOLD:
        rate = exchange_rate(s, GOLD)
        return (rate * s.gold_feed_price) // ONE
    # XSTOCK: PriceRouter.getPrice returns the raw per-share USD feed price and
    # does not compose xStockAdapter.rebaseMultiplier into it. Embedded, not a typo.
    return s.stock_feed_price


def token_name_and_balance(s: State, adapter: str):
    return ("GoldToken", s.gold_balance) if adapter == GOLD else ("StockToken", s.stock_balance)


# ---------------------------------------------------------------------------
# Trace primitives
# ---------------------------------------------------------------------------

def r(key, value):
    return {"key": key, "op": "read", "pre": value, "post": value}


def w(key, pre, post):
    return {"key": key, "op": "write", "pre": pre, "post": post}


# ---------------------------------------------------------------------------
# Transaction bodies — each returns (trace, return_value)
# ---------------------------------------------------------------------------

def do_deposit(s: State, user: str, adapter: str, amount: int):
    trace = []
    price = price_for_adapter(s, adapter)
    trace.append(r(f"PriceRouter.price[{adapter}]", price))

    rate = exchange_rate(s, adapter)
    shares = (amount * ONE) // rate

    if adapter == GOLD:
        pre_pool = s.gold_pool_balance
        s.gold_pool_balance += amount
        trace.append(w(f"{GOLD}.pool.balance", pre_pool, s.gold_pool_balance))
        pre_ts = s.gold_total_shares
        s.gold_total_shares += shares
        trace.append(w(f"{GOLD}.totalShares", pre_ts, s.gold_total_shares))
    else:
        pre_pool = s.xstock_pool_balance
        s.xstock_pool_balance += amount
        trace.append(w(f"{XSTOCK}.pool.balance", pre_pool, s.xstock_pool_balance))
        pre_ts = s.xstock_total_shares
        s.xstock_total_shares += shares
        trace.append(w(f"{XSTOCK}.totalShares", pre_ts, s.xstock_total_shares))

    token_name, bal = token_name_and_balance(s, adapter)
    pre_bal = bal.get(user, 0)
    bal[user] = pre_bal - amount
    trace.append(w(f"{token_name}.balanceOf[{user}]", pre_bal, bal[user]))

    lk = (user, adapter)
    pre_locked = s.locked_shares.get(lk, 0)
    s.locked_shares[lk] = pre_locked + shares
    trace.append(w(f"Ledger.lockedShares[{user}][{adapter}]", pre_locked, s.locked_shares[lk]))

    value = (amount * price) // ONE
    pre_principal = s.principal.get(user, 0)
    s.principal[user] = pre_principal + value
    trace.append(w(f"Ledger.principal[{user}]", pre_principal, s.principal[user]))

    return trace, shares


def do_mint(s: State, user: str, amount: int):
    trace = []
    pre_principal = s.principal.get(user, 0)
    s.principal[user] = pre_principal - amount
    trace.append(w(f"Ledger.principal[{user}]", pre_principal, s.principal[user]))

    pre_bal = s.rwausd_balance.get(user, 0)
    s.rwausd_balance[user] = pre_bal + amount
    trace.append(w(f"rwaUSDToken.balanceOf[{user}]", pre_bal, s.rwausd_balance[user]))

    pre_supply = s.rwausd_total_supply
    s.rwausd_total_supply += amount
    trace.append(w("rwaUSDToken.totalSupply", pre_supply, s.rwausd_total_supply))

    return trace, None


def do_deposit_and_mint(s: State, user: str, adapter: str, amount: int):
    trace = []
    price = price_for_adapter(s, adapter)
    trace.append(r(f"PriceRouter.price[{adapter}]", price))

    # depositAtPrice() trusts the router-supplied price directly for the share
    # calc rather than re-deriving exchangeRate() — transcribed as-written even
    # though for GOLD this mixes a USD-denominated price into a formula that
    # deposit() feeds a collateral-denominated rate into. Not our bug to fix.
    shares = (amount * ONE) // price

    if adapter == GOLD:
        pre_pool = s.gold_pool_balance
        s.gold_pool_balance += amount
        trace.append(w(f"{GOLD}.pool.balance", pre_pool, s.gold_pool_balance))
        pre_ts = s.gold_total_shares
        s.gold_total_shares += shares
        trace.append(w(f"{GOLD}.totalShares", pre_ts, s.gold_total_shares))
    else:
        pre_pool = s.xstock_pool_balance
        s.xstock_pool_balance += amount
        trace.append(w(f"{XSTOCK}.pool.balance", pre_pool, s.xstock_pool_balance))
        pre_ts = s.xstock_total_shares
        s.xstock_total_shares += shares
        trace.append(w(f"{XSTOCK}.totalShares", pre_ts, s.xstock_total_shares))

    token_name, bal = token_name_and_balance(s, adapter)
    pre_bal = bal.get(user, 0)
    bal[user] = pre_bal - amount
    trace.append(w(f"{token_name}.balanceOf[{user}]", pre_bal, bal[user]))

    lk = (user, adapter)
    pre_locked = s.locked_shares.get(lk, 0)
    s.locked_shares[lk] = pre_locked + shares
    trace.append(w(f"Ledger.lockedShares[{user}][{adapter}]", pre_locked, s.locked_shares[lk]))

    value = (amount * price) // ONE

    pre_principal_1 = s.principal.get(user, 0)
    s.principal[user] = pre_principal_1 + value
    trace.append(w(f"Ledger.principal[{user}]", pre_principal_1, s.principal[user]))

    minted = value
    pre_principal_2 = s.principal[user]
    s.principal[user] = pre_principal_2 - minted
    trace.append(w(f"Ledger.principal[{user}]", pre_principal_2, s.principal[user]))

    pre_rwa_bal = s.rwausd_balance.get(user, 0)
    s.rwausd_balance[user] = pre_rwa_bal + minted
    trace.append(w(f"rwaUSDToken.balanceOf[{user}]", pre_rwa_bal, s.rwausd_balance[user]))

    pre_supply = s.rwausd_total_supply
    s.rwausd_total_supply += minted
    trace.append(w("rwaUSDToken.totalSupply", pre_supply, s.rwausd_total_supply))

    return trace, minted


def do_redeem(s: State, user: str, adapter: str, shares: int):
    # AccountManager has no withdraw() path yet, and xStockAdapter has no redeem()
    # at all in src/ (only GoldAdapter does). Rather than leave withdrawals out of
    # the corpus entirely, this models the natural module-level equivalent for
    # both adapters symmetrically: unlock shares, pay out at the adapter's live
    # reserve-ratio rate, and unwind a proportional slice of Ledger.principal
    # (the real GoldAdapter.redeem doesn't touch Ledger at all today — this is a
    # deliberate, documented extension so "money leaving" dynamics are covered).
    trace = []
    rate = exchange_rate(s, adapter)
    amount_out = (shares * rate) // ONE
    price = price_for_adapter(s, adapter)
    trace.append(r(f"PriceRouter.price[{adapter}]", price))

    if adapter == GOLD:
        pre_ts = s.gold_total_shares
        s.gold_total_shares -= shares
        trace.append(w(f"{GOLD}.totalShares", pre_ts, s.gold_total_shares))
        pre_pool = s.gold_pool_balance
        s.gold_pool_balance -= amount_out
        trace.append(w(f"{GOLD}.pool.balance", pre_pool, s.gold_pool_balance))
    else:
        pre_ts = s.xstock_total_shares
        s.xstock_total_shares -= shares
        trace.append(w(f"{XSTOCK}.totalShares", pre_ts, s.xstock_total_shares))
        pre_pool = s.xstock_pool_balance
        s.xstock_pool_balance -= amount_out
        trace.append(w(f"{XSTOCK}.pool.balance", pre_pool, s.xstock_pool_balance))

    token_name, bal = token_name_and_balance(s, adapter)
    pre_bal = bal.get(user, 0)
    bal[user] = pre_bal + amount_out
    trace.append(w(f"{token_name}.balanceOf[{user}]", pre_bal, bal[user]))

    lk = (user, adapter)
    pre_locked = s.locked_shares.get(lk, 0)
    s.locked_shares[lk] = pre_locked - shares
    trace.append(w(f"Ledger.lockedShares[{user}][{adapter}]", pre_locked, s.locked_shares[lk]))

    value = (amount_out * price) // ONE
    pre_principal = s.principal.get(user, 0)
    unwind = min(value, pre_principal)
    s.principal[user] = pre_principal - unwind
    trace.append(w(f"Ledger.principal[{user}]", pre_principal, s.principal[user]))

    return trace, amount_out


def do_apply_corporate_action(s: State, new_multiplier: int):
    trace = []
    pre = s.xstock_rebase_multiplier
    s.xstock_rebase_multiplier = new_multiplier
    trace.append(w(f"{XSTOCK}.rebaseMultiplier", pre, new_multiplier))
    return trace, None


def fund_user(s: State, user: str, gold_amount: int, stock_amount: int):
    s.gold_balance[user] = s.gold_balance.get(user, 0) + gold_amount
    s.stock_balance[user] = s.stock_balance.get(user, 0) + stock_amount


# ---------------------------------------------------------------------------
# TraceSource seam
# ---------------------------------------------------------------------------

class TraceSource:
    """Contract a future real-fork trace source would implement: given a tx
    spec, run it and return a fully-populated record dict (see `.run` below).
    A ForkTraceSource driving real anvil transactions could replace
    SimTraceSource without changing generation or aggregation logic."""

    def run(self, spec: dict) -> dict:
        raise NotImplementedError


class SimTraceSource(TraceSource):
    DISPATCH = {
        "AccountManager.deposit": lambda s, spec: do_deposit(s, spec["user"], spec["adapter"], spec["args"]["amount"]),
        "AccountManager.mint": lambda s, spec: do_mint(s, spec["user"], spec["args"]["amount"]),
        "AccountManager.depositAndMint": lambda s, spec: do_deposit_and_mint(s, spec["user"], spec["adapter"], spec["args"]["amount"]),
        "Adapter.redeem": lambda s, spec: do_redeem(s, spec["user"], spec["adapter"], spec["args"]["shares"]),
        "xStockAdapter.applyCorporateAction": lambda s, spec: do_apply_corporate_action(s, spec["args"]["new_multiplier"]),
    }

    GAS_RANGES = {
        "AccountManager.deposit": (95_000, 165_000),
        "AccountManager.mint": (55_000, 85_000),
        "AccountManager.depositAndMint": (160_000, 230_000),
        "Adapter.redeem": (85_000, 130_000),
        "xStockAdapter.applyCorporateAction": (35_000, 50_000),
    }

    def __init__(self, state: State, start_ts: int = 1_700_000_000):
        self.state = state
        self.timestamp = start_ts
        self.tx_id = 0

    def run(self, spec: dict) -> dict:
        self.tx_id += 1
        fn = spec["function"]
        trace, ret = self.DISPATCH[fn](self.state, spec)

        pre_state, post_state = {}, {}
        for entry in trace:
            if entry["key"] not in pre_state:
                pre_state[entry["key"]] = entry["pre"]
            post_state[entry["key"]] = entry["post"]

        lo, hi = self.GAS_RANGES[fn]
        gas = random.randint(lo, hi)

        gap = spec.pop("_gap", None)
        self.timestamp += gap if gap is not None else random.randint(1, 600)

        record = {
            "tx_id": self.tx_id,
            "category": spec["category"],
            "function": fn,
            "user": spec.get("user"),
            "adapter": spec.get("adapter"),
            "args": spec.get("args", {}),
            "timestamp": self.timestamp,
            "gas_used": gas,
            "return_value": ret,
            "trace": trace,
            "pre_state": pre_state,
            "post_state": post_state,
        }
        if "edge_kind" in spec:
            record["edge_kind"] = spec["edge_kind"]
        return record


# ---------------------------------------------------------------------------
# User population
# ---------------------------------------------------------------------------

PROFILES = {
    "retail_small": {"weight": 0.40, "usd_lo": 10, "usd_hi": 1_000},
    "mid_size": {"weight": 0.35, "usd_lo": 1_000, "usd_hi": 50_000},
    "large": {"weight": 0.20, "usd_lo": 50_000, "usd_hi": 1_000_000},
    "active_trader": {"weight": 0.05, "usd_lo": 100, "usd_hi": 20_000},
}

NUM_USERS = 160


def make_addr(i: int) -> str:
    return "0x" + format(0xA000 + i, "040x")


def build_users():
    names = list(PROFILES.keys())
    weights = [PROFILES[n]["weight"] for n in names]
    users = []
    for i in range(NUM_USERS):
        profile = random.choices(names, weights=weights, k=1)[0]
        users.append({"addr": make_addr(i), "profile": profile})
    return users


def log_uniform_usd(lo: int, hi: int) -> float:
    return math.exp(random.uniform(math.log(lo), math.log(hi)))


def usd_amount_wei(usd: float) -> int:
    return int(usd * ONE)


def deposit_amount_for(s: State, adapter: str, usd_wei: int) -> int:
    feed = s.gold_feed_price if adapter == GOLD else s.stock_feed_price
    return (usd_wei * ONE) // feed


def fund_all_users(s: State, users):
    for u in users:
        hi = PROFILES[u["profile"]]["usd_hi"]
        budget_wei = usd_amount_wei(hi * 25)
        fund_user(
            s, u["addr"],
            gold_amount=(budget_wei * ONE) // s.gold_feed_price,
            stock_amount=(budget_wei * ONE) // s.stock_feed_price,
        )


def pick_adapter() -> str:
    return GOLD if random.random() < 0.55 else XSTOCK


# ---------------------------------------------------------------------------
# Category generation
# ---------------------------------------------------------------------------

def gen_deposits(src: SimTraceSource, users, n: int):
    out = []
    for _ in range(n):
        u = random.choice(users)
        adapter = pick_adapter()
        usd = log_uniform_usd(*[PROFILES[u["profile"]]["usd_lo"], PROFILES[u["profile"]]["usd_hi"]])
        amount = deposit_amount_for(src.state, adapter, usd_amount_wei(usd))
        if amount <= 0:
            continue
        spec = {
            "category": "deposit", "function": "AccountManager.deposit",
            "user": u["addr"], "adapter": adapter,
            "args": {"amount": amount, "usd_target": round(usd, 2)},
        }
        out.append(src.run(spec))
    return out


def gen_deposit_and_mint(src: SimTraceSource, users, n: int):
    out = []
    for _ in range(n):
        u = random.choice(users)
        adapter = pick_adapter()
        usd = log_uniform_usd(*[PROFILES[u["profile"]]["usd_lo"], PROFILES[u["profile"]]["usd_hi"]])
        amount = deposit_amount_for(src.state, adapter, usd_amount_wei(usd))
        if amount <= 0:
            continue
        spec = {
            "category": "depositAndMint", "function": "AccountManager.depositAndMint",
            "user": u["addr"], "adapter": adapter,
            "args": {"amount": amount, "usd_target": round(usd, 2)},
        }
        out.append(src.run(spec))
    return out


def users_with_principal(s: State, users):
    return [u for u in users if s.principal.get(u["addr"], 0) > 0]


def gen_mints(src: SimTraceSource, users, n: int):
    out = []
    attempts = 0
    while len(out) < n and attempts < n * 20:
        attempts += 1
        pool = users_with_principal(src.state, users)
        if not pool:
            break
        u = random.choice(pool)
        principal = src.state.principal[u["addr"]]
        frac = random.uniform(0.1, 1.0)
        amount = int(principal * frac)
        if amount <= 0:
            continue
        spec = {
            "category": "mint", "function": "AccountManager.mint",
            "user": u["addr"], "adapter": None,
            "args": {"amount": amount},
        }
        out.append(src.run(spec))
    return out


def users_with_locked_shares(s: State, users, adapter=None):
    result = []
    for u in users:
        for a in ((GOLD, XSTOCK) if adapter is None else (adapter,)):
            if s.locked_shares.get((u["addr"], a), 0) > 0:
                result.append((u, a))
    return result


def gen_withdrawals(src: SimTraceSource, users, n: int):
    out = []
    attempts = 0
    while len(out) < n and attempts < n * 20:
        attempts += 1
        pool = users_with_locked_shares(src.state, users)
        if not pool:
            break
        u, adapter = random.choice(pool)
        locked = src.state.locked_shares[(u["addr"], adapter)]
        frac = random.uniform(0.05, 0.8)
        shares = int(locked * frac)
        if shares <= 0:
            continue
        spec = {
            "category": "withdrawal", "function": "Adapter.redeem",
            "user": u["addr"], "adapter": adapter,
            "args": {"shares": shares},
        }
        out.append(src.run(spec))
    return out


def gen_xstock_multiplier_change(src: SimTraceSource, users, n_events: int, follow_ups_per_event: int):
    out = []
    for _ in range(n_events):
        bump = random.uniform(1.005, 1.10)
        new_mult = int(src.state.xstock_rebase_multiplier * bump)
        if new_mult <= src.state.xstock_rebase_multiplier:
            new_mult = src.state.xstock_rebase_multiplier + 1
        spec = {
            "category": "xstock_multiplier_change",
            "function": "xStockAdapter.applyCorporateAction",
            "user": "0xADMIN", "adapter": XSTOCK,
            "args": {"new_multiplier": new_mult},
            "new_multiplier": new_mult,
        }
        out.append(src.run(spec))

        for _ in range(follow_ups_per_event):
            u = random.choice(users)
            kind = random.choice(["deposit", "mint", "withdrawal"])
            if kind == "deposit":
                usd = log_uniform_usd(*[PROFILES[u["profile"]]["usd_lo"], PROFILES[u["profile"]]["usd_hi"]])
                amount = deposit_amount_for(src.state, XSTOCK, usd_amount_wei(usd))
                if amount <= 0:
                    continue
                out.append(src.run({
                    "category": "xstock_multiplier_change", "function": "AccountManager.deposit",
                    "user": u["addr"], "adapter": XSTOCK, "args": {"amount": amount},
                }))
            elif kind == "mint" and src.state.principal.get(u["addr"], 0) > 0:
                amount = int(src.state.principal[u["addr"]] * random.uniform(0.1, 1.0))
                if amount <= 0:
                    continue
                out.append(src.run({
                    "category": "xstock_multiplier_change", "function": "AccountManager.mint",
                    "user": u["addr"], "adapter": None, "args": {"amount": amount},
                }))
            else:
                locked = src.state.locked_shares.get((u["addr"], XSTOCK), 0)
                if locked <= 0:
                    continue
                shares = int(locked * random.uniform(0.05, 0.5))
                if shares <= 0:
                    continue
                out.append(src.run({
                    "category": "xstock_multiplier_change", "function": "Adapter.redeem",
                    "user": u["addr"], "adapter": XSTOCK, "args": {"shares": shares},
                }))
    return out


def gen_edge_cases(src: SimTraceSource, users, n_dust_deposit: int, n_dust_mint: int, n_rapid_bursts: int, ops_per_burst: int):
    out = []

    for _ in range(n_dust_deposit):
        u = random.choice(users)
        adapter = pick_adapter()
        usd = random.uniform(0.01, 0.99)
        amount = deposit_amount_for(src.state, adapter, usd_amount_wei(usd))
        if amount <= 0:
            amount = 1
        rec = src.run({
            "category": "edge_case", "function": "AccountManager.deposit",
            "user": u["addr"], "adapter": adapter,
            "args": {"amount": amount, "usd_target": round(usd, 4)},
            "edge_kind": "dust_deposit",
        })
        out.append(rec)

    for _ in range(n_dust_mint):
        pool = users_with_principal(src.state, users)
        if not pool:
            continue
        u = random.choice(pool)
        principal = src.state.principal[u["addr"]]
        amount = min(principal, usd_amount_wei(random.uniform(0.001, 0.99)))
        if amount <= 0:
            continue
        rec = src.run({
            "category": "edge_case", "function": "AccountManager.mint",
            "user": u["addr"], "adapter": None,
            "args": {"amount": amount},
            "edge_kind": "dust_mint",
        })
        out.append(rec)

    for _ in range(n_rapid_bursts):
        u = random.choice(users)
        adapter = pick_adapter()
        for i in range(ops_per_burst):
            src.tx_id_note = None
            op = random.choice(["deposit", "deposit", "mint"])
            if op == "deposit" or src.state.principal.get(u["addr"], 0) <= 0:
                usd = log_uniform_usd(*[PROFILES[u["profile"]]["usd_lo"], PROFILES[u["profile"]]["usd_hi"]])
                amount = deposit_amount_for(src.state, adapter, usd_amount_wei(usd))
                if amount <= 0:
                    continue
                rec = src.run({
                    "category": "edge_case", "function": "AccountManager.deposit",
                    "user": u["addr"], "adapter": adapter,
                    "args": {"amount": amount}, "edge_kind": "rapid_sequence",
                    "_gap": random.randint(1, 3),
                })
            else:
                amount = int(src.state.principal[u["addr"]] * random.uniform(0.1, 0.5))
                if amount <= 0:
                    continue
                rec = src.run({
                    "category": "edge_case", "function": "AccountManager.mint",
                    "user": u["addr"], "adapter": None,
                    "args": {"amount": amount}, "edge_kind": "rapid_sequence",
                    "_gap": random.randint(1, 3),
                })
            out.append(rec)

    return out


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def percentile(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return float(s[int(k)])
    return float(s[f] * (c - k) + s[c] * (k - f))


def compute_stats(all_records):
    magnitudes = {}
    for rec in all_records:
        for entry in rec["trace"]:
            mag = abs(entry["post"] - entry["pre"])
            magnitudes.setdefault(entry["key_class"], []).append(mag)

    stats = {}
    for key, vals in magnitudes.items():
        vals_f = [float(v) for v in vals]
        stats[key] = {
            "count": len(vals_f),
            "mean": statistics.fmean(vals_f),
            "std": statistics.pstdev(vals_f) if len(vals_f) > 1 else 0.0,
            "p50": percentile(vals_f, 50),
            "p95": percentile(vals_f, 95),
            "p99": percentile(vals_f, 99),
            "max": max(vals_f),
        }
    return stats


def key_class(key: str) -> str:
    # Collapse per-user/per-adapter instance keys ("Ledger.principal[0xabc]") down
    # to their variable class ("Ledger.principal") so stats aggregate across the
    # whole user population instead of being sliced one-per-address.
    idx = key.find("[")
    return key if idx == -1 else key[:idx]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    state = State()
    users = build_users()
    fund_all_users(state, users)
    src = SimTraceSource(state)

    deposits = gen_deposits(src, users, 1000)
    deposit_and_mint = gen_deposit_and_mint(src, users, 150)
    xstock_change = gen_xstock_multiplier_change(src, users, n_events=10, follow_ups_per_event=4)
    mints = gen_mints(src, users, 300)
    withdrawals = gen_withdrawals(src, users, 400)
    edge_cases = gen_edge_cases(src, users, n_dust_deposit=20, n_dust_mint=20, n_rapid_bursts=15, ops_per_burst=4)

    categories = {
        "deposit": deposits,
        "withdrawal": withdrawals,
        "mint": mints,
        "depositAndMint": deposit_and_mint,
        "edge_case": edge_cases,
        "xstock_multiplier_change": xstock_change,
    }

    file_map = {
        "deposit": "deposits.jsonl",
        "withdrawal": "withdrawals.jsonl",
        "mint": "mints.jsonl",
        "depositAndMint": "deposit_and_mint.jsonl",
        "edge_case": "edge_cases.jsonl",
        "xstock_multiplier_change": "xstock_multiplier_change.jsonl",
    }

    all_records = []
    for cat, records in categories.items():
        path = DATA_DIR / file_map[cat]
        with open(path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        all_records.extend(records)

    for rec in all_records:
        for entry in rec["trace"]:
            entry["key_class"] = key_class(entry["key"])

    stats = compute_stats(all_records)
    with open(ROOT / "stats.json", "w") as f:
        json.dump(stats, f, indent=2, sort_keys=True)

    # ---- coverage report -------------------------------------------------
    deposit_usds = [rec["args"]["usd_target"] for rec in deposits if "usd_target" in rec["args"]]
    max_deposit_usd = max(deposit_usds) if deposit_usds else 0
    min_deposit_usd = min(deposit_usds) if deposit_usds else 0

    users_by_addr = {u["addr"]: u for u in users}
    cross_adapter_users = [
        addr for addr in {k[0] for k in state.locked_shares}
        if state.locked_shares.get((addr, GOLD), 0) > 0 and state.locked_shares.get((addr, XSTOCK), 0) > 0
    ]

    multipliers_used = [rec["args"]["new_multiplier"] for rec in xstock_change if rec["function"] == "xStockAdapter.applyCorporateAction"]

    warnings = [
        f"No deposits >= $1,000,000 and none >= $10,000,000 in corpus (max observed: ${max_deposit_usd:,.2f}) "
        "-- large-deposit / whale-transaction behavior is entirely untested and any downstream threshold "
        "for that band should get manual review before large-deposit deployment.",
        "GoldAdapter.exchangeRate() and xStockAdapter.exchangeRate() never move off exactly 1e18 anywhere in "
        "this corpus: under purely proportional benign deposits (no bare/donation transfers into the pool) the "
        "reserve ratio is mathematically invariant. The deltas recorded for these derived rates are therefore "
        "always 0 -- this corpus provides no ground truth for what a *legitimate* small reserve-ratio wobble "
        "looks like, so any nonzero exchange-rate movement in a candidate trace will look maximally anomalous "
        "by construction, not just donation-attack movement specifically.",
        "PriceRouter.price[GoldAdapter]/[xStockAdapter] are recorded as reads (getPrice is a view call, not "
        "persisted storage) against feeds held constant at $2000/oz and $190/share for the entire generation "
        "run -- there is no market-volatility scenario in this corpus. Their stats.json entries are all-zero "
        "by construction and must not be used as anomaly bounds for legitimate price movement or oracle staleness.",
        "xStockAdapter.rebaseMultiplier was only exercised across "
        f"{len(multipliers_used)} corporate-action events spanning {min(multipliers_used) if multipliers_used else ONE} "
        f"to {max(multipliers_used) if multipliers_used else ONE} (roughly 1.00x-1.5x cumulative) -- large one-shot "
        "corporate actions (e.g. multi-for-one splits, multiplier jumps of 2x+) are not represented.",
        f"Cross-adapter combined positions (same user holding locked shares in both {GOLD} and {XSTOCK} "
        f"simultaneously) occurred incidentally for {len(cross_adapter_users)}/{NUM_USERS} users because both "
        "adapters are drawn from the same random pool per transaction, not because any scenario deliberately "
        "targets multi-collateral exposure -- there is no stress case for e.g. one account maximizing both "
        "positions at once, sequencing a gold withdrawal against an xStock mint in the same burst, or otherwise "
        "exercising adapter-interaction edge behavior beyond what falls out incidentally.",
        "No failed/reverted transactions are represented anywhere in the corpus (every generated tx succeeds by "
        "construction) -- there is no ground truth for what a legitimate revert (insufficient balance, "
        "NOT_ADMIN, NOT_ACCOUNT_MANAGER, arithmetic underflow) looks like versus a genuine attack attempt.",
        "Withdrawals are modeled as a module-level adapter share-redemption (see do_redeem in this script) "
        "since AccountManager has no withdraw() entry point in src/ and xStockAdapter has no redeem() at all "
        "(only GoldAdapter does) -- the withdrawal traces in this corpus are therefore a documented "
        "extrapolation, not a transcription of an existing on-chain code path.",
        "All 2,000 transactions were generated by a single deterministic PRNG seed and a fixed set of "
        f"{NUM_USERS} synthetic addresses -- there is no wallet-level Sybil diversity, no gas-price/mempool "
        "context, and no time-of-day/seasonality structure to timestamps beyond random per-tx gaps.",
    ]

    coverage_report = {
        "corpus_size": len(all_records),
        "categories": {cat: len(records) for cat, records in categories.items()},
        "seed": SEED,
        "num_users": NUM_USERS,
        "deposit_usd_range": {"min": round(min_deposit_usd, 2), "max": round(max_deposit_usd, 2)},
        "cross_adapter_users": len(cross_adapter_users),
        "xstock_multiplier_events": len(multipliers_used),
        "xstock_multiplier_range": {
            "min": min(multipliers_used) if multipliers_used else ONE,
            "max": max(multipliers_used) if multipliers_used else ONE,
        },
        "coverage_warnings": warnings,
    }

    with open(ROOT / "coverage_report.json", "w") as f:
        json.dump(coverage_report, f, indent=2)

    md_lines = [
        "# Red Queen Benign Corpus -- Coverage Report",
        "",
        f"- Corpus size: **{coverage_report['corpus_size']}** transactions",
        f"- Generator seed: `{SEED}` (deterministic)",
        f"- Synthetic users: {NUM_USERS}",
        "",
        "## Category counts",
        "",
        "| Category | Count |",
        "|---|---|",
    ]
    for cat, records in categories.items():
        md_lines.append(f"| {cat} | {len(records)} |")
    md_lines += [
        "",
        "## Deposit size range",
        "",
        f"- min: ${coverage_report['deposit_usd_range']['min']:,}",
        f"- max: ${coverage_report['deposit_usd_range']['max']:,}",
        "",
        "## Coverage warnings",
        "",
    ]
    for warning in warnings:
        md_lines.append(f"- {warning}")
    md_lines.append("")

    with open(ROOT / "coverage_report.md", "w") as f:
        f.write("\n".join(md_lines))

    print(f"Generated {len(all_records)} transactions across {len(categories)} categories.")
    print(f"Wrote stats for {len(stats)} state-variable classes.")


if __name__ == "__main__":
    main()
