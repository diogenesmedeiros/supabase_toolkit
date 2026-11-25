import re

from .constants import RPC_READ_VERBS, RPC_WRITE_VERBS
from .heuristics import classify_rpc_access
from .http_client import request


def classify_rpc_op(fn):
    tokens = set(re.split(r"[^a-z0-9]+", fn.lower()))

    if tokens & set(RPC_WRITE_VERBS):
        return "write"

    if tokens & set(RPC_READ_VERBS):
        return "read"

    return "undefined"


def singularize(name):
    n = name.lower()

    if n.endswith("ies") and len(n) > 3:
        return n[:-3] + "y"

    if n.endswith("ses") and len(n) > 3:
        return n[:-2]

    if n.endswith("s") and not n.endswith("ss") and len(n) > 1:
        return n[:-1]

    return n


def table_variants(table):
    n = table.lower()
    sing = singularize(n)
    variants = {n, sing, sing + "s", n + "s"}

    return {v for v in variants if v}


def correlate_rpc(tables, rpc_map):
    result = {}

    for table in tables:
        variants = table_variants(table)
        hits = []

        for fn in rpc_map:
            fn_tokens = set(re.split(r"[^a-z0-9]+", fn.lower()))

            if variants & fn_tokens:
                hits.append((fn, classify_rpc_op(fn)))

        if hits:
            result[table] = sorted(hits)

    return result


def probe_rpc(session, base_url, fn, args=None):
    resp = request(session, "GET", f"{base_url}/rest/v1/rpc/{fn}")

    op = classify_rpc_op(fn)

    if isinstance(resp, Exception):
        return {"rpc": fn, "status": None, "verdict": "error", "op": op,
                "severity": "info", "confidence": "low",
                "error": str(resp), "args": args or []}

    verdict, severity, confidence = classify_rpc_access(resp.status_code)

    snippet = None

    if resp.status_code == 200:
        try:
            snippet = resp.json()
        except ValueError:
            snippet = resp.text[:200]

    return {"rpc": fn, "status": resp.status_code, "verdict": verdict,
            "severity": severity, "confidence": confidence,
            "requires_args": resp.status_code == 400,
            "post_only": resp.status_code == 405,
            "sample": snippet, "op": op, "args": args or []}


def exploit_rpc(session, base_url, fn, args=None, op=None):
    op = op or classify_rpc_op(fn)
    result = {"rpc": fn, "op": op, "status": None, "verdict": "?",
              "severity": "info", "confidence": "high", "args": args or [],
              "leaked": False, "sample": None}

    if op == "write":
        result["verdict"] = "write — not invoked (use 'call' in the shell carefully)"
        result["severity"] = "medium"
        result["confidence"] = "medium"
        return result

    body = {a: None for a in (args or [])}

    resp = request(session, "POST", f"{base_url}/rest/v1/rpc/{fn}",
                   json=body, headers={"Content-Type": "application/json"})

    if isinstance(resp, Exception):
        result["verdict"] = "error"
        result["confidence"] = "low"
        result["error"] = str(resp)
        return result

    result["status"] = resp.status_code

    if resp.status_code in (401, 403):
        result["verdict"] = "blocked (authorization)"
        return result

    if resp.status_code not in (200, 206):
        result["verdict"] = f"HTTP {resp.status_code}"
        result["confidence"] = "medium"
        return result

    try:
        data = resp.json()
    except ValueError:
        data = resp.text[:200]

    has_data = bool(data) and data not in ([], {}, None)
    result["sample"] = data if isinstance(data, (list, dict)) else str(data)[:200]

    if has_data:
        result["leaked"] = True
        result["verdict"] = "READ ALLOWED via RPC (returned data)"
        result["severity"] = "high"
    else:
        result["verdict"] = "callable, no data"
        result["severity"] = "low"

    return result
