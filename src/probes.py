from .constants import (
    DUMP_MAX_ROWS,
    DUMP_PAGE,
    IDENT_RE,
    NOMATCH_SENTINEL,
    SAMPLE_ROWS,
    STRICT_TYPES,
    WRITE_SENTINEL,
)
from .heuristics import classify_mutation, classify_read, classify_write
from .http_client import parse_count, request


def probe_table(session, base_url, table):
    result = {
        "table": table,
        "status": None,
        "count": None,
        "returned": 0,
        "sample": None,
        "verdict": "?",
        "severity": "info",
        "confidence": "high",
        "error": None,
    }

    if not IDENT_RE.fullmatch(table):
        result["verdict"] = "invalid name"
        return result

    resp = request(
        session, "GET", f"{base_url}/rest/v1/{table}",
        params={"select": "*", "limit": str(SAMPLE_ROWS)},
        headers={"Prefer": "count=exact", "Range-Unit": "items"},
    )

    if isinstance(resp, Exception):
        result["error"] = str(resp)
        result["verdict"] = "error"
        result["confidence"] = "low"
        return result

    result["status"] = resp.status_code
    result["count"] = parse_count(resp.headers.get("Content-Range"))

    if resp.status_code in (200, 206):
        try:
            rows = resp.json()
        except ValueError:
            rows = []

        if isinstance(rows, list):
            result["returned"] = len(rows)
            result["sample"] = rows[:SAMPLE_ROWS]

    result["verdict"], result["severity"], result["confidence"] = classify_read(
        result["status"], result["count"], result["returned"]
    )

    return result


def pick_probe_column(coltypes):
    for col, kind in coltypes.items():
        if any(kind == t or kind.startswith(t) for t in STRICT_TYPES):
            return col

    return None


def probe_write(session, base_url, table, coltypes):
    result = {"table": table, "status": None, "code": None, "verdict": "?",
              "severity": "info", "confidence": "high", "wrote": False}

    col = pick_probe_column(coltypes)

    if not col:
        result["verdict"] = "skipped (no typed column for a safe test)"
        return result

    result["probe_column"] = col
    payload = {col: WRITE_SENTINEL}

    resp = request(
        session, "POST", f"{base_url}/rest/v1/{table}",
        json=payload,
        headers={"Prefer": "return=minimal", "Content-Type": "application/json"},
    )

    if isinstance(resp, Exception):
        result["verdict"] = "error"
        result["confidence"] = "low"
        result["error"] = str(resp)
        return result

    result["status"] = resp.status_code
    code = None

    try:
        body = resp.json()
        code = (body or {}).get("code")
    except ValueError:
        body = {}

    result["code"] = code
    (result["verdict"], result["wrote"],
     result["severity"], result["confidence"]) = classify_write(resp.status_code, code)

    return result


def _mutation_probe(session, base_url, table, coltypes, method, verb):
    result = {"table": table, "status": None, "code": None, "verdict": "?",
              "severity": "info", "confidence": "high", "passed": False}

    col = pick_probe_column(coltypes)

    if not col:
        result["verdict"] = "skipped (no typed column for a safe test)"
        return result

    result["probe_column"] = col
    kwargs = {
        "params": {col: f"eq.{NOMATCH_SENTINEL}"},
        "headers": {"Prefer": "return=minimal"},
    }

    if method == "PATCH":
        kwargs["json"] = {col: WRITE_SENTINEL}
        kwargs["headers"]["Content-Type"] = "application/json"

    resp = request(session, method, f"{base_url}/rest/v1/{table}", **kwargs)

    if isinstance(resp, Exception):
        result["verdict"] = "error"
        result["confidence"] = "low"
        result["error"] = str(resp)
        return result

    result["status"] = resp.status_code
    code = None

    try:
        code = (resp.json() or {}).get("code")
    except ValueError:
        code = None

    result["code"] = code
    (result["verdict"], result["passed"],
     result["severity"], result["confidence"]) = classify_mutation(
        resp.status_code, code, verb)

    return result


def probe_update(session, base_url, table, coltypes):
    return _mutation_probe(session, base_url, table, coltypes, "PATCH", "UPDATE")


def probe_delete(session, base_url, table, coltypes):
    return _mutation_probe(session, base_url, table, coltypes, "DELETE", "DELETE")


def dump_table(session, base_url, table, max_rows=DUMP_MAX_ROWS):
    rows = []
    offset = 0

    while len(rows) < max_rows:
        resp = request(
            session, "GET", f"{base_url}/rest/v1/{table}",
            params={"select": "*", "limit": str(DUMP_PAGE), "offset": str(offset)},
        )

        if isinstance(resp, Exception) or resp.status_code not in (200, 206):
            break

        try:
            page = resp.json()
        except ValueError:
            break

        if not isinstance(page, list) or not page:
            break

        rows.extend(page)
        offset += len(page)

        if len(page) < DUMP_PAGE:
            break

    return rows[:max_rows]
