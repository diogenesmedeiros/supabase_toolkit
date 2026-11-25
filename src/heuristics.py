from .constants import PASSED_AUTH_CODES


def classify_read(status, count, returned):
    if status in (200, 206):
        if returned and returned > 0:
            return "READ ALLOWED (data leaked)", "high", "high"

        if count:
            return "accessible, 0 rows visible (RLS likely)", "info", "high"

        return "accessible, empty table", "info", "medium"

    if status == 401:
        return "unauthorized", "info", "high"

    if status == 403:
        return "forbidden (RLS active)", "info", "high"

    if status == 404:
        return "not found/not exposed", "info", "high"

    return f"HTTP {status}", "info", "low"


def classify_write(status, code):
    if status in (200, 201, 204):
        return "!! INSERT ACCEPTED (row written!) VULNERABLE", True, "critical", "high"

    if status in (401, 403) or code == "42501":
        return "write blocked (RLS/grant) — safe", False, "info", "high"

    if code in PASSED_AUTH_CODES:
        return "WRITE ALLOWED (RLS permits INSERT) — vulnerable", False, "high", "medium"

    if code == "PGRST204":
        return "inconclusive (column rejected before authorization)", False, "info", "low"

    return f"inconclusive (HTTP {status}, code={code})", False, "info", "low"


def classify_mutation(status, code, verb):
    high = "critical" if verb == "DELETE" else "high"

    if status in (200, 201, 204, 206):
        return f"{verb} AUTHORIZED (passed RLS) — review", True, high, "high"

    if status in (401, 403) or code == "42501":
        return f"{verb} blocked (RLS/grant) — safe", False, "info", "high"

    if code in PASSED_AUTH_CODES:
        return f"{verb} ALLOWED (RLS permits) — vulnerable", True, high, "medium"

    if code == "PGRST204":
        return "inconclusive (column rejected before authorization)", False, "info", "low"

    return f"inconclusive (HTTP {status}, code={code})", False, "info", "low"


def classify_rpc_access(status):
    table = {
        200: ("CALLABLE via GET (returned data)", "medium", "high"),
        204: ("callable, no content", "low", "medium"),
        400: ("requires arguments", "info", "high"),
        401: ("unauthorized", "info", "high"),
        403: ("forbidden", "info", "high"),
        404: ("not found", "info", "high"),
        405: ("requires POST (volatile/write)", "info", "high"),
    }

    return table.get(status, (f"HTTP {status}", "info", "low"))
