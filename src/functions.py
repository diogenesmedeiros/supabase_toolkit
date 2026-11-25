from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import COMMON_FUNCTIONS
from .http_client import request


def probe_function(session, base_url, name):
    resp = request(session, "GET", f"{base_url}/functions/v1/{name}")

    if isinstance(resp, Exception):
        return {"name": name, "status": None, "verdict": "error"}

    status = resp.status_code

    if status == 404:
        verdict = "not found"
    elif status in (401, 403):
        verdict = "exists (requires authorization)"
    elif status in (200, 204):
        verdict = "ACCESSIBLE (no auth)"
    elif status == 405:
        verdict = "exists (requires POST)"
    else:
        verdict = f"HTTP {status}"

    return {"name": name, "status": status, "verdict": verdict}


def check_functions(session, base_url, names=None, workers=10, findings=None):
    names = list(dict.fromkeys(names or COMMON_FUNCTIONS))

    print(f"\n[*] Enumerating Edge Functions (/functions/v1) over {len(names)} name(s)...")

    results = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_function, session, base_url, n): n
            for n in names
        }

        for fut in as_completed(futures):
            r = fut.result()

            if r["status"] in (404, None):
                continue

            results.append(r)
            tag = "[+]" if r["status"] in (200, 204) else "[-]"
            print(f"{tag} functions/{r['name']:<24} {r['verdict']}")

            if findings and r["status"] in (200, 204):
                findings.add("medium", "functions",
                             f"Edge Function '{r['name']}' accessible without authorization",
                             None, "high")

    if not results:
        print("[-] No function found (or names outside the wordlist).")

    return sorted(results, key=lambda r: r["name"])
