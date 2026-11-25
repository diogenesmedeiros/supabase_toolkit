from .http_client import request


def fingerprint(session, base_url):
    print("\n[*] Fingerprinting the target...")

    result = {"server": None, "postgrest": None, "headers": {}}

    resp = request(session, "GET", f"{base_url}/rest/v1/")

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return result

    interesting = ("Server", "X-Powered-By", "sb-gateway-version",
                   "sb-project-ref", "Content-Profile", "X-Kong-Upstream-Latency")

    for header in interesting:
        value = resp.headers.get(header)

        if value:
            result["headers"][header] = value

    result["server"] = resp.headers.get("Server")

    for key in ("content-location", "server"):
        value = resp.headers.get(key, "")

        if "postgrest" in value.lower():
            result["postgrest"] = value

    if result["headers"]:
        for header, value in result["headers"].items():
            print(f"    {header}: {value}")
    else:
        print("    (no revealing header exposed)")

    return result
