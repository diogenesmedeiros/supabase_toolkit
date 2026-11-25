from .http_client import request


def check_health(session, base_url):
    print("\n[*] Checking Auth availability...")

    resp = request(session, "GET", f"{base_url}/auth/v1/health")

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return False

    print(f"[+] /auth/v1/health -> HTTP {resp.status_code}")

    return True


def extract_rpc_args(methods):
    args = []

    for method in ("post", "get"):
        op = (methods or {}).get(method) or {}

        for param in op.get("parameters", []):
            schema = param.get("schema") or {}
            props = schema.get("properties")

            if props:
                args.extend(props.keys())
            elif param.get("in") == "body" and param.get("name"):
                args.append(param["name"])
            elif param.get("name") and param.get("name") not in ("args",):
                args.append(param["name"])

        if args:
            break

    return list(dict.fromkeys(args))


def discover_schema(session, base_url):
    print("\n[*] Discovering schema via OpenAPI (/rest/v1/)...")

    resp = request(session, "GET", f"{base_url}/rest/v1/")

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return {}, {}

    print(f"[+] /rest/v1/ -> HTTP {resp.status_code}")

    if resp.status_code in (401, 403):
        print("[-] OpenAPI spec protected. Falling back to wordlist.")
        return {}, {}

    try:
        schema = resp.json()
    except ValueError:
        print("[-] Response is not valid JSON. Falling back.")
        return {}, {}

    tables = {}
    rpc = {}
    paths = schema.get("paths") or {}

    for name, body in (schema.get("definitions") or {}).items():
        props = body.get("properties") or {}
        coltypes = {}

        for col, meta in props.items():
            coltypes[col] = (meta.get("format") or meta.get("type") or "").lower()

        tables[name] = {"columns": list(props.keys()), "coltypes": coltypes}

    for path, methods in paths.items():
        if path.startswith("/rpc/"):
            fn = path[len("/rpc/"):]
            rpc[fn] = {
                "args": extract_rpc_args(methods),
                "has_get": "get" in (methods or {}),
                "has_post": "post" in (methods or {}),
            }

    for path in paths:
        name = path.strip("/")

        if name and not name.startswith("rpc") and name not in tables:
            tables[name] = {"columns": [], "coltypes": {}}

    print(f"[+] {len(tables)} table(s)/view(s) and {len(rpc)} RPC function(s) discovered.")

    return tables, rpc
