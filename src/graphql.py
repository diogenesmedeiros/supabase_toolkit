from .http_client import request

INTROSPECTION = {
    "query": "query{__schema{queryType{name} types{name kind}}}"
}


def check_graphql(session, base_url, findings=None):
    print("\n[*] Auditing GraphQL (/graphql/v1)...")

    result = {"status": None, "introspection": False, "types": []}

    resp = request(session, "POST", f"{base_url}/graphql/v1",
                   json=INTROSPECTION,
                   headers={"Content-Type": "application/json"})

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return result

    result["status"] = resp.status_code
    print(f"[+] /graphql/v1 -> HTTP {resp.status_code}")

    if resp.status_code != 200:
        return result

    try:
        body = resp.json()
    except ValueError:
        return result

    schema = (body.get("data") or {}).get("__schema")

    if schema:
        result["introspection"] = True
        types = [t.get("name") for t in (schema.get("types") or [])
                 if t.get("name") and not t.get("name").startswith("__")]
        result["types"] = types

        print(f"[+] Introspection ENABLED — {len(types)} type(s) exposed.")

        if findings:
            findings.add("medium", "graphql",
                         "GraphQL introspection enabled",
                         {"types": len(types)}, "high")
    else:
        print("[-] Introspection did not return a schema.")

    return result
