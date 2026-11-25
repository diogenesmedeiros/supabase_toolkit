from .http_client import request


def list_objects(session, base_url, bucket):
    resp = request(session, "POST",
                   f"{base_url}/storage/v1/object/list/{bucket}",
                   json={"prefix": "", "limit": 100, "offset": 0},
                   headers={"Content-Type": "application/json"})

    if isinstance(resp, Exception) or resp.status_code != 200:
        return []

    try:
        items = resp.json()
    except ValueError:
        return []

    if not isinstance(items, list):
        return []

    return [i.get("name") for i in items if isinstance(i, dict) and i.get("name")]


def check_storage(session, base_url, findings=None):
    print("\n[*] Auditing Storage (/storage/v1)...")

    result = {"buckets": [], "status": None}

    resp = request(session, "GET", f"{base_url}/storage/v1/bucket")

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return result

    result["status"] = resp.status_code
    print(f"[+] /storage/v1/bucket -> HTTP {resp.status_code}")

    if resp.status_code != 200:
        print("[-] Bucket listing not allowed for this key.")
        return result

    try:
        buckets = resp.json()
    except ValueError:
        buckets = []

    if not isinstance(buckets, list):
        return result

    for b in buckets:
        name = b.get("id") or b.get("name")
        public = bool(b.get("public"))
        entry = {"name": name, "public": public, "objects": []}

        tag = "PUBLIC" if public else "private"
        print(f"    - {name}  [{tag}]")

        if public:
            entry["objects"] = list_objects(session, base_url, name)

            if entry["objects"]:
                print(f"        {len(entry['objects'])} object(s): "
                      f"{', '.join(entry['objects'][:5])}")

            if findings:
                findings.add("high", "storage",
                             f"Public bucket '{name}' exposes objects",
                             {"listed_objects": len(entry["objects"])}, "high")

        result["buckets"].append(entry)

    return result
