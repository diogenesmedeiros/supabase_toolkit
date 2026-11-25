import json


def parse_filter(filter_str):
    params = {}

    for part in (filter_str or "").split("&"):
        part = part.strip()

        if not part or "=" not in part:
            continue

        key, value = part.split("=", 1)
        params[key.strip()] = value.strip()

    return params


def fmt_rows(rows, max_val=80):
    if not isinstance(rows, list):
        print(f"    {rows}")
        return

    if not rows:
        print("    (0 rows)")
        return

    for i, row in enumerate(rows, 1):
        print(f"  #{i}")

        if isinstance(row, dict):
            for k, v in row.items():
                s = json.dumps(v, ensure_ascii=False, default=str)

                if len(s) > max_val:
                    s = s[:max_val] + "..."

                print(f"      {k}: {s}")
        else:
            print(f"      {row}")


def confirm(prompt):
    try:
        return input(f"{prompt} (y/N): ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def show_response(resp, action):
    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return

    ok = resp.status_code in (200, 201, 204, 206)
    tag = "[+]" if ok else "[-]"

    print(f"{tag} {action}: HTTP {resp.status_code}")

    cr = resp.headers.get("Content-Range")

    if cr:
        print(f"    Content-Range: {cr}")

    body = None

    try:
        body = resp.json()
    except ValueError:
        if resp.text:
            print(f"    {resp.text[:300]}")

        return

    if isinstance(body, dict) and body.get("code"):
        print(f"    error code={body.get('code')}: {body.get('message')}")

        if body.get("hint"):
            print(f"    hint: {body['hint']}")

        return

    if isinstance(body, list):
        print(f"    {len(body)} row(s):")

    fmt_rows(body)
