def parse_request_file(path):
    result = {"url": None, "apikey": None, "authorization": None}

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    if not lines:
        raise ValueError("Empty request file.")

    first = lines[0].split()

    if len(first) < 2:
        raise ValueError("Invalid request line.")

    target = first[1]
    headers = {}

    for line in lines[1:]:
        if not line.strip():
            break

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    host = headers.get("host")
    scheme = "https"

    if target.startswith("http"):
        result["url"] = target
    elif host:
        result["url"] = f"{scheme}://{host}"

    result["apikey"] = headers.get("apikey")
    result["authorization"] = headers.get("authorization")

    return result
