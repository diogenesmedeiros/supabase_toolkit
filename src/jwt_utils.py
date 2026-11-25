import base64
import binascii
import datetime
import json


def _b64url_decode(segment):
    pad = "=" * (-len(segment) % 4)

    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (binascii.Error, ValueError):
        return None


def decode_jwt(token):
    if not token:
        return None

    token = token.strip()

    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")

    if len(parts) != 3:
        return None

    raw_header = _b64url_decode(parts[0])
    raw_payload = _b64url_decode(parts[1])

    if raw_header is None or raw_payload is None:
        return None

    try:
        header = json.loads(raw_header)
        payload = json.loads(raw_payload)
    except ValueError:
        return None

    return {"header": header, "payload": payload}


def analyze_key(token):
    info = {
        "is_jwt": False,
        "alg": None,
        "role": None,
        "ref": None,
        "iss": None,
        "exp": None,
        "expired": None,
        "service_role": False,
        "notes": [],
    }

    decoded = decode_jwt(token)

    if not decoded:
        info["notes"].append("not a decodable JWT (may be a new publishable/secret key)")
        return info

    header = decoded["header"]
    payload = decoded["payload"]

    info["is_jwt"] = True
    info["alg"] = header.get("alg")
    info["role"] = payload.get("role")
    info["ref"] = payload.get("ref")
    info["iss"] = payload.get("iss")

    exp = payload.get("exp")

    if isinstance(exp, (int, float)):
        when = datetime.datetime.utcfromtimestamp(exp)
        info["exp"] = when.isoformat() + "Z"
        info["expired"] = when < datetime.datetime.utcnow()

    if info["role"] == "service_role":
        info["service_role"] = True
        info["notes"].append("service_role: bypasses RLS — must NEVER be exposed to the client")

    if info["alg"] and info["alg"].lower() == "none":
        info["notes"].append("alg=none: signature not verified")

    return info
