import datetime
import json
import os


def save_state(path, base_url, tables_map, rpc_map):
    state = {
        "saved_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": base_url,
        "tables_map": tables_map,
        "rpc_map": rpc_map,
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2, default=str)

    print(f"[+] Session saved to: {path}")


def load_state(path, base_url):
    if not os.path.isfile(path):
        print(f"[-] Session does not exist: {path}")
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError) as error:
        print(f"[-] Failed to read session: {error}")
        return None

    if state.get("target") != base_url:
        print(f"[!] Session is from another target ({state.get('target')}); ignoring.")
        return None

    print(f"[+] Session resumed from {path} (saved at {state.get('saved_at')})")

    return state.get("tables_map") or {}, state.get("rpc_map") or {}
