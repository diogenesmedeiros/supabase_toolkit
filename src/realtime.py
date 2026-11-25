import json
import time

try:
    import websocket as _ws
except ImportError:
    _ws = None


def available():
    return _ws is not None


def _ws_url(base_url, apikey):
    host = base_url.replace("https://", "", 1).replace("http://", "", 1)

    return f"wss://{host}/realtime/v1/websocket?apikey={apikey}&vsn=1.0.0"


def check_realtime(base_url, apikey, tables=None, findings=None, duration=6):
    print("\n[*] Auditing Realtime (websocket)...")

    result = {"supported": available(), "joined": [], "leaked": [], "messages": 0}

    if not available():
        print("[-] Module 'websocket-client' missing. "
              "Install with: pip install websocket-client")
        return result

    tables = list(tables or [])[:10]

    if not tables:
        print("[-] No tables to subscribe to.")
        return result

    try:
        conn = _ws.create_connection(_ws_url(base_url, apikey), timeout=duration)
    except Exception as error:
        print(f"[!] Failed to connect: {error}")
        return result

    ref = 0

    for table in tables:
        ref += 1
        join = {
            "topic": f"realtime:public:{table}",
            "event": "phx_join",
            "payload": {
                "config": {
                    "postgres_changes": [
                        {"event": "*", "schema": "public", "table": table}
                    ]
                }
            },
            "ref": str(ref),
        }

        try:
            conn.send(json.dumps(join))
        except Exception:
            break

    conn.settimeout(duration)
    deadline = time.time() + duration

    while time.time() < deadline:
        try:
            raw = conn.recv()
        except Exception:
            break

        if not raw:
            continue

        try:
            msg = json.loads(raw)
        except ValueError:
            continue

        event = msg.get("event")
        topic = msg.get("topic", "")
        table = topic.rsplit(":", 1)[-1]

        if event == "phx_reply":
            status = (msg.get("payload") or {}).get("status")

            if status == "ok" and table not in result["joined"]:
                result["joined"].append(table)
                print(f"[+] Subscription accepted on public:{table}")
        elif event == "postgres_changes":
            result["messages"] += 1

            if table not in result["leaked"]:
                result["leaked"].append(table)
                print(f"[!] Data received via Realtime on '{table}' (possible leak)")

    try:
        conn.close()
    except Exception:
        pass

    if findings:
        for table in result["leaked"]:
            findings.add("high", "realtime",
                         f"Table '{table}' emits changes via Realtime to the key used",
                         None, "high")

    if not result["joined"]:
        print("[-] No subscription confirmed.")

    return result
