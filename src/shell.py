import json

from .constants import IDENT_RE
from .formatting import confirm, parse_filter, show_response
from .http_client import parse_count, request
from .rpc import classify_rpc_op

SHELL_HELP = """
Commands (always operate on the CURRENT TABLE):
  tables                  list known tables
  use <table>             select the current table
  cols                    show columns and types of the current table
  count [filter]          total rows (count=exact). Ex: count status=eq.active
  view [limit] [filter]   view rows (default limit 10). Ex: view 20 active=eq.true
  select <filter>         same as view, with filter. Ex: select id=eq.5
  insert <json>           INSERT a row. Ex: insert {"name":"x","age":9}
  update <filter> <json>  UPDATE rows matching the filter. Ex: update id=eq.5 {"name":"y"}
  delete <filter>         DELETE rows matching the filter. Ex: delete id=eq.5
  rpcs                    RPCs correlated with the current table
  allrpcs                 list ALL known RPC functions
  call <function> [json]  call an RPC (POST). Ex: call create_tenant {"name":"x"}
  help                    show this help
  exit                    quit the tool
"""


def sh_view(session, base_url, table, args_str):
    tokens = args_str.split()
    limit = "10"

    if tokens and tokens[0].isdigit():
        limit = tokens.pop(0)

    params = parse_filter(" ".join(tokens))
    params.update({"select": "*", "limit": limit})

    resp = request(session, "GET", f"{base_url}/rest/v1/{table}",
                   params=params, headers={"Prefer": "count=exact"})

    show_response(resp, f"view {table} (limit {limit})")


def sh_count(session, base_url, table, args_str):
    params = parse_filter(args_str)
    params.update({"select": "*", "limit": "1"})

    resp = request(session, "GET", f"{base_url}/rest/v1/{table}",
                   params=params, headers={"Prefer": "count=exact"})

    if isinstance(resp, Exception):
        print(f"[!] Connection error: {resp}")
        return

    total = parse_count(resp.headers.get("Content-Range"))

    print(f"[+] {table}: total = {total if total is not None else '?'} "
          f"(HTTP {resp.status_code})")


def sh_insert(session, base_url, table, args_str):
    try:
        payload = json.loads(args_str)
    except json.JSONDecodeError as error:
        print(f"[-] Invalid JSON: {error}")
        return

    print(f"[*] INSERT into '{table}': {json.dumps(payload, ensure_ascii=False)}")

    if not confirm("Confirm insert?"):
        print("[.] Cancelled.")
        return

    resp = request(session, "POST", f"{base_url}/rest/v1/{table}",
                   json=payload,
                   headers={"Prefer": "return=representation",
                            "Content-Type": "application/json"})

    show_response(resp, f"insert {table}")


def _split_filter_json(args_str):
    brace = args_str.find("{")

    if brace == -1:
        return args_str.strip(), None

    return args_str[:brace].strip(), args_str[brace:].strip()


def sh_update(session, base_url, table, args_str):
    filter_str, json_str = _split_filter_json(args_str)

    if not json_str:
        print("[-] Usage: update <filter> <json>. Ex: update id=eq.5 {\"n\":1}")
        return

    try:
        payload = json.loads(json_str)
    except json.JSONDecodeError as error:
        print(f"[-] Invalid JSON: {error}")
        return

    params = parse_filter(filter_str)

    if not params:
        print("[!!] NO FILTER: this UPDATES **ALL** rows in "
              f"'{table}'.")

        if input(f"    Type the table name to confirm: ").strip() != table:
            print("[.] Cancelled.")
            return
    else:
        print(f"[*] UPDATE on '{table}' where {filter_str} -> "
              f"{json.dumps(payload, ensure_ascii=False)}")

        if not confirm("Confirm update?"):
            print("[.] Cancelled.")
            return

    resp = request(session, "PATCH", f"{base_url}/rest/v1/{table}",
                   params=params, json=payload,
                   headers={"Prefer": "return=representation",
                            "Content-Type": "application/json"})

    show_response(resp, f"update {table}")


def sh_delete(session, base_url, table, args_str):
    filter_str = args_str.strip()
    params = parse_filter(filter_str)

    if not params:
        print("[!!] NO FILTER: this DELETES **ALL** rows in "
              f"'{table}'.")

        if input(f"    Type the table name to confirm: ").strip() != table:
            print("[.] Cancelled.")
            return
    else:
        print(f"[*] DELETE on '{table}' where {filter_str}")

        if not confirm("Confirm delete?"):
            print("[.] Cancelled.")
            return

    resp = request(session, "DELETE", f"{base_url}/rest/v1/{table}",
                   params=params, headers={"Prefer": "return=representation"})

    show_response(resp, f"delete {table}")


def sh_rpc_call(session, base_url, fn, args_str):
    if not IDENT_RE.fullmatch(fn or ""):
        print("[-] Invalid function name.")
        return

    body = {}

    if args_str.strip():
        try:
            body = json.loads(args_str)
        except json.JSONDecodeError as error:
            print(f"[-] Invalid JSON: {error}")
            return

    print(f"[*] CALL rpc/{fn} {json.dumps(body, ensure_ascii=False)}")
    print("    (RPC may write/alter data — it is a real POST)")

    if not confirm("Confirm call?"):
        print("[.] Cancelled.")
        return

    resp = request(session, "POST", f"{base_url}/rest/v1/rpc/{fn}",
                   json=body, headers={"Content-Type": "application/json"})

    show_response(resp, f"rpc/{fn}")


def interactive_shell(session, base_url, tables_map, rpc_map=None,
                      correlation=None):
    rpc_map = rpc_map or {}
    correlation = correlation or {}
    known = sorted(tables_map.keys())
    current = known[0] if len(known) == 1 else None

    print("\n" + "=" * 46)
    print("  INTERACTIVE MODE  (type 'help' or 'exit')")
    print("=" * 46)

    if known:
        print(f"[*] {len(known)} known table(s). 'tables' to list.")
    else:
        print("[*] No table via OpenAPI. Use 'use <table>' manually.")

    while True:
        prompt = f"supabase:{current or '-'}> "

        try:
            line = input(prompt).strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print("\n[.] (use 'exit' to quit)")
            continue

        if not line:
            continue

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd == "exit":
            break

        if cmd == "help":
            print(SHELL_HELP)
            continue

        if cmd == "tables":
            if known:
                for t in known:
                    mark = " *" if t == current else ""
                    print(f"    {t}{mark}")
            else:
                print("    (none discovered; use 'use <table>')")

            continue

        if cmd == "use":
            name = rest.strip()

            if not IDENT_RE.fullmatch(name or ""):
                print("[-] Invalid table name.")
                continue

            current = name

            if known and name not in known:
                print(f"[!] '{name}' did not appear in the spec; testing anyway.")

            print(f"[+] Current table: {current}")
            continue

        if cmd in ("call", "rpc"):
            fn_parts = rest.split(maxsplit=1)

            if not fn_parts:
                print("[-] Usage: call <function> [json]. "
                      "Ex: call create_tenant {\"name\":\"x\"}")
            else:
                sh_rpc_call(session, base_url, fn_parts[0],
                            fn_parts[1] if len(fn_parts) > 1 else "")

            continue

        if cmd == "allrpcs":
            if rpc_map:
                for fn in sorted(rpc_map):
                    op = classify_rpc_op(fn)
                    args = ", ".join(rpc_map[fn].get("args") or []) or "—"
                    print(f"    [{op.upper():<10}] {fn}  (args: {args})")
            else:
                print("    (no known RPC)")

            continue

        if not current:
            print("[-] Select a table first: use <table>")
            continue

        if cmd == "cols":
            cols = tables_map.get(current, {}).get("coltypes") or {}

            if cols:
                for c, t in cols.items():
                    print(f"    {c}: {t}")
            else:
                print("    (no column metadata for this table)")
        elif cmd in ("view", "select"):
            sh_view(session, base_url, current, rest)
        elif cmd == "count":
            sh_count(session, base_url, current, rest)
        elif cmd == "insert":
            sh_insert(session, base_url, current, rest)
        elif cmd == "update":
            sh_update(session, base_url, current, rest)
        elif cmd == "delete":
            sh_delete(session, base_url, current, rest)
        elif cmd == "rpcs":
            related = correlation.get(current, [])

            if related:
                print(f"    RPCs related to '{current}':")

                for fn, op in related:
                    args = ", ".join(rpc_map.get(fn, {}).get("args") or []) or "—"
                    print(f"      [{op.upper():<10}] {fn}  (args: {args})")
            else:
                print(f"    (no RPC correlated with '{current}')")

            print("    Use: call <function> {json}")
        else:
            print(f"[-] Unknown command: {cmd}. Type 'help'.")

    print("[+] Session ended.")
