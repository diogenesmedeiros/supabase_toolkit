import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from .probes import dump_table, probe_delete, probe_table, probe_update, probe_write
from .rpc import exploit_rpc, probe_rpc


def run_tables(session, base_url, tables, workers, verbose=False, quiet=False):
    results = []
    missing = 0

    if not quiet:
        print(f"\n[*] Testing read on {len(tables)} table(s) ({workers} threads)...\n")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_table, session, base_url, t): t
            for t in tables
        }

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            if r["verdict"] == "not found/not exposed" and not verbose:
                missing += 1
                continue

            if quiet:
                continue

            tag = "[+]" if "ALLOWED" in r["verdict"] else "[-]"
            cnt = "" if r["count"] is None else f" | total={r['count']}"

            print(f"{tag} {r['table']:<28} {r['verdict']}{cnt}")

    if missing and not quiet:
        print(f"[.] {missing} name(s) returned 404 (hidden). Use --verbose to list them.")

    return sorted(results, key=lambda r: (r["verdict"] != "READ ALLOWED (data leaked)", r["table"]))


def run_rpc(session, base_url, rpc_map, workers):
    results = []

    if not rpc_map:
        return results

    print(f"\n[*] Probing {len(rpc_map)} RPC function(s) (GET, read-only)...\n")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_rpc, session, base_url, f, rpc_map[f].get("args")): f
            for f in rpc_map
        }

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            tag = "[+]" if r.get("status") == 200 else "[-]"
            op = r.get("op", "?")
            args = ", ".join(r.get("args") or []) or "—"

            print(f"{tag} rpc/{r['rpc']:<26} [{op}] {r['verdict']}")
            print(f"      args: {args}")

    return sorted(results, key=lambda r: r["rpc"])


def run_rpc_exploit(session, base_url, rpc_map, workers):
    results = []

    if not rpc_map:
        return results

    print(f"\n[*] Exploiting {len(rpc_map)} RPC(s) via POST (read invoked, write flagged)...\n")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(exploit_rpc, session, base_url, f,
                        rpc_map[f].get("args"), None): f
            for f in rpc_map
        }

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            tag = "[+]" if r.get("leaked") else "[-]"

            print(f"{tag} rpc/{r['rpc']:<26} [{r['op']}] {r['verdict']}")

    return sorted(results, key=lambda r: r["rpc"])


def run_writes(session, base_url, tables_map, exposed, workers):
    results = []
    targets = [t for t in exposed if tables_map.get(t, {}).get("coltypes")]

    if not targets:
        print("\n[*] Write probe: no table with column metadata.")
        return results

    print(f"\n[*] WRITE PROBE (non-destructive INSERT) on {len(targets)} table(s)...")
    print("    Invalid values are sent; nothing is written.\n")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_write, session, base_url, t,
                        tables_map[t]["coltypes"]): t
            for t in targets
        }

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            tag = "[+]" if ("ALLOWED" in r["verdict"] or r["wrote"]) else "[-]"

            print(f"{tag} {r['table']:<28} {r['verdict']}")

    return results


def _run_mutation(session, base_url, tables_map, exposed, workers, probe_fn, label):
    results = []
    targets = [t for t in exposed if tables_map.get(t, {}).get("coltypes")]

    if not targets:
        print(f"\n[*] {label} probe: no table with column metadata.")
        return results

    print(f"\n[*] {label.upper()} PROBE (non-destructive) on {len(targets)} table(s)...\n")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_fn, session, base_url, t,
                        tables_map[t]["coltypes"]): t
            for t in targets
        }

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

            tag = "[+]" if r.get("passed") else "[-]"

            print(f"{tag} {r['table']:<28} {r['verdict']}")

    return results


def run_updates(session, base_url, tables_map, exposed, workers):
    return _run_mutation(session, base_url, tables_map, exposed, workers,
                         probe_update, "update")


def run_deletes(session, base_url, tables_map, exposed, workers):
    return _run_mutation(session, base_url, tables_map, exposed, workers,
                         probe_delete, "delete")


def run_dump(session, base_url, leaked_tables, out_dir, max_rows):
    if not leaked_tables:
        return {}

    os.makedirs(out_dir, exist_ok=True)

    print(f"\n[*] DUMP of {len(leaked_tables)} readable table(s) -> {out_dir}/\n")

    summary = {}

    for table in leaked_tables:
        rows = dump_table(session, base_url, table, max_rows)
        path = os.path.join(out_dir, f"{table}.json")

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, ensure_ascii=False, indent=2, default=str)

        summary[table] = len(rows)
        print(f"[+] {table:<28} {len(rows)} row(s) -> {path}")

    return summary
