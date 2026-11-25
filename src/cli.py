import argparse
import datetime
import os
import shutil
import sys
from getpass import getpass

from .auth import check_auth
from .constants import DEFAULT_WORDLIST, DUMP_MAX_ROWS, TOR_DEFAULT_PORT, TOR_PROXY
from .diff import compute_diff, print_diff
from .discovery import check_health, discover_schema
from .findings import Findings, print_findings
from .fingerprint import fingerprint
from .functions import check_functions
from .graphql import check_graphql
from .harvest import harvest_from_url
from .http_client import build_session, normalize_url
from .jwt_utils import analyze_key
from .realtime import check_realtime
from .report import export_findings, print_correlation, save_report, summarize
from .request_file import parse_request_file
from .rpc import correlate_rpc
from .scanner import (
    run_deletes,
    run_dump,
    run_rpc,
    run_rpc_exploit,
    run_tables,
    run_updates,
    run_writes,
)
from .session_state import load_state, save_state
from .shell import interactive_shell
from .storage import check_storage
from .wordlist import load_builtin_wordlist, load_wordlist


def banner():
    print("""
╔══════════════════════════════════════════╗
║             SUPABASE TOOL KIT            ║
╚══════════════════════════════════════════╝
""")


def build_parser():
    parser = argparse.ArgumentParser(description="Supabase REST/RLS/Auth/Storage auditor")

    parser.add_argument("--url", help="Supabase URL")
    parser.add_argument("--apikey", help="apikey (anon/service). Omit for a secure prompt.")
    parser.add_argument("--auth", help="Authorization bearer token (optional)")
    parser.add_argument("--service-key", help="service_role apikey for anon x service_role diff")
    parser.add_argument("-r", "--request-file", help="file with a raw HTTP request (sqlmap style)")
    parser.add_argument("--harvest", help="crawl a website for url/keys before auditing")

    parser.add_argument("--level", type=int, default=1, choices=(1, 2, 3),
                        help="1=REST+RPC, 2=+auth/storage/graphql/functions, 3=+realtime")
    parser.add_argument("--risk", type=int, default=1, choices=(1, 2, 3),
                        help="1=read-only, 2=+insert, 3=+update/delete")

    parser.add_argument("--auth-scan", action="store_true", help="audit GoTrue /auth/v1")
    parser.add_argument("--storage", action="store_true", help="audit Storage /storage/v1")
    parser.add_argument("--graphql", action="store_true", help="audit GraphQL /graphql/v1")
    parser.add_argument("--functions", action="store_true", help="enumerate Edge Functions")
    parser.add_argument("--functions-wordlist", help="wordlist of edge function names")
    parser.add_argument("--realtime", action="store_true", help="audit Realtime (websocket)")
    parser.add_argument("--realtime-time", type=int, default=6, help="seconds to listen on Realtime")
    parser.add_argument("--no-fingerprint", action="store_true", help="do not fingerprint")

    parser.add_argument("--workers", type=int, default=10, help="threads (default 10)")
    parser.add_argument("--report", help="save JSON report to this path")
    parser.add_argument("--export", help="export findings (.md/.csv/.html)")
    parser.add_argument("--no-rpc", action="store_true", help="do not probe RPC functions")
    parser.add_argument("--rpc-exec", action="store_true",
                        help="exploit RPCs via POST (invoke read, flag write)")
    parser.add_argument("--wordlist", "-w", help=".txt file with table names (one per line)")
    parser.add_argument("--no-builtin", action="store_true",
                        help="do not use the built-in wordlist (only OpenAPI + --wordlist)")
    parser.add_argument("--schema-only", action="store_true",
                        help="test only tables discovered via OpenAPI (no brute-force)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="also list 404s (hidden) during brute-force")
    parser.add_argument("--write-test", action="store_true",
                        help="non-destructive INSERT write probe (same as --risk 2)")

    parser.add_argument("--dump", action="store_true", help="dump readable tables (paginated)")
    parser.add_argument("--dump-dir", help="dump output directory")
    parser.add_argument("--dump-max", type=int, default=DUMP_MAX_ROWS, help="max rows per table")

    parser.add_argument("--save-session", help="save the discovered schema to this file")
    parser.add_argument("--resume", help="resume the schema from a session file")

    parser.add_argument("--proxy", help="http(s)/socks proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--tor", action="store_true", help="route via Tor (SOCKS 127.0.0.1)")
    parser.add_argument("--tor-port", type=int, default=TOR_DEFAULT_PORT,
                        help=f"Tor SOCKS port (default {TOR_DEFAULT_PORT})")
    parser.add_argument("--proxychains", action="store_true",
                        help="re-exec the tool under proxychains/proxychains4")
    parser.add_argument("--delay", type=float, default=0.0, help="delay between requests (s)")
    parser.add_argument("--retries", type=int, default=0, help="extra attempts on network failure")
    parser.add_argument("--random-ua", "--random-agent", dest="random_ua",
                        action="store_true", help="random User-Agent per request")
    parser.add_argument("--insecure", action="store_true", help="do not validate the TLS certificate")
    parser.add_argument("--timeout", type=int, default=15, help="timeout per request (s)")

    parser.add_argument("--shell", "-i", action="store_true",
                        help="interactive CRUD mode after the audit (quit with 'exit')")

    return parser


def maybe_proxychains(enabled):
    if not enabled:
        return

    if os.environ.get("STK_PROXYCHAINS"):
        return

    binary = shutil.which("proxychains4") or shutil.which("proxychains")

    if not binary:
        print("[!] proxychains not found in PATH; continuing without it.")
        return

    print(f"[*] Re-executing under {binary} ...")
    os.environ["STK_PROXYCHAINS"] = "1"
    os.execvp(binary, [binary, sys.executable, *sys.argv])


def resolve_proxy(args):
    if args.proxy:
        if args.tor:
            print("[!] --proxy and --tor both given; using --proxy.")

        return args.proxy

    if args.tor:
        return TOR_PROXY.format(port=args.tor_port)

    return None


def enabled_surfaces(args):
    explicit = {
        "auth": args.auth_scan,
        "storage": args.storage,
        "graphql": args.graphql,
        "functions": args.functions,
        "realtime": args.realtime,
    }

    surfaces = {k for k, v in explicit.items() if v}

    if not any(explicit.values()):
        if args.level >= 2:
            surfaces |= {"auth", "storage", "graphql", "functions"}

        if args.level >= 3:
            surfaces |= {"realtime"}

    return surfaces


def resolve_credentials(args, proxy=None):
    url = args.url
    apikey = args.apikey
    authorization = args.auth

    if args.request_file:
        parsed = parse_request_file(args.request_file)
        url = url or parsed["url"]
        apikey = apikey or parsed["apikey"]

        if authorization is None:
            authorization = parsed["authorization"]

    if args.harvest:
        found = harvest_from_url(args.harvest, timeout=args.timeout, proxy=proxy)

        if not url and found["urls"]:
            url = found["urls"][0]

        if not apikey and found["jwts"]:
            apikey = found["jwts"][0]

    url = normalize_url(url or input("Supabase URL: "))
    apikey = apikey or getpass("API Key: ")

    if authorization is None:
        authorization = getpass("Authorization (Enter to skip): ")

    if not apikey:
        raise ValueError("API Key is required.")

    return url, apikey, authorization


def collect_targets(args, discovered):
    wordlist = []

    if not args.schema_only:
        if not args.no_builtin:
            wordlist += load_builtin_wordlist()

        if args.wordlist:
            wordlist += load_wordlist(args.wordlist)

    if args.schema_only and not discovered:
        print("[!] --schema-only with no discovered tables. Nothing to test.")

    return list(dict.fromkeys([*discovered, *wordlist]))


def report_key(apikey, authorization, findings):
    print("\n[*] Analyzing the key...")

    key_info = analyze_key(apikey)

    print(f"    role: {key_info.get('role') or '?'}  "
          f"alg: {key_info.get('alg') or '?'}  "
          f"exp: {key_info.get('exp') or '?'}")

    for note in key_info.get("notes", []):
        print(f"    [!] {note}")

    if key_info.get("expired"):
        findings.add("info", "auth", "Provided key is expired", None, "high")

    auth_info = analyze_key(authorization) if authorization else None

    if auth_info and auth_info.get("service_role"):
        findings.add("critical", "auth",
                     "Authorization token is service_role (bypasses RLS)", None, "high")

    return key_info


def run_surfaces(session, base_url, surfaces, args, findings, key_info,
                 real_tables, apikey):
    out = {}

    if surfaces == set():
        return out

    if "auth" in surfaces:
        out["auth"] = check_auth(session, base_url, findings, key_info, args.risk)

    if "storage" in surfaces:
        out["storage"] = check_storage(session, base_url, findings)

    if "graphql" in surfaces:
        out["graphql"] = check_graphql(session, base_url, findings)

    if "functions" in surfaces:
        names = None

        if args.functions_wordlist:
            names = load_wordlist(args.functions_wordlist)

        out["functions"] = check_functions(session, base_url, names,
                                            args.workers, findings)

    if "realtime" in surfaces:
        out["realtime"] = check_realtime(base_url, apikey, real_tables,
                                         findings, args.realtime_time)

    return out


def record_table_findings(findings, table_results, write_results,
                          update_results, delete_results, rpc_exploit=None):
    for r in table_results:
        if r.get("severity", "info") != "info":
            findings.add(r["severity"], "rest",
                         f"Read allowed on '{r['table']}' (missing/permissive RLS)",
                         {"rows": r.get("count")}, r.get("confidence"))

    for r in write_results or []:
        if r.get("wrote") or "ALLOWED" in r.get("verdict", ""):
            findings.add(r.get("severity", "high"), "rest",
                         f"INSERT passed authorization on '{r['table']}'"
                         + (" (WROTE)" if r.get("wrote") else ""),
                         None, r.get("confidence"))

    for r in (update_results or []) + (delete_results or []):
        if r.get("passed"):
            verb = r["verdict"].split()[0]
            findings.add(r.get("severity", "high"), "rest",
                         f"{verb} passed authorization on '{r['table']}'",
                         None, r.get("confidence"))

    for r in rpc_exploit or []:
        if r.get("leaked"):
            findings.add(r.get("severity", "high"), "rpc",
                         f"RPC '{r['rpc']}' leaked data via POST",
                         {"op": r.get("op")}, r.get("confidence"))


def main():
    args = build_parser().parse_args()

    maybe_proxychains(args.proxychains)

    banner()
    print("[CONFIGURATION]")

    proxy = resolve_proxy(args)

    if proxy:
        print(f"[*] Proxy: {proxy}")

    base_url, apikey, authorization = resolve_credentials(args, proxy)

    session = build_session(apikey, authorization, proxy=proxy,
                            delay=args.delay, retries=args.retries,
                            random_ua=args.random_ua, insecure=args.insecure,
                            timeout=args.timeout)

    findings = Findings()
    key_info = report_key(apikey, authorization, findings)

    if not args.no_fingerprint:
        fingerprint(session, base_url)

    check_health(session, base_url)

    resumed = load_state(args.resume, base_url) if args.resume else None

    if resumed:
        tables_map, rpc_map = resumed
    else:
        tables_map, rpc_map = discover_schema(session, base_url)

    if args.save_session:
        save_state(args.save_session, base_url, tables_map, rpc_map)

    discovered = list(tables_map.keys())
    table_names = collect_targets(args, discovered)

    if not table_names:
        raise ValueError(
            "No target to test. You need a wordlist: "
            "provide --wordlist file.txt or make sure "
            f"{DEFAULT_WORDLIST} exists (or use --schema-only if the OpenAPI "
            "spec is accessible)."
        )

    print(f"[*] Targets: {len(discovered)} from spec + {len(table_names) - len(discovered)} "
          f"from wordlist = {len(table_names)} unique name(s).")

    table_results = run_tables(session, base_url, table_names, args.workers, args.verbose)

    exposed = [r["table"] for r in table_results
               if r.get("status") in (200, 206, 401, 403)]
    real_tables = list(dict.fromkeys([*discovered, *exposed]))

    rpc_results = []
    rpc_exploit = []

    if rpc_map and not args.no_rpc:
        rpc_results = run_rpc(session, base_url, rpc_map, args.workers)

        if args.rpc_exec:
            rpc_exploit = run_rpc_exploit(session, base_url, rpc_map, args.workers)

    correlation = correlate_rpc(real_tables, rpc_map)
    print_correlation(correlation, rpc_map)

    risk = max(args.risk, 2) if args.write_test else args.risk

    write_results = []
    update_results = []
    delete_results = []

    if risk >= 2:
        write_results = run_writes(session, base_url, tables_map, exposed, args.workers)

    if risk >= 3:
        update_results = run_updates(session, base_url, tables_map, exposed, args.workers)
        delete_results = run_deletes(session, base_url, tables_map, exposed, args.workers)

    surfaces = run_surfaces(session, base_url, enabled_surfaces(args), args,
                            findings, key_info, real_tables, apikey)

    surfaces["rpc_exploit"] = rpc_exploit

    diff_rows = []

    if args.service_key:
        print("\n[*] Running control scan with service_role for diff...")
        svc_session = build_session(args.service_key, None, proxy=proxy,
                                    delay=args.delay, retries=args.retries,
                                    random_ua=args.random_ua, insecure=args.insecure,
                                    timeout=args.timeout)
        svc_results = run_tables(svc_session, base_url, real_tables,
                                 args.workers, quiet=True)
        diff_rows = compute_diff(table_results, svc_results)
        print_diff(diff_rows, findings)
        surfaces["diff"] = diff_rows

    dump_summary = {}

    if args.dump:
        leaked = [r["table"] for r in table_results
                  if r["verdict"].startswith("READ ALLOWED")]
        out_dir = args.dump_dir or f"dump_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        dump_summary = run_dump(session, base_url, leaked, out_dir, args.dump_max)
        surfaces["dump"] = dump_summary

    record_table_findings(findings, table_results, write_results,
                          update_results, delete_results, rpc_exploit)

    summarize(table_results, write_results + update_results + delete_results, findings)
    print_findings(findings)

    if args.report:
        save_report(args.report, base_url, tables_map, table_results,
                    rpc_results, write_results + update_results + delete_results,
                    rpc_map, correlation, findings.as_list(), surfaces)

    if args.export:
        export_findings(args.export, base_url, findings.as_list())

    print("\n[+] Audit finished.")

    if args.shell:
        shell_map = dict(tables_map)

        for name in exposed:
            if name not in shell_map:
                shell_map[name] = {"columns": [], "coltypes": {}}

        interactive_shell(session, base_url, shell_map, rpc_map, correlation)


def run():
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted.")
    except ValueError as error:
        print(f"[-] {error}")
