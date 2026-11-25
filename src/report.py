import csv
import datetime
import html
import json


def print_correlation(correlation, rpc_map):
    if not correlation:
        return

    print("\n" + "=" * 46)
    print("  RPC x TABLE  (likely operations via function)")
    print("=" * 46)
    print("  In this app, changes go through RPC, not the table endpoint.")
    print("  For each table, the related functions:\n")

    for table in sorted(correlation):
        print(f"  > {table}")

        for fn, op in correlation[table]:
            args = ", ".join(rpc_map.get(fn, {}).get("args") or []) or "—"
            mark = op.upper()

            print(f"      [{mark:<10}] rpc/{fn}  (args: {args})")


SEVERITY_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 2, "info": 0}


def risk_posture(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    score = 0

    for f in findings or []:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        score += SEVERITY_WEIGHT.get(sev, 0)

    score = min(score, 100)

    if counts["critical"]:
        posture = "CRITICAL"
    elif counts["high"]:
        posture = "HIGH RISK"
    elif counts["medium"]:
        posture = "ATTENTION"
    elif counts["low"]:
        posture = "LOW RISK"
    else:
        posture = "NO RELEVANT FINDINGS"

    return posture, score, counts


def summarize(table_results, write_results=None, findings=None):
    leaked = [r for r in table_results if r["verdict"].startswith("READ ALLOWED")]

    print("\n" + "=" * 46)
    print("  SUMMARY")
    print("=" * 46)
    print(f"  Tables tested ............. {len(table_results)}")
    print(f"  With readable data ........ {len(leaked)}")

    if write_results:
        writable = [r for r in write_results
                    if "ALLOWED" in r["verdict"] or r.get("wrote") or r.get("passed")]
        print(f"  Mutations tested .......... {len(write_results)}")
        print(f"  That passed RLS ........... {len(writable)}")

    if findings is not None:
        posture, score, counts = risk_posture(findings.as_list()
                                              if hasattr(findings, "as_list") else findings)

        print("\n  SECURITY POSTURE")
        print(f"    Verdict ................. {posture}")
        print(f"    Risk score .............. {score}/100")
        print(f"    Findings ................ "
              f"critical={counts['critical']} high={counts['high']} "
              f"medium={counts['medium']} low={counts['low']}")

    if leaked:
        print("\n  [!] READ — tables with data exposed to the key used:")

        for r in leaked:
            print(f"      - {r['table']}  (total rows: {r['count']})")

            if r["sample"]:
                keys = list(r["sample"][0].keys()) if r["sample"] else []
                print(f"        columns: {', '.join(keys[:12])}")


def save_report(path, base_url, tables, table_results, rpc_results,
                write_results, rpc_map=None, correlation=None,
                findings=None, surfaces=None):
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": base_url,
        "discovered_tables": tables,
        "rpc_functions": rpc_map or {},
        "rpc_table_correlation": correlation or {},
        "table_results": table_results,
        "rpc_results": rpc_results,
        "write_results": write_results,
        "surfaces": surfaces or {},
        "findings": list(findings or []),
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, default=str)

    print(f"\n[+] Report saved to: {path}")


def export_findings(path, base_url, findings):
    items = list(findings or [])
    fmt = path.rsplit(".", 1)[-1].lower() if "." in path else "md"

    if fmt == "csv":
        _export_csv(path, items)
    elif fmt in ("html", "htm"):
        _export_html(path, base_url, items)
    else:
        _export_markdown(path, base_url, items)

    print(f"[+] Findings exported to: {path}")


def _export_csv(path, items):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "confidence", "surface", "title", "evidence"])

        for f in items:
            writer.writerow([f["severity"], f.get("confidence", ""), f["surface"],
                             f["title"],
                             json.dumps(f.get("evidence") or {}, ensure_ascii=False)])


def _export_markdown(path, base_url, items):
    lines = [f"# Supabase report — {base_url}", ""]
    lines.append(f"Generated at {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append(f"Total findings: {len(items)}")
    lines.append("")
    lines.append("| Severity | Confidence | Surface | Title |")
    lines.append("| --- | --- | --- | --- |")

    for f in items:
        lines.append(f"| {f['severity']} | {f.get('confidence','')} | "
                     f"{f['surface']} | {f['title']} |")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _export_html(path, base_url, items):
    rows = ""

    for f in items:
        rows += (f"<tr><td>{html.escape(f['severity'])}</td>"
                 f"<td>{html.escape(f.get('confidence',''))}</td>"
                 f"<td>{html.escape(f['surface'])}</td>"
                 f"<td>{html.escape(f['title'])}</td></tr>")

    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>Supabase — {html.escape(base_url)}</title>"
        "<style>body{font-family:sans-serif;margin:2rem}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
        "</style></head><body>"
        f"<h1>Supabase report</h1><p>{html.escape(base_url)}</p>"
        f"<p>{len(items)} finding(s)</p>"
        "<table><tr><th>Severity</th><th>Confidence</th>"
        "<th>Surface</th><th>Title</th></tr>"
        f"{rows}</table></body></html>"
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
