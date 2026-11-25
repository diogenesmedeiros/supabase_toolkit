def _by_table(results):
    return {r["table"]: r for r in results}


def _readable(r):
    return bool(r) and r.get("verdict", "").startswith("READ ALLOWED")


def _exists(r):
    return bool(r) and r.get("status") in (200, 206, 401, 403)


def compute_diff(anon_results, service_results):
    anon = _by_table(anon_results)
    svc = _by_table(service_results)

    tables = sorted(set(anon) | set(svc))
    rows = []

    for table in tables:
        a = anon.get(table)
        s = svc.get(table)

        if not _exists(a) and not _exists(s):
            continue

        a_read = _readable(a)
        s_read = _readable(s)
        a_count = (a or {}).get("count")
        s_count = (s or {}).get("count")

        if a_read and s_read and a_count is not None and a_count == s_count and a_count:
            status = "FULLY EXPOSED (anon sees everything service_role sees)"
            severity = "critical"
        elif a_read and s_read:
            status = "partially exposed (anon sees less than service_role)"
            severity = "high"
        elif a_read and not s_read:
            status = "exposed to anon only (unusual — review)"
            severity = "high"
        elif not a_read and s_read:
            status = "protected (service_role sees it, anon does not)"
            severity = "info"
        else:
            status = "no read by either key"
            severity = "info"

        rows.append({
            "table": table,
            "anon_count": a_count,
            "service_count": s_count,
            "anon_read": a_read,
            "service_read": s_read,
            "status": status,
            "severity": severity,
        })

    return rows


def print_diff(rows, findings=None):
    print("\n" + "=" * 46)
    print("  DIFF anon x service_role")
    print("=" * 46)

    if not rows:
        print("  (nothing comparable)")
        return

    for r in rows:
        tag = "[!]" if r["severity"] in ("critical", "high") else "[-]"
        counts = f"anon={r['anon_count']} / service={r['service_count']}"
        print(f"  {tag} {r['table']:<26} {r['status']}  ({counts})")

        if findings and r["severity"] in ("critical", "high"):
            findings.add(r["severity"], "rest-diff",
                         f"{r['table']}: {r['status']}",
                         {"anon": r["anon_count"], "service_role": r["service_count"]})
