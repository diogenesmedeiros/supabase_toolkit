from .http_client import request


def check_auth(session, base_url, findings=None, key_info=None, risk=1):
    print("\n[*] Auditing Auth (GoTrue /auth/v1)...")

    result = {"settings": None, "admin_users": None, "signup": None}

    if key_info and key_info.get("service_role") and findings:
        findings.add("critical", "auth",
                     "service_role key in use (bypasses RLS entirely)",
                     {"role": "service_role", "exp": key_info.get("exp")}, "high")

    resp = request(session, "GET", f"{base_url}/auth/v1/settings")

    if not isinstance(resp, Exception) and resp.status_code == 200:
        try:
            settings = resp.json()
        except ValueError:
            settings = {}

        result["settings"] = settings
        disable_signup = settings.get("disable_signup")
        autoconfirm = settings.get("mailer_autoconfirm") or settings.get("autoconfirm")
        external = settings.get("external") or {}
        enabled = [k for k, v in external.items() if v]

        print(f"[+] /auth/v1/settings -> HTTP 200")
        print(f"    signup enabled: {not disable_signup}")
        print(f"    email autoconfirm: {bool(autoconfirm)}")
        print(f"    external providers: {', '.join(enabled) or '—'}")

        if findings and not disable_signup:
            findings.add("medium", "auth",
                         "Public signup enabled",
                         {"endpoint": "/auth/v1/signup"}, "high")

        if findings and autoconfirm:
            findings.add("low", "auth",
                         "Email autoconfirm enabled (active accounts without verification)",
                         None, "medium")
    else:
        code = resp.status_code if not isinstance(resp, Exception) else "error"
        print(f"[-] /auth/v1/settings -> {code}")

    admin = request(session, "GET", f"{base_url}/auth/v1/admin/users",
                    params={"page": "1", "per_page": "1"})

    if not isinstance(admin, Exception):
        result["admin_users"] = admin.status_code

        if admin.status_code == 200:
            print("[+] /auth/v1/admin/users -> HTTP 200  (ADMIN ACCESSIBLE!)")

            if findings:
                findings.add("critical", "auth",
                             "Admin users endpoint accessible with the provided key",
                             {"endpoint": "/auth/v1/admin/users"}, "high")
        else:
            print(f"[-] /auth/v1/admin/users -> HTTP {admin.status_code}")

    return result
