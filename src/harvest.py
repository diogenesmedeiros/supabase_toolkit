import re
from collections import deque
from urllib.parse import urljoin, urlparse

import requests

URL_RE = re.compile(r"https://[a-z0-9-]+\.supabase\.(?:co|in|net)", re.IGNORECASE)
KEY_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
NEWKEY_RE = re.compile(r"sb_(?:publishable|secret)_[A-Za-z0-9_-]{10,}")

SCRIPT_RE = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def _get(url, timeout, proxies):
    try:
        return requests.get(url, timeout=timeout, proxies=proxies,
                            headers={"User-Agent": "Mozilla/5.0"})
    except requests.RequestException:
        return None


def _scan_text(text, found):
    for u in URL_RE.findall(text):
        found["urls"].add(u)

    for j in KEY_RE.findall(text):
        found["jwts"].add(j)

    for k in NEWKEY_RE.findall(text):
        found["keys"].add(k)


def _absolute(base, src):
    if src.startswith("//"):
        return "https:" + src

    return urljoin(base, src)


def harvest_from_url(target, timeout=15, proxy=None, max_pages=15, max_depth=2):
    print(f"\n[*] Crawling {target} for Supabase url/keys "
          f"(max {max_pages} page(s), depth {max_depth})...")

    found = {"urls": set(), "jwts": set(), "keys": set()}
    proxies = {"http": proxy, "https": proxy} if proxy else None

    origin = urlparse(target)
    host = origin.netloc
    queue = deque([(target, 0)])
    visited = set()
    pages = 0

    while queue and pages < max_pages:
        url, depth = queue.popleft()

        if url in visited:
            continue

        visited.add(url)
        resp = _get(url, timeout, proxies)

        if resp is None or not resp.text:
            continue

        pages += 1
        _scan_text(resp.text, found)

        for src in SCRIPT_RE.findall(resp.text):
            js_url = _absolute(url, src)
            js = _get(js_url, timeout, proxies)

            if js is not None and js.text:
                _scan_text(js.text, found)

        if found["urls"] and (found["jwts"] or found["keys"]):
            break

        if depth >= max_depth:
            continue

        for href in HREF_RE.findall(resp.text):
            link = _absolute(url, href)
            parsed = urlparse(link)

            if parsed.scheme in ("http", "https") and parsed.netloc == host:
                clean = link.split("#", 1)[0]

                if clean not in visited:
                    queue.append((clean, depth + 1))

    result = {
        "urls": sorted(found["urls"]),
        "jwts": sorted(found["jwts"]),
        "keys": sorted(found["keys"]),
        "pages_crawled": pages,
    }

    print(f"[*] {pages} page(s) crawled.")

    if result["urls"]:
        print(f"[+] Supabase URL(s): {', '.join(result['urls'])}")

    if result["jwts"]:
        print(f"[+] {len(result['jwts'])} JWT token(s) found.")

    if result["keys"]:
        print(f"[+] {len(result['keys'])} new-format key(s) found.")

    if not (result["urls"] or result["jwts"] or result["keys"]):
        print("[-] Nothing found.")

    return result
