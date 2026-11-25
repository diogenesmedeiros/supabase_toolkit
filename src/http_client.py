import random
import re
import time
from urllib.parse import urlparse

import requests

from .constants import USER_AGENTS

requests.packages.urllib3.disable_warnings()


def normalize_url(value):
    value = value.strip().rstrip("/")

    if not value.startswith(("https://", "http://")):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme != "https":
        raise ValueError("Use HTTPS.")

    if not parsed.hostname:
        raise ValueError("Invalid host.")

    host_ok = re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", parsed.hostname, re.IGNORECASE)

    if not host_ok:
        raise ValueError(f"Suspicious host: {parsed.hostname}")

    return f"https://{parsed.netloc}"


def build_session(apikey, authorization=None, proxy=None, delay=0.0,
                  retries=0, random_ua=False, insecure=False, timeout=15):
    session = requests.Session()
    session.headers.update({"apikey": apikey, "Accept": "application/json"})

    if random_ua:
        session.headers["User-Agent"] = random.choice(USER_AGENTS)

    if authorization:
        session.headers["Authorization"] = (
            authorization if authorization.lower().startswith("bearer ")
            else f"Bearer {authorization}"
        )

    if proxy:
        if proxy.lower().startswith("socks"):
            try:
                import socks  # noqa: F401
            except ImportError:
                raise ValueError(
                    "SOCKS/Tor proxy requires PySocks. "
                    "Install with: pip install PySocks (or requests[socks])."
                )

        session.proxies.update({"http": proxy, "https": proxy})

    if insecure:
        session.verify = False

    session.tk_delay = delay
    session.tk_retries = retries
    session.tk_random_ua = random_ua
    session.tk_timeout = timeout

    return session


def request(session, method, url, **kwargs):
    delay = getattr(session, "tk_delay", 0.0)
    retries = getattr(session, "tk_retries", 0)
    timeout = kwargs.pop("timeout", getattr(session, "tk_timeout", 15))

    if getattr(session, "tk_random_ua", False):
        session.headers["User-Agent"] = random.choice(USER_AGENTS)

    attempt = 0
    last_error = None

    while attempt <= retries:
        if delay:
            time.sleep(delay)

        try:
            return session.request(
                method, url, timeout=timeout, allow_redirects=False, **kwargs
            )
        except requests.RequestException as error:
            last_error = error
            attempt += 1

            if attempt <= retries:
                time.sleep(min(2 ** attempt, 8))

    return last_error


def parse_count(content_range):
    if not content_range or "/" not in content_range:
        return None

    total = content_range.rsplit("/", 1)[-1].strip()

    return int(total) if total.isdigit() else None
