import os
import re

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(PACKAGE_DIR)
DEFAULT_WORDLIST = os.path.join(PROJECT_ROOT, "wordlists", "tables.txt")

IDENT_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
SAMPLE_ROWS = 3

RPC_WRITE_VERBS = (
    "create", "insert", "add", "new", "update", "edit", "modify", "set",
    "upsert", "save", "register", "delete", "remove", "drop", "destroy",
    "revoke", "grant", "reset", "change", "toggle", "approve", "reject",
)

RPC_READ_VERBS = (
    "get", "list", "fetch", "select", "read", "find", "search", "show",
    "all", "count", "exists", "check", "view",
)

STRICT_TYPES = (
    "bigint", "integer", "smallint", "int", "int2", "int4", "int8",
    "numeric", "decimal", "double precision", "real", "float", "float4",
    "float8", "money", "boolean", "bool", "uuid", "date", "time",
    "timestamp", "timestamp with time zone", "timestamp without time zone",
    "timestamptz", "timetz", "interval",
)

PASSED_AUTH_CODES = {
    "22P02",
    "22007", "22008",
    "23502",
    "23503",
    "23505",
    "23514",
    "23P01",
}

WRITE_SENTINEL = "zzz_rls_write_probe_zzz"
NOMATCH_SENTINEL = "zzz_no_match_sentinel_zzz_404"

DUMP_PAGE = 1000
DUMP_MAX_ROWS = 100000

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "curl/8.6.0",
)

TOR_DEFAULT_PORT = 9050
TOR_PROXY = "socks5h://127.0.0.1:{port}"

COMMON_FUNCTIONS = (
    "hello", "hello-world", "health", "status", "webhook", "stripe-webhook",
    "send-email", "email", "notify", "sms", "payment", "checkout", "login",
    "auth", "token", "upload", "download", "export", "import", "cron",
    "admin", "user", "users", "process", "worker", "callback",
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
