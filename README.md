# Supabase Tool Kit

Surface auditor for **Supabase** instances. It started focused on **REST
(PostgREST)** and **RLS (Row Level Security)** and now covers the whole stack a
Supabase project exposes: **REST**, **Auth (GoTrue)**, **Storage**, **Realtime**,
**Edge Functions** and **GraphQL**. Given a project's URL and `apikey`, the tool
discovers the real schema, measures what the key can actually **read** and
**write**, audits the other surfaces, consolidates **findings** by severity and
offers an interactive **CRUD shell**.

---

## Index

- [How it works](#how-it-works)
- [Installation](#installation)
- [Architecture](#architecture)
- [Concepts: apikey, RLS and PostgREST](#concepts-apikey-rls-and-postgrest)
- [Quick start](#quick-start)
- [Level and risk](#level-and-risk)
- [Audited surfaces](#audited-surfaces)
  - [REST / RLS (read, insert, update, delete)](#rest--rls)
  - [Auth (GoTrue)](#auth-gotrue)
  - [Storage](#storage)
  - [Realtime](#realtime)
  - [Edge Functions](#edge-functions)
  - [GraphQL](#graphql)
  - [RPC functions and correlation](#rpc-functions-and-correlation)
  - [Diff anon x service_role](#diff-anon-x-service_role)
- [Key analysis (JWT)](#key-analysis-jwt)
- [Data dump](#data-dump)
- [Findings and export](#findings-and-export)
- [Session (save / resume)](#session-save--resume)
- [Evasion and robustness](#evasion-and-robustness)
- [Input via request / harvest (crawler)](#input-via-request--harvest-crawler)
- [Wordlist](#wordlist)
- [Interactive mode (CRUD shell)](#interactive-mode-crud-shell)
- [JSON report](#json-report)
- [Flag reference](#flag-reference)
- [Limitations and safety](#limitations-and-safety)

---

## How it works

Supabase exposes the database through **PostgREST**, plus the GoTrue, Storage,
Realtime, Edge Functions and pg_graphql services. The `/rest/v1/` endpoint
publishes the **OpenAPI spec** with the tables, views and RPC functions the key
can reach. The tool:

1. Analyzes the **key** (decodes the JWT: `anon` vs `service_role`, `exp`, `alg`).
2. **Fingerprints** and checks availability.
3. Reads the OpenAPI spec and extracts **tables, columns, types and RPCs**.
4. Measures **read** per table (`count=exact` + sample) and, per `--risk`, tests
   **INSERT/UPDATE/DELETE** non-destructively.
5. Audits **Auth, Storage, Realtime, Edge Functions and GraphQL** per `--level`
   (or explicit flags).
6. **Correlates** each table with the RPCs that manipulate it.
7. Consolidates **findings** with severity and confidence, exports
   (`md`/`csv`/`html`) and can **dump** readable tables (paginated).
8. (Optional) opens a **CRUD shell** + RPC `call`.

---

## Installation

Requires **Python 3.8+**. Use a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt`:

- `requests` — required.
- `PySocks` — required for **Tor / SOCKS proxies** (`--tor`, `--proxy socks5h://…`).
- `websocket-client` — required **only** for the **Realtime** module. Without it,
  everything else works and Realtime is skipped with a warning.

Then run with the venv's Python:

```bash
python3 main.py --help
```

### As a package (optional)

The project ships a `pyproject.toml`. To install it as a package and get the
`supabase-toolkit` command:

```bash
pip install -e .            # editable (keeps the default wordlist working)
pip install -e ".[all]"     # + PySocks (Tor/SOCKS) and websocket-client (Realtime)
supabase-toolkit --help
```

Extras: `.[socks]` (Tor/SOCKS), `.[realtime]` (Realtime), `.[all]` (both).

---

## Architecture

The tool is a modular package under `src/`, split by responsibility. `main.py`
is only the entrypoint.

```text
SupabaseToolKit/
├── main.py                 # entrypoint -> src.cli.run()
├── pyproject.toml
├── requirements.txt
├── README.md
├── wordlists/
│   └── tables.txt          # default table wordlist
└── src/
    ├── cli.py              # argparse, orchestration (level/risk/surfaces)
    ├── constants.py        # regex, types, verbs, codes, paths
    ├── http_client.py      # session, request (proxy/delay/retry/UA), normalize_url
    ├── heuristics.py       # verdict + severity + confidence logic
    ├── jwt_utils.py        # JWT decode (anon vs service_role)
    ├── fingerprint.py      # revealing versions/headers
    ├── wordlist.py         # wordlist loading
    ├── discovery.py        # health + OpenAPI schema
    ├── probes.py           # read / insert / update / delete probes + dump
    ├── rpc.py              # RPC classification, correlation and exploitation
    ├── scanner.py          # concurrent orchestration of the probes
    ├── diff.py             # anon x service_role diff
    ├── auth.py             # GoTrue (/auth/v1)
    ├── storage.py          # Storage (/storage/v1)
    ├── graphql.py          # GraphQL (/graphql/v1)
    ├── functions.py        # Edge Functions (/functions/v1)
    ├── realtime.py         # Realtime (websocket, optional)
    ├── harvest.py          # crawler for url/keys on websites
    ├── request_file.py     # raw HTTP request parser (-r)
    ├── findings.py         # findings model by severity/confidence
    ├── report.py           # summary, correlation, JSON + md/csv/html export
    ├── session_state.py    # save / resume schema
    ├── formatting.py       # parse_filter, fmt_rows, show_response, confirm
    └── shell.py            # interactive CRUD mode
```

---

## Concepts: apikey, RLS and PostgREST

- **`anon` apikey**: public key embedded in the front-end. It is an anonymous
  attacker's view — the key you want to test what leaks.
- **`service_role` apikey**: secret key that **bypasses RLS**. The tool
  **detects** when it is in use (by decoding the JWT) and marks it as
  **critical** — it should never be exposed to the client.
- **RLS**: Postgres policies that decide which rows each role can see/edit.
- **PostgREST filters**: `column=operator.value`, e.g. `id=eq.5`, `age=gte.18`,
  `id=in.(1,2,3)`. Combine with `&`.

---

## Quick start

Interactive (prompts for URL and key securely):

```bash
python3 main.py
```

Broad audit (REST+RPC + auth/storage/graphql/functions), with write and report:

```bash
python3 main.py --url test.supabase.co --level 2 --risk 2 \
  --report report.json --export findings.html
```

The key is read via a secure prompt by default (kept out of shell history).

---

## Level and risk

Two independent axes control the audit's reach:

**`--level` (surface breadth):**

| Level | Includes |
|---|---|
| `1` (default) | REST (read) + RPC |
| `2` | + Auth, Storage, GraphQL, Edge Functions, fingerprint |
| `3` | + Realtime |

**`--risk` (how mutating):**

| Risk | Includes |
|---|---|
| `1` (default) | read-only |
| `2` | + INSERT probe (non-destructive) |
| `3` | + UPDATE and DELETE probes (non-destructive) |

Surface flags (`--auth-scan`, `--storage`, `--graphql`, `--functions`,
`--realtime`) enable surfaces individually, regardless of `--level`.
`--write-test` is a shortcut equivalent to `--risk 2`.

---

## Audited surfaces

### REST / RLS

For each table: `GET /rest/v1/{t}?select=*&limit=3` with `Prefer: count=exact`.

| Verdict | Meaning |
|---|---|
| `READ ALLOWED (data leaked)` | rows came back → **RLS exposed** ⚠️ |
| `accessible, 0 rows visible (RLS likely)` | empty 200 → RLS working |
| `forbidden (RLS active)` / `unauthorized` | 403 / 401 → blocked |
| `not found/not exposed` | 404 |

**Write (risk ≥ 2):** INSERT with an **uncastable value** in a typed column —
the data is never written, but the response reveals RLS via Postgres' check
order (`42501` → blocked; `22P02`/`23502`/… → passed authorization →
**vulnerable**; `201`/`204` → actually written).

**UPDATE/DELETE (risk = 3):** same technique, but with a filter that **matches
no rows** (sentinel) so nothing is changed/deleted. The response reveals whether
the operation passed authorization.

Each result carries a **severity** and a **confidence** level.

### Auth (GoTrue)

`--auth-scan` or `--level ≥ 2`. Checks `/auth/v1/settings` (open signup, email
autoconfirm, external providers) and tries `/auth/v1/admin/users` — if it
answers `200`, the **admin endpoint is accessible with the key** (critical).

### Storage

`--storage` or `--level ≥ 2`. Lists buckets at `/storage/v1/bucket`, flags the
**public** ones and lists their objects.

### Realtime

`--realtime` or `--level 3`. Connects to the Realtime websocket, subscribes to
the discovered tables and listens for a few seconds (`--realtime-time`). If
changes arrive, the table **leaks via Realtime** even if REST has RLS.

> Requires `websocket-client` (see [Installation](#installation)). Without the
> library, the module is skipped with a warning.

### Edge Functions

`--functions` or `--level ≥ 2`. Enumerates functions at `/functions/v1/<name>`
by wordlist (built-in + `--functions-wordlist`). Distinguishes 404 from
existing, from protected (401/403), from **accessible without auth**.

### GraphQL

`--graphql` or `--level ≥ 2`. Runs an **introspection** query against
`/graphql/v1`; if the schema comes back, introspection is enabled.

### RPC functions and correlation

The tool reads all RPCs from the spec (with arguments), does a read-only `GET`
on each and **correlates** every table with the RPCs that reference it,
classifying the operation by the verb in the name (WRITE/READ). In many Supabase
apps mutations go through RPC, not the table endpoint.

```text
  > tenants
      [WRITE     ] rpc/create_tenant  (args: p_name, p_owner)
      [READ      ] rpc/get_tenant  (args: id)
```

**Exploitation (`--rpc-exec`):** beyond the `GET`, it invokes via **POST** the
RPCs classified as **read** (with discovered arguments filled as `null`) to
detect **data leakage through a function**. **Write** RPCs are **not invoked
automatically** (potentially destructive) — they are only flagged for you to run
manually with `call` in the shell.

### Diff anon x service_role

With `--service-key <service_role>`, the tool runs a **control scan** with the
key that bypasses RLS and compares, table by table, what `anon` sees versus what
`service_role` sees:

```text
==============================================
  DIFF anon x service_role
==============================================
  [!] users        FULLY EXPOSED (anon sees everything service_role sees)  (anon=1200 / service=1200)
  [!] orders       partially exposed (anon sees less than service_role)  (anon=30 / service=5000)
  [-] secrets      protected (service_role sees it, anon does not)  (anon=None / service=88)
```

- **FULLY EXPOSED** (anon = service, both > 0) → RLS filters nothing → critical.
- **partially exposed** → RLS filters, but still leaks something → high.
- **protected** → RLS is doing its job.

---

## Key analysis (JWT)

At the start, the key (and `--auth`, if present) is **decoded** locally:

```text
[*] Analyzing the key...
    role: anon  alg: HS256  exp: 2035-...
```

It detects `role` (**anon** vs **service_role**), algorithm, expiration and the
new format (`sb_publishable_…`/`sb_secret_…`). A `service_role` in use becomes a
**critical** finding (bypasses RLS).

---

## Data dump

`--dump` extracts, **paginated**, every table in `READ ALLOWED` to JSON files
(one per table):

```bash
python3 main.py --url test.supabase.co --dump --dump-dir out --dump-max 5000
```

- `--dump-dir` — output directory (default `dump_<timestamp>`).
- `--dump-max` — row cap per table.

---

## Findings and export

Every surface feeds a single **findings** registry with **severity**
(`critical` → `info`) and **confidence** (`high`/`medium`/`low`), printed at the
end and exportable:

```bash
python3 main.py --url test.supabase.co --level 2 --export findings.md
```

The format is inferred from the extension: `.md`, `.csv` or `.html`.

The **summary** at the end gives a **security posture** read: a verdict
(`CRITICAL`/`HIGH RISK`/`ATTENTION`/`LOW RISK`), a **risk score** 0–100
(severity-weighted) and the findings histogram.

```text
  SECURITY POSTURE
    Verdict ................. CRITICAL
    Risk score .............. 72/100
    Findings ................ critical=1 high=3 medium=2 low=0
```

---

## Session (save / resume)

To avoid rediscovering the schema on every run:

```bash
python3 main.py --url test.supabase.co --save-session session.json
python3 main.py --url test.supabase.co --resume session.json --risk 2
```

`--resume` is accepted only if the saved target matches the current `--url`.

---

## Evasion and robustness

| Flag | Effect |
|---|---|
| `--proxy URL` | route everything through an http(s) **or socks** proxy (e.g. Burp, `socks5h://…`) |
| `--tor` | route via **Tor** (`socks5h://127.0.0.1:9050`), with DNS over Tor |
| `--tor-port N` | Tor SOCKS port (default 9050) |
| `--proxychains` | **re-exec** the tool under `proxychains`/`proxychains4` |
| `--delay S` | delay between requests (rate-limit) |
| `--retries N` | extra attempts on network failure (backoff) |
| `--random-ua` / `--random-agent` | random User-Agent per request (pool of 12) |
| `--insecure` | do not validate the TLS certificate |
| `--timeout S` | timeout per request (default 15) |

```bash
# via Tor (requires Tor running + PySocks)
python3 main.py --url test.supabase.co --tor --random-agent

# via proxychains (requires proxychains4 configured)
python3 main.py --url test.supabase.co --proxychains --level 2
```

> **Coverage:** `--proxy`, `--tor` and `--random-ua` apply to every HTTP request
> (REST, Auth, Storage, GraphQL, Functions, harvest). The **Realtime** websocket
> does not go through `--tor`; to route it too, use `--proxychains`, which wraps
> the whole process at the network level.

---

## Input via request / harvest (crawler)

- **`-r file.txt`** — reads a raw HTTP request (sqlmap style) and extracts URL,
  `apikey` and `Authorization` from the headers.
- **`--harvest URL`** — **crawls the website**: it fetches the page, follows
  internal links (up to a page/depth limit) and scans each page plus its `.js`
  bundles for `*.supabase.co` URLs, JWTs and new-format keys. If `--url`/`--apikey`
  are not given, it adopts what it finds (first Supabase URL and first JWT).

```bash
python3 main.py --harvest https://app.example.com --level 2
python3 main.py -r req.txt --proxy http://127.0.0.1:8080
```

---

## Wordlist

- By default it loads `wordlists/tables.txt`; combined with what OpenAPI
  discovered (deduplicated).
- One name per line; blank lines and `#` are ignored.

```bash
python3 main.py -w my_list.txt          # default + yours
python3 main.py --no-builtin -w mine.txt # only yours
python3 main.py --schema-only           # no brute-force
```

---

## Interactive mode (CRUD shell)

Enabled with `--shell`/`-i`. Operates on the **current table** (`use`).

| Command | Action |
|---|---|
| `tables` / `use <t>` / `cols` | navigation and metadata |
| `count [filter]` / `view [limit] [filter]` / `select <filter>` | read |
| `insert <json>` / `update <filter> <json>` / `delete <filter>` | direct write |
| `rpcs` / `allrpcs` / `call <function> [json]` | RPC (the real write path) |
| `help` / `exit` | help / quit |

**Guards:** `insert`/`update`/`delete` ask for confirmation; `update`/`delete`
**without a filter** require typing the table name; only `exit` (or `Ctrl+D`)
ends the session.

```text
supabase:tenants> call create_tenant {"p_name":"acme"}
Confirm call? (y/N): y
[+] rpc/create_tenant: HTTP 200
```

---

## JSON report

With `--report file.json`, everything is saved in a structured way (top-level
keys):

```json
{
  "generated_at": "2026-11-24T10:30:00",
  "target": "https://test.supabase.co",
  "discovered_tables": {
    "plans": {
      "columns": [
        "id"
      ],
      "coltypes": {
        "id": "bigint"
      }
    }
  },
  "rpc_functions": {
    "create_tenant": {
      "args": [
        "p_name"
      ],
      "has_get": false,
      "has_post": true
    }
  },
  "rpc_table_correlation": {
    "tenants": [
      [
        "create_tenant",
        "write"
      ]
    ]
  },
  "table_results": [
    {
      "table": "plans",
      "status": 200,
      "count": 7,
      "verdict": "READ ALLOWED (data leaked)",
      "severity": "high",
      "confidence": "high"
    }
  ],
  "rpc_results": [
    {
      "rpc": "get_showcase",
      "status": 200,
      "verdict": "CALLABLE via GET (returned data)"
    }
  ],
  "write_results": [
    {
      "table": "plans",
      "verdict": "write blocked (RLS/grant) — safe"
    }
  ],
  "surfaces": {
    "auth": {},
    "storage": {},
    "graphql": {},
    "functions": [],
    "realtime": {},
    "rpc_exploit": [],
    "diff": [],
    "dump": {}
  },
  "findings": [
    {
      "severity": "high",
      "surface": "rest",
      "title": "Read allowed on 'plans'...",
      "confidence": "high",
      "evidence": {
        "rows": 7
      }
    }
  ]
}
```

---

## Flag reference

| Flag | Description |
|---|---|
| `--url URL` | Supabase URL (or prompt) |
| `--apikey KEY` | anon/service apikey (or secure prompt) |
| `--auth TOKEN` | Authorization Bearer (user session, optional) |
| `--service-key KEY` | service_role for the anon × service_role diff |
| `-r`, `--request-file` | raw HTTP request (extracts url/apikey/auth) |
| `--harvest URL` | crawl a website for url/keys before auditing |
| `--level {1,2,3}` | surface breadth (see [Level and risk](#level-and-risk)) |
| `--risk {1,2,3}` | read / +insert / +update+delete |
| `--auth-scan` | audit GoTrue `/auth/v1` |
| `--storage` | audit Storage `/storage/v1` |
| `--graphql` | audit GraphQL `/graphql/v1` |
| `--functions` | enumerate Edge Functions |
| `--functions-wordlist` | wordlist of edge function names |
| `--realtime` | audit Realtime (websocket) |
| `--realtime-time S` | seconds to listen on Realtime (default 6) |
| `--no-fingerprint` | do not fingerprint |
| `--dump` | dump readable tables (paginated) |
| `--dump-dir PATH` | dump output directory |
| `--dump-max N` | max rows per table |
| `--save-session PATH` | save the discovered schema |
| `--resume PATH` | resume the schema from a session |
| `--proxy URL` | http(s)/socks proxy |
| `--tor` | route via Tor (local SOCKS) |
| `--tor-port N` | Tor SOCKS port (default 9050) |
| `--proxychains` | re-exec under proxychains/proxychains4 |
| `--delay S` | delay between requests |
| `--retries N` | extra attempts on network failure |
| `--random-ua`, `--random-agent` | random User-Agent |
| `--insecure` | do not validate TLS |
| `--timeout S` | timeout per request |
| `--workers N` | threads (default 10) |
| `--wordlist`, `-w` | `.txt` file of table names |
| `--no-builtin` | ignore the default wordlist |
| `--schema-only` | test only what OpenAPI discovered |
| `--verbose`, `-v` | also list 404s (hidden) |
| `--write-test` | shortcut for `--risk 2` |
| `--no-rpc` | do not test RPC functions |
| `--rpc-exec` | exploit RPCs via POST (invoke read, flag write) |
| `--report PATH` | save JSON report |
| `--export PATH` | export findings (`.md`/`.csv`/`.html`) |
| `--shell`, `-i` | interactive CRUD mode |

---

## Limitations and safety

- The tool only sees what the **provided key** allows — it does not break
  cryptography or bypass authentication.
- The write probes (INSERT/UPDATE/DELETE) are **non-destructive by construction**
  (invalid value + non-matching filter); without a suitable typed column the
  table is **skipped** rather than risked.
- The **shell** performs **real** operations; hence the confirmations.
- Treat the `service_role` as a secret: never expose it in the front-end or logs.
- Only use it against targets you are **authorized** to test.
