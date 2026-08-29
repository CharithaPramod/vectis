# WebPT — Pentest Checklist + Burp Sitemap Coverage Tracker

Flask rebuild of the single-file pentest checklist, restructured around a
Burp Suite sitemap instead of a flat phase list.

## What it does

- **Import a Burp Suite site map export (XML)** per project. Every request
  Burp saw becomes an `Endpoint` (method + host + path + params).
- **Left sidebar = sitemap**, grouped by host and path, each row showing a
  `tested/applicable` coverage badge (green = fully tested, red = has a
  failed/vulnerable check).
- Selecting an endpoint shows only the vulnerability checks that are
  **actually relevant to that endpoint** — decided by a heuristic engine
  (`vuln_engine.py`) that looks at HTTP method, query/body params, content
  type, and path patterns (e.g. SQLi/XSS checks only appear on endpoints
  that take input; CSRF/business-logic checks only on state-changing
  endpoints; auth checks only on login/reset/session paths; API-Top-10
  checks only on `/api`-style endpoints; .NET checks only on
  `.aspx/.ashx/.asmx/.axd`, etc).
- Each check is a click-to-cycle status: **untested → pass → fail → n/a**,
  plus a notes field for evidence/payloads and a CVSS field once marked
  fail — this is where you record "this vulnerability exists on this
  endpoint."
- **Automated scanning plugin system**: a "🤖 Run Automated Checks" button
  on each endpoint (plus a project-wide "Scan All") triggers real HTTP
  probes against that endpoint and writes evidence — and, where the
  scanner is confident enough, a real pass/fail verdict — directly onto
  the relevant checklist item's notes/status. Currently ships with one
  scanner (clickjacking / framing headers); see **Automated scanners**
  below for how to add more without touching the rest of the app.
- **Project-level checklist tab** still covers the phases that aren't tied
  to one endpoint: Pre-Engagement, Reconnaissance, App Mapping, Automated
  Scanning, Documentation.
- **Report generator** produces a standalone HTML report: coverage table
  per endpoint, and a findings section for everything marked FAIL.

The full 98-item / 13-phase checklist from your original file (OWASP Top
10, OWASP API Top 10, CWE, MITRE ATT&CK mappings) is preserved as the
seed data in `seed/phases.json` — nothing was dropped, it's just now
split into "project-level" vs "per-endpoint" scope and filtered per
endpoint instead of shown as one long flat list.

## Automated scanners

WebPT can run live automated checks against an endpoint instead of relying
entirely on manual testing. This is deliberately built as a **plugin
system** (`scanners/` package) so it can grow over time without touching
the rest of the app:

- Click **🤖 run automated checks** on any endpoint to scan just that one,
  or **🤖 SCAN ALL (AUTOMATED)** in the sidebar to sweep every endpoint in
  the project.
- Findings are written as timestamped `[AUTO ...]` lines in the relevant
  check's notes field, tagged with a 🤖 AUTO badge in the UI.
- A scanner only auto-sets a check's pass/fail status when it's testing
  the *actual* condition the checklist item describes (e.g. clickjacking:
  are anti-framing headers present) — and only if the tester hasn't
  already recorded a manual verdict. **Automated findings never overwrite
  a manual conclusion**; re-scanning just appends fresh evidence.
- The current scanner (`scanners/clickjacking.py`) fetches the endpoint
  once and produces evidence for four checklist items at once:
  `WSTG-CLNT-09` (Clickjacking — real verdict), `WSTG-CONF-07` (security
  headers), `WSTG-CONF-12` (CSP analysis), `WSTG-SESS-02` (cookie
  attributes) — the latter three as supporting evidence only, since a
  single request doesn't fully test those broader checks.
- A second scanner (`scanners/security_headers.py`) is a dedicated audit
  of `WSTG-CONF-07` (HSTS, X-Content-Type-Options, Referrer-Policy,
  version-disclosure headers) that *does* assert a real verdict for that
  check — proof that two scanners can safely cover the same checklist
  item as long as only one of them is the high-confidence verdict source.
- Raw scan evidence (headers seen, cookies, etc.) is stored per-check and
  viewable under a "🤖 RAW SCAN EVIDENCE" expandable panel on each check,
  separate from the tester's own notes.

**Adding a new automated check is one file, no other code changes:**
drop a new module in `scanners/`, subclass `BaseScanner`, decorate it with
`@register`. See `scanners/README.md` for the exact contract and a
copy-paste template, plus a running list of good next scanners (TLS
config, JWT alg confusion, CORS misconfig, active SQLi/XSS probing, etc).

Existing installs pick up new scanner-related database columns
automatically — `app.py` runs a small `ensure_columns()` migration at
startup that adds any missing columns to `instance/webpt.db` without
touching existing data, so upgrading doesn't mean starting a new project.

## Getting a Burp Suite sitemap export

1. In Burp, browse/crawl/proxy the target so requests populate **Target →
   Site map**.
2. Right-click the host(s) you want → **Save selected items**.
3. Save format: **XML**. (Don't use "Base64-encode requests and
   responses = off" — leave the default on; the parser reads the raw
   base64 to pull out params, content-type, etc.)
4. Upload that `.xml` file via **📥 IMPORT BURP SITEMAP** in the sidebar.

Re-importing the same file (or a newer export) is safe — endpoints are
matched on `(method, url)` and updated in place rather than duplicated.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000. The SQLite DB is created automatically
at `instance/webpt.db` on first run (and the checklist library is seeded
once from `seed/phases.json`).

## Project layout

```
app.py            routes: dashboard, project view, Burp import, status APIs,
                  automated-scan APIs, report
models.py         Project / Endpoint / VulnCheck / EndpointVulnStatus / ProjectVulnStatus
burp_parser.py     parses Burp's XML sitemap export into endpoint dicts
vuln_engine.py     decides which checks are "applicable" to a given endpoint
scanners/         automated scanner plugins (see scanners/README.md)
seed/phases.json  the original 13-phase / 98-item checklist as data
templates/        Jinja templates (dashboard, project workspace, report)
static/           CSS + vanilla JS (no build step, no frontend framework)
```

## Notes / next steps you may want

- The applicability engine is heuristic, not exhaustive — if you find a
  check that should (or shouldn't) show up for a certain kind of
  endpoint, adjust the `RULES` list in `vuln_engine.py`.
- Currently single-user, no auth — fine for local use; add
  Flask-Login/SSO before exposing this beyond localhost.
- `has_id_param` detection is deliberately loose (numeric/UUID path
  segments + params like `user_id`, `order`, `account`) since IDOR checks
  should err toward being shown rather than hidden.
