# Automated Scanner Plugins

This package is the "automate a checklist item" extension point. Each
scanner looks at an `Endpoint` and returns evidence (and sometimes a
verdict) for one or more `VulnCheck` ids from `seed/phases.json`.

## Adding a new scanner

Copy this template into a new file in this folder, e.g. `scanners/tls_config.py`:

```python
from . import BaseScanner, ScanFinding, register

@register
class MyScanner(BaseScanner):
    id = "my_scanner"                 # unique, used as a dict key
    name = "Human-Readable Name"
    description = "One line describing what it checks."
    covers = ["WSTG-XXXX-NN"]         # VulnCheck id(s) this can speak to

    def applies_to(self, endpoint):
        # cheap pre-check -- e.g. only run on https:// endpoints
        return endpoint.url.startswith("https://")

    def scan(self, endpoint):
        # do the work, NEVER raise -- catch exceptions and return an
        # 'error' finding instead so one bad scanner can't break a bulk run
        ...
        return [
            ScanFinding(
                vuln_id="WSTG-XXXX-NN",
                status="pass",       # 'pass' | 'fail' | 'info' | 'error'
                summary="One-line human summary shown in the notes field",
                evidence={"raw": "..."},   # any JSON-serialisable dict
                confidence="high",   # only 'high' + pass/fail auto-sets a verdict
            )
        ]
```

No other file needs to change — `scanners/__init__.py` auto-imports every
module in this package at startup, and the `@register` decorator does the
rest. The endpoint page and the "Run Automated Checks" button pick it up
automatically for any endpoint where `applies_to()` returns `True`.

## Design rules a scanner should follow

- **Never raise.** `registry.run_all()` guards against exceptions too, but
  a scanner that fails cleanly with an `'error'` finding gives the tester
  a much more useful message than a stack trace.
- **Be honest about confidence.** Only use `status='pass'/'fail'` +
  `confidence='high'` when the scanner is actually testing the full
  condition the checklist item describes. If it's partial evidence toward
  a broader manual check, use `status='info'` — app.py will log it as
  supporting evidence in the notes field without touching the check's
  pass/fail/n-a status.
- **Automated findings never overwrite a manual verdict.** app.py only
  auto-sets a check's status if it's currently `untested`. A scanner
  doesn't need to worry about this — just report what you found.
- **Keep `evidence` JSON-serialisable** (dict of primitives / lists /
  small dicts) — it's stored as-is and may be shown in the UI or report
  later.

## Current scanners

| id                        | covers                                                        | what it does |
|---------------------------|----------------------------------------------------------------|--------------|
| `clickjacking_headers`    | WSTG-CLNT-09, WSTG-CONF-07, WSTG-CONF-12, WSTG-SESS-02          | Fetches the endpoint, checks X-Frame-Options / CSP frame-ancestors (asserts a real pass/fail for clickjacking) and logs header/cookie evidence for the broader misconfig checks. |
| `security_headers_audit`  | WSTG-CONF-07                                                    | Dedicated HSTS / X-Content-Type-Options / Referrer-Policy audit with a real pass/fail verdict, plus flags version-disclosing headers (Server, X-Powered-By, etc). |

Note that both of the above report findings for `WSTG-CONF-07` — that's
intentional and shows how overlap is meant to work: `security_headers_audit`
is the one that asserts a real verdict there (`confidence="high"`), while
`clickjacking_headers`'s contribution to that same check stays `info` and
just adds supporting evidence underneath it. Two scanners can safely cover
the same checklist item as long as at most one of them is the "high
confidence verdict" source for it.

## Ideas for what to add next

- Active SQLi/XSS probing scanner (`WSTG-INPV-05`, `WSTG-INPV-01`) — needs
  care around scope/authorization, keep it opt-in per project.
- TLS/cipher suite checker (`WSTG-CRYP-*`)
- JWT algorithm confusion / `alg:none` checker (`WSTG-SESS-*`, API auth checks)
- CORS misconfiguration prober
- Security headers full audit (HSTS, X-Content-Type-Options, Referrer-Policy)
  as its own scanner rather than piggybacking on the clickjacking one
