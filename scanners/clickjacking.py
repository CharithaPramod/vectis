"""
Ported from the standalone "Framing & Clickjacking Diagnostic Tool"
(analyze_target() in the original app.py). The HTTP-fetch-and-inspect logic
is unchanged; what's different is that it no longer prints to stdout,
render a Flask page, or hold global state -- it returns structured
ScanFinding objects that app.py writes onto the relevant checklist items.

One HTTP request here produces evidence for four checklist items:
  - WSTG-CLNT-09  Clickjacking                  (real verdict: pass/fail)
  - WSTG-CONF-07  HTTP Security Headers Audit    (evidence only)
  - WSTG-CONF-12  Content Security Policy        (evidence only)
  - WSTG-SESS-02  Cookie Security Attributes     (evidence only)
"""
import requests
import urllib3

from . import BaseScanner, ScanFinding, register

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@register
class ClickjackingScanner(BaseScanner):
    id = "clickjacking_headers"
    name = "Clickjacking / Framing Header Scanner"
    description = (
        "Fetches the endpoint and inspects X-Frame-Options, "
        "Content-Security-Policy (frame-ancestors), and cookie attributes."
    )
    covers = ["WSTG-CLNT-09", "WSTG-CONF-07", "WSTG-CONF-12", "WSTG-SESS-02"]

    def applies_to(self, endpoint):
        return bool(endpoint.url) and endpoint.url.lower().startswith(("http://", "https://"))

    def scan(self, endpoint):
        try:
            response = requests.get(endpoint.url, verify=False, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            return [ScanFinding(vuln_id=vid, status="error", summary=f"Request failed: {e}")
                    for vid in self.covers]

        headers = response.headers

        xfo = headers.get("X-Frame-Options")

        csp = headers.get("Content-Security-Policy", "")
        frame_ancestors = None
        if "frame-ancestors" in csp:
            for directive in csp.split(";"):
                if "frame-ancestors" in directive:
                    frame_ancestors = directive.strip()
                    break

        samesite_cookies = []
        for cookie in response.cookies:
            samesite_cookies.append({
                "name": cookie.name,
                "samesite": cookie._rest.get("SameSite", "Not explicit"),
                "secure": cookie.secure,
                "httponly": "httponly" in {k.lower() for k in cookie._rest.keys()},
            })

        findings = []

        # --- WSTG-CLNT-09: Clickjacking -- this is a definitive test, so we
        # let it auto-set pass/fail (subject to app.py not clobbering a
        # manual verdict already on file).
        protected = bool(xfo or frame_ancestors)
        findings.append(ScanFinding(
            vuln_id="WSTG-CLNT-09",
            status="pass" if protected else "fail",
            summary=(
                f"Anti-framing directive present ({'X-Frame-Options: ' + xfo if xfo else ''}"
                f"{' + ' if xfo and frame_ancestors else ''}"
                f"{frame_ancestors or ''})".strip()
                if protected else
                "Neither X-Frame-Options nor CSP frame-ancestors detected on "
                f"{response.url} — the page can be embedded in a cross-origin iframe."
            ),
            evidence={
                "requested_url": endpoint.url,
                "final_url": response.url,
                "status_code": response.status_code,
                "x_frame_options": xfo,
                "csp_frame_ancestors": frame_ancestors,
            },
            confidence="high",
        ))

        # --- WSTG-CONF-07 / WSTG-CONF-12 / WSTG-SESS-02: this single request
        # only tells part of the story for these broader checks, so we log
        # it as evidence rather than asserting a verdict.
        findings.append(ScanFinding(
            vuln_id="WSTG-CONF-07",
            status="info",
            summary=f"X-Frame-Options: {xfo or 'missing'} (checked via automated clickjacking scan)",
            evidence={"x_frame_options": xfo, "response_headers": dict(headers)},
            confidence="low",
        ))

        findings.append(ScanFinding(
            vuln_id="WSTG-CONF-12",
            status="info",
            summary=(
                f"CSP header {'present' if csp else 'missing'}"
                + (f"; frame-ancestors: {frame_ancestors}" if frame_ancestors else "")
            ),
            evidence={"csp_raw": csp},
            confidence="low",
        ))

        findings.append(ScanFinding(
            vuln_id="WSTG-SESS-02",
            status="info",
            summary=(f"{len(samesite_cookies)} cookie(s) observed on this response"
                     if samesite_cookies else "No cookies set on this response"),
            evidence={"cookies": samesite_cookies},
            confidence="low",
        ))

        return findings
