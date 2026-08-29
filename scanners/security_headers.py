"""
A focused HTTP security headers auditor for WSTG-CONF-07.

This is deliberately a separate scanner from clickjacking.py (rather than
bolting more checks onto that one) to prove out the plugin model: two
scanners can both report findings for the same VulnCheck id, and
apply_scan_findings() in app.py handles that fine because only ONE of
them (this one) asserts a real pass/fail verdict at high confidence --
the clickjacking scanner's WSTG-CONF-07 finding stays 'info' and just
contributes supporting evidence underneath.
"""
import requests
import urllib3

from . import BaseScanner, ScanFinding, register

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# header -> validator(value) -> True if the header is configured acceptably.
# HSTS is only required on https endpoints (checked separately below).
REQUIRED_HEADERS = {
    "X-Content-Type-Options": lambda v: v is not None and "nosniff" in v.lower(),
    "Referrer-Policy": lambda v: v is not None and v.strip() != "",
}

# present-or-not is informational rather than pass/fail-worthy on its own
OPTIONAL_HEADERS = ["Permissions-Policy", "X-XSS-Protection"]

VERSION_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


@register
class SecurityHeadersScanner(BaseScanner):
    id = "security_headers_audit"
    name = "HTTP Security Headers Audit"
    description = (
        "Checks HSTS (on https), X-Content-Type-Options, Referrer-Policy, "
        "and flags version-disclosing headers."
    )
    covers = ["WSTG-CONF-07"]

    def applies_to(self, endpoint):
        return bool(endpoint.url) and endpoint.url.lower().startswith(("http://", "https://"))

    def scan(self, endpoint):
        try:
            response = requests.get(endpoint.url, verify=False, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            return [ScanFinding(vuln_id="WSTG-CONF-07", status="error", summary=f"Request failed: {e}")]

        headers = response.headers
        is_https = response.url.lower().startswith("https://")

        missing = [name for name, ok in REQUIRED_HEADERS.items() if not ok(headers.get(name))]
        if is_https and not headers.get("Strict-Transport-Security"):
            missing.append("Strict-Transport-Security")

        disclosed = {h: headers[h] for h in VERSION_DISCLOSURE_HEADERS if h in headers}
        optional_present = [h for h in OPTIONAL_HEADERS if h in headers]

        protected = len(missing) == 0
        summary_parts = []
        if missing:
            summary_parts.append(f"Missing/misconfigured: {', '.join(missing)}")
        else:
            summary_parts.append("All required security headers present and correctly configured")
        if disclosed:
            summary_parts.append(f"Version-disclosing header(s) present: {', '.join(disclosed.keys())}")

        return [ScanFinding(
            vuln_id="WSTG-CONF-07",
            status="pass" if protected else "fail",
            summary=" — ".join(summary_parts),
            evidence={
                "checked_url": response.url,
                "missing_required": missing,
                "optional_present": optional_present,
                "version_disclosure_headers": disclosed,
                "all_response_headers": dict(headers),
            },
            confidence="high",
        )]
