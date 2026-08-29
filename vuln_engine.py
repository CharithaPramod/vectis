"""
Decides which VulnCheck items are "applicable" to a given Endpoint.

Checks with scope == "project" (e.g. Scoping, Recon, Mobile app settings, Reporting)
are assessed at the project/application level.

Checks with scope == "endpoint" (e.g. Injection, Auth, SSRF, Headers) are filtered
using keyword heuristics against endpoint flags (has_params, is_state_changing,
is_auth_path, is_api, is_dotnet, has_file_upload, has_id_param, is_admin_path)
so the tester sees a relevant checklist per endpoint.
"""
import re

PROJECT_PHASES = {"P0", "P1", "P2", "P11", "P12"}

RULES = [
    # (keyword regex on "name how", condition lambda(ep) -> bool)
    (re.compile(r"sql injection|sqli", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"command injection|os command|code injection", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"ldap injection", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"nosql", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"xxe|xml external entity", re.I), lambda ep: "xml" in (ep["content_type"] or "").lower() or ep["has_params"]),
    (re.compile(r"ssti|template injection", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"ssrf|server-side request forgery", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"\bxss\b|cross-site scripting", re.I), lambda ep: ep["has_params"] or ep["method"] == "GET"),
    (re.compile(r"deserialization|viewstate", re.I), lambda ep: ep["is_dotnet"] or ep["has_params"]),
    (re.compile(r"file upload|malicious file|webshell", re.I), lambda ep: ep["has_file_upload"] or "upload" in ep["path"].lower()),
    (re.compile(r"csrf|cross-site request forgery", re.I), lambda ep: ep["is_state_changing"]),
    (re.compile(r"race condition", re.I), lambda ep: ep["is_state_changing"]),
    (re.compile(r"business logic|workflow|negative value|payment tamper", re.I), lambda ep: ep["is_state_changing"]),
    (re.compile(r"idor|insecure direct object|object reference|horizontal|vertical privilege|bola", re.I),
        lambda ep: ep["has_id_param"] or True),
    (re.compile(r"path traversal|directory traversal|lfi|rfi", re.I), lambda ep: ep["has_params"]),
    (re.compile(r"jwt|json web token", re.I), lambda ep: True),
    (re.compile(r"session token|session cookie|session fixation|session hijack", re.I), lambda ep: True),
    (re.compile(r"login|brute force|account lockout|credential stuffing|account enumeration|"
                r"password reset|mfa|otp|2fa|logout", re.I), lambda ep: ep["is_auth_path"]),
    (re.compile(r"cors|clickjacking|security header|csp|http method|http verb", re.I), lambda ep: True),
    (re.compile(r"admin|bfla", re.I), lambda ep: ep["is_admin_path"] or True),
    (re.compile(r"swagger|api doc|api version|shadow api|rate limit|mass assignment|"
                r"excessive data exposure|batch request|graphql|bopla", re.I), lambda ep: ep["is_api"] or True),
    (re.compile(r"elmah|trace\.axd|machinekey|x-aspnet-version|\.net\b", re.I), lambda ep: ep["is_dotnet"]),
]


def phase_scope(phase_id: str) -> str:
    return "project" if phase_id in PROJECT_PHASES or phase_id.startswith("MASVS-") else "endpoint"


def is_applicable(check, ep_attrs: dict) -> bool:
    """check: VulnCheck row or dict-like with .name/.how/.phase_id/.scope
       ep_attrs: dict of endpoint boolean flags + method/path/content_type"""
    scope = getattr(check, "scope", None)
    if not scope:
        phase_id = getattr(check, "phase_id", "")
        scope = phase_scope(phase_id)
    if scope != "endpoint":
        return False
    text = f"{getattr(check, 'name', '')} {getattr(check, 'how', '')}"
    for pattern, condition in RULES:
        if pattern.search(text):
            try:
                return bool(condition(ep_attrs))
            except Exception:
                return True
    return True


def applicable_checks_for_endpoint(all_checks, endpoint):
    ep_attrs = {
        "has_params": endpoint.has_params,
        "is_state_changing": endpoint.is_state_changing,
        "is_auth_path": endpoint.is_auth_path,
        "is_api": endpoint.is_api,
        "is_dotnet": endpoint.is_dotnet,
        "has_file_upload": endpoint.has_file_upload,
        "has_id_param": endpoint.has_id_param,
        "is_admin_path": endpoint.is_admin_path,
        "method": endpoint.method,
        "path": endpoint.path,
        "content_type": endpoint.content_type,
    }
    return [c for c in all_checks if is_applicable(c, ep_attrs)]
