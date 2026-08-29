"""
Parses a Burp Suite "Site map -> Save selected items" XML export
(Proxy > right-click host > Save selected items) into a list of endpoint dicts.

Burp XML shape:

<?xml version="1.0"?>
<items burpVersion="..." exportTime="...">
  <item>
    <time>...</time>
    <url><![CDATA[https://target.com/path?x=1]]></url>
    <host ip="1.2.3.4">target.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/path]]></path>
    <extension>...</extension>
    <request base64="true">BASE64...</request>
    <status>200</status>
    <responselength>1234</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true">BASE64...</response>
    <comment></comment>
  </item>
  ...
</items>
"""
import base64
import re
from urllib.parse import urlparse, parse_qsl
from xml.etree import ElementTree as ET

ID_LIKE_PARAM = re.compile(r"(^id$|_id$|^uid$|^uuid$|account|order|invoice|user|customer)", re.I)
NUMERIC_OR_UUID_SEGMENT = re.compile(
    r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I
)
AUTH_PATH = re.compile(
    r"(login|logon|signin|sign-in|signup|sign-up|register|logout|password|reset|forgot|"
    r"mfa|otp|2fa|verify|token|session|auth)", re.I
)
DOTNET_EXT = re.compile(r"\.(aspx|ashx|asmx|axd|svc)(\?|$)", re.I)
STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _text(el, tag):
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _decode_request(req_el):
    """Returns (headers dict, body str, content_type str)."""
    if req_el is None or not req_el.text:
        return {}, "", ""
    is_b64 = req_el.get("base64", "false") == "true"
    try:
        raw = base64.b64decode(req_el.text) if is_b64 else req_el.text.encode()
        raw_text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return {}, "", ""

    header_part, _, body = raw_text.partition("\r\n\r\n")
    if not body and "\n\n" in raw_text:
        header_part, _, body = raw_text.partition("\n\n")

    headers = {}
    lines = header_part.replace("\r\n", "\n").split("\n")
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    content_type = headers.get("content-type", "")
    return headers, body, content_type


def _extract_body_param_names(body, content_type):
    if not body:
        return []
    ct = content_type.lower()
    if "application/x-www-form-urlencoded" in ct:
        return [k for k, _ in parse_qsl(body, keep_blank_values=True)][:100]
    if "multipart/form-data" in ct:
        # \bname=" avoids matching the tail of "filename=" as a field name
        return list(dict.fromkeys(re.findall(r'\bname="([^"]+)"', body)))[:100]
    if "json" in ct:
        return list(dict.fromkeys(re.findall(r'"([A-Za-z0-9_\-]+)"\s*:', body)))[:100]
    return []


def parse_burp_xml(xml_bytes, tech_stack_hint=""):
    """Returns a list of dicts, one per unique (method, url) endpoint."""
    root = ET.fromstring(xml_bytes)
    items = root.findall("item") if root.tag != "item" else [root]

    seen = {}
    for item in items:
        url = _text(item, "url")
        if not url:
            continue
        method = (_text(item, "method") or "GET").upper()
        host = _text(item, "host")
        path = _text(item, "path") or urlparse(url).path or "/"
        status = _text(item, "status")
        mimetype = _text(item, "mimetype")

        headers, body, content_type = _decode_request(item.find("request"))

        parsed = urlparse(url)
        query_params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        body_params = _extract_body_param_names(body, content_type)

        key = (method, url)
        if key in seen:
            continue  # de-dupe repeated hits on same URL+method

        full_path_for_regex = path + ("?" + parsed.query if parsed.query else "")
        all_param_names = query_params + body_params

        is_dotnet = bool(DOTNET_EXT.search(path)) or "asp.net" in tech_stack_hint.lower() \
            or "x-aspnet-version" in headers or "x-powered-by" in headers and "asp" in headers.get("x-powered-by", "").lower()

        seen[key] = {
            "method": method,
            "host": host,
            "path": path,
            "url": url,
            "query_params": query_params,
            "body_params": body_params,
            "content_type": content_type,
            "status_code": status,
            "mimetype": mimetype,
            "has_params": bool(all_param_names),
            "is_state_changing": method in STATE_CHANGING_METHODS,
            "is_auth_path": bool(AUTH_PATH.search(path)),
            "is_api": path.lower().startswith(("/api", "/graphql", "/rest", "/rpc"))
            or "json" in content_type.lower(),
            "is_dotnet": is_dotnet,
            "has_file_upload": "multipart/form-data" in content_type.lower(),
            "has_id_param": bool(NUMERIC_OR_UUID_SEGMENT.search(full_path_for_regex))
            or any(ID_LIKE_PARAM.search(p) for p in all_param_names),
            "is_admin_path": "admin" in path.lower(),
        }

    return list(seen.values())
