"""
Domain and target scope parser for Vectis / WebPT.
Parses domain lists, in-scope hosts, URLs, and uploaded files (.txt, .csv)
into structured Endpoint records.
"""
import csv
import io
import json
import re
from urllib.parse import urlsplit

from burp_parser import (
    AUTH_PATH,
    DOTNET_EXT,
    NUMERIC_OR_UUID_SEGMENT,
)
from extensions import db
from models import Endpoint

# Regex to check if a token looks like a hostname, IP address, or URL
DOMAIN_OR_IP_RE = re.compile(
    r"^(https?://)?"  # optional protocol
    r"([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+|localhost|\d{1,3}(\.\d{1,3}){3})"  # hostname or IP
    r"(:\d+)?(/.*)?$",  # optional port and path
    re.IGNORECASE,
)


def is_probable_target(token: str) -> bool:
    """Checks whether a token looks like a valid domain, IP, or URL."""
    if not token:
        return False
    token = token.strip().strip("'\"").strip()
    if not token or token.startswith("#") or token.startswith("//"):
        return False
    if token.startswith(("http://", "https://")):
        return True
    if token.lower().startswith("localhost"):
        return True
    return bool(DOMAIN_OR_IP_RE.match(token))


def normalize_target_domain(raw_entry: str, default_proto: str = "https"):
    """
    Normalizes a single domain/URL string into an endpoint dictionary.
    Returns None if entry is invalid.
    """
    item = raw_entry.strip().strip("'\"").strip()
    if not item or item.startswith("#") or item.startswith("//"):
        return None

    # Strip any trailing commas or semicolons
    item = item.rstrip(",;").strip()
    if not item:
        return None

    proto = default_proto.lower()
    if proto not in ("http", "https"):
        proto = "https"

    if re.match(r"^https?://", item, re.IGNORECASE):
        try:
            parsed = urlsplit(item)
            proto = parsed.scheme.lower()
            netloc = parsed.netloc
            path = parsed.path or "/"
            query = parsed.query
        except Exception:
            return None
    else:
        # Check if item includes a path
        if "/" in item:
            host_part, _, path_part = item.partition("/")
            netloc = host_part.strip()
            path = "/" + path_part.strip()
        else:
            netloc = item.strip()
            path = "/"
        query = ""

    netloc = netloc.strip().rstrip("/")
    if not netloc:
        return None

    # Handle port if present
    if ":" in netloc:
        host_name, _, port_str = netloc.partition(":")
        host = f"{host_name.lower()}:{port_str}"
    else:
        host = netloc.lower()

    if not path.startswith("/"):
        path = "/" + path

    url = f"{proto}://{host}{path}"
    if query:
        url += f"?{query}"

    # Compute heuristic flags
    is_auth = bool(AUTH_PATH.search(path))
    is_api = path.lower().startswith(("/api", "/graphql", "/rest", "/rpc")) or "api." in host.lower()
    is_admin = "admin" in path.lower() or "admin." in host.lower()
    is_dotnet = bool(DOTNET_EXT.search(path))
    has_id = bool(NUMERIC_OR_UUID_SEGMENT.search(path))

    return {
        "method": "GET",
        "host": host,
        "path": path,
        "url": url,
        "query_params": [query] if query else [],
        "body_params": [],
        "content_type": "",
        "status_code": "",
        "mimetype": "",
        "has_params": bool(query),
        "is_state_changing": False,
        "is_auth_path": is_auth,
        "is_api": is_api,
        "is_dotnet": is_dotnet,
        "has_file_upload": False,
        "has_id_param": has_id,
        "is_admin_path": is_admin,
        "source": "domain_list",
    }


def parse_domains_text(text: str, default_proto: str = "https"):
    """
    Parses a string containing domains separated by commas, newlines, semicolons, tabs, or CSV rows.
    Returns a deduplicated list of endpoint dicts.
    """
    if not text:
        return []

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    candidates = []

    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#") or line_clean.startswith("//"):
            continue

        # Check if line contains CSV / comma / semicolon / tab delimiters
        # Use csv reader to handle potential quotes properly
        try:
            reader = csv.reader(io.StringIO(line_clean), delimiter=",", skipinitialspace=True)
            row_tokens = next(reader)
        except Exception:
            row_tokens = line_clean.split(",")

        for token in row_tokens:
            token = token.strip()
            # If token itself has semicolons, split those too
            if ";" in token:
                sub_tokens = token.split(";")
            elif "\t" in token:
                sub_tokens = token.split("\t")
            else:
                sub_tokens = [token]

            for st in sub_tokens:
                st = st.strip()
                if not st or st.startswith("#") or st.startswith("//"):
                    continue

                # If space separated multiple domains on one line (e.g. 'a.com b.com')
                # only split if not a URL with spaces
                if " " in st and not st.startswith(("http://", "https://")):
                    parts = st.split()
                    for p in parts:
                        if is_probable_target(p):
                            candidates.append(p)
                else:
                    if is_probable_target(st):
                        candidates.append(st)

    # Normalize and deduplicate by (method, url)
    results = []
    seen = set()

    for cand in candidates:
        ep_dict = normalize_target_domain(cand, default_proto=default_proto)
        if not ep_dict:
            continue
        key = (ep_dict["method"], ep_dict["url"])
        if key not in seen:
            seen.add(key)
            results.append(ep_dict)

    return results


def add_endpoints_to_project(project, endpoint_dicts):
    """
    Takes a Project model and a list of endpoint dicts.
    Inserts new Endpoint rows into the database (skipping duplicates).
    Returns (added_count, skipped_count).
    """
    if not endpoint_dicts:
        return 0, 0

    added = 0
    skipped = 0

    for ep_data in endpoint_dicts:
        existing = Endpoint.query.filter_by(
            project_id=project.id,
            method=ep_data["method"],
            url=ep_data["url"],
        ).first()

        if existing:
            skipped += 1
            continue

        ep = Endpoint(
            project_id=project.id,
            method=ep_data["method"],
            host=ep_data["host"],
            path=ep_data["path"],
            url=ep_data["url"],
            query_params=json.dumps(ep_data.get("query_params", [])),
            body_params=json.dumps(ep_data.get("body_params", [])),
            content_type=ep_data.get("content_type", ""),
            status_code=ep_data.get("status_code", ""),
            mimetype=ep_data.get("mimetype", ""),
            has_params=ep_data.get("has_params", False),
            is_state_changing=ep_data.get("is_state_changing", False),
            is_auth_path=ep_data.get("is_auth_path", False),
            is_api=ep_data.get("is_api", False),
            is_dotnet=ep_data.get("is_dotnet", False),
            has_file_upload=ep_data.get("has_file_upload", False),
            has_id_param=ep_data.get("has_id_param", False),
            is_admin_path=ep_data.get("is_admin_path", False),
            source=ep_data.get("source", "domain_list"),
        )
        db.session.add(ep)
        added += 1

    if added > 0:
        db.session.commit()

    return added, skipped


def parse_single_target(target_str: str, default_proto: str = "https"):
    """Normalizes a single target string if it looks like a valid target domain/URL."""
    if not target_str or not is_probable_target(target_str):
        return None
    return normalize_target_domain(target_str, default_proto=default_proto)
