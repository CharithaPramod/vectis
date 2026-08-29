#!/usr/bin/env python3
"""
CLI Runner for WebPT Automated Scanners.
Allows executing diagnostic security scanners (Clickjacking, Headers, TLS, etc.)
directly from the terminal with colored output and formatted diagnostics.

Usage:
  python3 scanner_cli.py clickjacking https://target.com/path
  python3 scanner_cli.py headers https://target.com/path
  python3 scanner_cli.py all https://target.com/path
"""
import sys
import os
import json
import argparse
from types import SimpleNamespace

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners import all_scanners, applicable_scanners, run_all

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="WebPT Scanner Diagnostic CLI")
    parser.add_argument("scanner", help="Scanner name ('clickjacking', 'headers', 'all', or scanner ID)")
    parser.add_argument("url", help="Target URL (e.g. https://example.com/login)")
    parser.add_argument("--method", default="GET", help="HTTP Method (default GET)")
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ep = SimpleNamespace(
        url=url,
        method=args.method.upper(),
        host=url.split("//")[-1].split("/")[0],
        path="/" + "/".join(url.split("//")[-1].split("/")[1:]),
        content_type="",
        has_params="?" in url,
        is_state_changing=args.method.upper() in ("POST", "PUT", "DELETE", "PATCH"),
        is_auth_path=any(w in url.lower() for w in ("login", "auth", "signin", "password")),
        is_api="api" in url.lower(),
        is_dotnet=any(ext in url.lower() for ext in (".aspx", ".ashx", ".asmx")),
        has_file_upload="upload" in url.lower(),
        has_id_param=False,
        is_admin_path="admin" in url.lower(),
    )

    print(f"\n{CYAN}{BOLD}================================================================{RESET}")
    print(f"{CYAN}{BOLD}              WEBPT SECURITY SCANNER DIAGNOSTIC                 {RESET}")
    print(f"{CYAN}{BOLD}================================================================{RESET}")
    print(f"🎯 Target URL:   {BOLD}{ep.url}{RESET}")
    print(f"📡 HTTP Method:  {BOLD}{ep.method}{RESET}")
    print(f"⚙️ Scanner Tool: {BOLD}{args.scanner.upper()}{RESET}")
    print(f"{CYAN}----------------------------------------------------------------{RESET}\n")

    chosen = args.scanner.lower()
    scanners_to_run = []

    all_list = all_scanners()
    if chosen in ("all", "*"):
        scanners_to_run = applicable_scanners(ep)
    elif chosen in ("clickjacking", "clickjacking_headers", "framing"):
        scanners_to_run = [s for s in all_list if "clickjacking" in s.id]
    elif chosen in ("headers", "security_headers", "security_headers_audit", "hsts", "csp"):
        scanners_to_run = [s for s in all_list if "security_headers" in s.id]
    else:
        scanners_to_run = [s for s in all_list if chosen in s.id.lower() or chosen in s.name.lower()]

    if not scanners_to_run:
        print(f"{YELLOW}[!] No matching scanner found for '{args.scanner}'. Available scanners:{RESET}")
        for s in all_list:
            print(f"  - {s.id}: {s.name}")
        sys.exit(1)

    total_findings = 0
    passes = 0
    fails = 0

    for scanner in scanners_to_run:
        print(f"{BOLD}► Running Scanner: {scanner.name} ({scanner.id})...{RESET}")
        try:
            findings = scanner.scan(ep)
            for f in findings:
                total_findings += 1
                status_color = GREEN if f.status == "pass" else (RED if f.status == "fail" else (YELLOW if f.status == "info" else RED))
                glyph = "✓ PASS" if f.status == "pass" else ("✕ FAIL" if f.status == "fail" else f"ℹ {f.status.upper()}")
                
                if f.status == "pass":
                    passes += 1
                elif f.status == "fail":
                    fails += 1

                print(f"  {status_color}{BOLD}[{glyph}]{RESET} {BOLD}{f.vuln_id}{RESET} (Confidence: {f.confidence})")
                print(f"     {f.summary}")

                if f.evidence:
                    print(f"     {DIM}Evidence:{RESET}")
                    for k, v in f.evidence.items():
                        if isinstance(v, (dict, list)):
                            v_str = json.dumps(v, indent=2)
                            lines = v_str.split("\n")
                            print(f"       {DIM}{k}:{RESET} {lines[0]}")
                            for l in lines[1:8]:
                                print(f"         {DIM}{l}{RESET}")
                            if len(lines) > 8:
                                print(f"         {DIM}... ({len(lines)-8} more lines){RESET}")
                        else:
                            print(f"       {DIM}{k}:{RESET} {v}")
                print()
        except Exception as e:
            print(f"  {RED}[ERROR]{RESET} Scanner execution failed: {e}\n")

    print(f"{CYAN}----------------------------------------------------------------{RESET}")
    print(f"{BOLD}Scan Diagnostic Summary:{RESET} {total_findings} check(s) evaluated. "
          f"{GREEN}{passes} PASS{RESET}, {RED}{fails} FAIL (VULNERABLE){RESET}.")
    print(f"{CYAN}================================================================{RESET}\n")


if __name__ == "__main__":
    main()
