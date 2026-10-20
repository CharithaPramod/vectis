# Vectis — Penetration Testing Platform & Sitemap Coverage Tracker

**Vectis** is an advanced, database-backed penetration testing management workspace and Burp Suite coverage tracker. Designed for security consultants and red teams, Vectis bridges the gap between manual testing methodologies, automated scanning tools, and live target architecture.

Instead of maintaining flat spreadsheets or rigid checklists, Vectis structures your assessment around the target's actual attack surface: ingesting Burp Suite sitemaps, heuristically filtering applicable vulnerability checks per endpoint, running automated security probes, executing live terminal commands with real-time SSE streaming, and generating standalone client-ready audit reports.

---

## ⚡ Key Capabilities & Features

### 1. 📋 Multi-Framework Assessment Library
* **Built-in Security Frameworks**:
  * **OWASP WSTG v4.2** (Web Security Testing Guide — 98 checks across 13 phases)
  * **OWASP API Security Top 10** (API-specific attack vectors)
  * **Mobile Security (OWASP MASTG / MASVS)** for Android & iOS
  * **AWS Cloud Security Review** & **Kubernetes (K8s) Cluster Assessment**
  * **Comprehensive Web Application Pentest Methodology** (OWASP WSTG v4 / MITRE ATT&CK / CWE)
* **Custom Checklist Engine**:
  * Download official JSON checklist templates (`/checklists/template`).
  * Import custom methodologies with MITRE ATT&CK tactics, CWE mappings, CVSS scores, remediation advice, and parameterized command scripts.
  * Multi-framework engagement support: attach multiple checklists to a single project.
  * **Dynamic Scope & Checklist Alteration (Safe Toggle)**: Check or uncheck assigned security frameworks at any time directly from the Dashboard or inside an active project. All recorded findings, tester notes, evidence, and CVSS scores are safely preserved in the database and automatically re-appear when a framework is re-enabled.
  * **Engagement Metadata & Details Editing**: Edit project details (Name, Target, Environment, Lead Tester, Tech Stack, Scope Notes, and Rules of Engagement) at any point during the assessment without affecting existing test findings.

### 2. 🗺️ Target Scoping, Domain Lists & Burp Suite Coverage
* **Multi-Domain & Target Scope Import**:
  * Include multiple target domains, subdomains, and hosts directly when creating an engagement or into an active project.
  * Supports comma-separated domains (`app.domain.com, api.domain.com`), line-by-line inputs, and file uploads (`.txt`, `.csv`).
  * Automatic protocol normalization (HTTPS/HTTP), port handling, and heuristic flag assignment (API, Auth, Admin).
* **Burp XML Import**: Import live XML sitemap exports directly from Burp Suite (`Target → Site map → Save selected items`).
* **Visual Sitemap Hierarchy**: Endpoints and hosts are parsed, grouped by host/path segments, and color-coded with live `tested / applicable` coverage badges.
* **Intelligent Heuristic Applicability Engine (`vuln_engine.py`)**:
  * Dynamically calculates which checks are relevant for each endpoint based on HTTP method, query/body parameters, headers, file uploads, authentication paths, IDOR indicators, and API routes.
  * SQLi / XSS checks appear on parameter-bearing endpoints; CSRF / State-change checks appear on state-changing endpoints; Auth checks appear on login/session endpoints; API Top 10 checks appear on `/api` routes; .NET checks appear on `.aspx/.ashx/.asmx`.
* **Testing Workflow**: Fast click-to-cycle statuses (`untested → pass → fail → n/a`), rich markdown/plain-text notes, CVSS scoring, and affected endpoints tagging.

### 3. 💻 Integrated Web Terminal & Command Runner
* **Browser-Based Tool Execution**: Run tools like `nmap`, `ffuf`, `gobuster`, `nikto`, `sqlmap`, `curl`, and custom scripts directly from the workspace.
* **🌐 Total Scope Sequential Execution**:
  * For command templates using domain or target variables (`{{DOMAIN}}`, `{{HOST}}`, `{{URL}}`, `{{TARGET}}`), the tool runner automatically exposes the **Total In-Scope Checklist**.
  * **Default Selected**: All project scope domains and endpoints are checked by default (`[x]`).
  * **Selective Scanning**: Easily uncheck any domain or host to exclude it from the scan, or use `✓ All` / `✕ None` quick toggles.
  * **Sequential Runner (`▶ RUN FOR SCOPE (N TARGETS)`)**: Executes commands sequentially (**one by one**) across all checked domains, preserving template parameters (e.g., `{{PORTS}}`, `{{WORDLIST}}`).
  * **Accurate Output Capture**: Each domain receives its own labeled section banner in the terminal drawer with real-time SSE streaming.
  * **Batch Evidence Archiving**: Automatically appends or lets you manually save all multi-target scan responses formatted cleanly under checklist item notes (`[Total Scope Batch Execution Evidence]`).
  * **Interactive Process Control**: Stop running executions at any time; halts active commands and cancels queued targets cleanly.
* **Live SSE Output Streaming**: Real-time server-sent events provide instant stdout/stderr terminal output with ANSI color support.
* **Smart Parameter Interpolation**: Command templates automatically interpolate endpoint context:
  * `{url}`, `{host}`, `{ip}`, `{path}`, `{method}`, `{port}`, `{assessment_dir}`, `{token}`
* **Interactive Stdin & Process Management**: Send interactive input to running commands or terminate long-running processes on demand.
* **Assessment Directory Isolation**: Output files and logs are automatically saved under `assessments/<project_id>_<project_name>/`.
* **1-Click Notes Integration**: Append command terminal output directly to the active checklist finding with a single click.
* **Artifacts File Explorer & Viewer**: Browse, preview, and download generated tool outputs, scan logs, and evidence artifacts.

### 4. 🤖 Pluggable Automated Security Scanners
* **Modular Plugin Architecture (`scanners/`)**:
  * Subclass `BaseScanner` and use the `@register` decorator to add new automated checks without altering application core code.
  * **Clickjacking & Framing Scanner (`scanners/clickjacking.py`)**: Tests `X-Frame-Options`, CSP `frame-ancestors`, and analyzes cookie security flags.
  * **Security Headers Audit Scanner (`scanners/security_headers.py`)**: Evaluates HSTS, `X-Content-Type-Options`, `Referrer-Policy`, and version disclosure headers.
* **Non-Destructive Scanning**:
  * Run automated checks on a single endpoint or trigger **Scan All** across the entire project.
  * Scanners log structured `[AUTO ...]` findings and raw evidence without overwriting manual tester verdicts.
* **CLI Diagnostic Runner (`scanner_cli.py`)**: Run diagnostic scans against any URL directly from the terminal with formatted ANSI output.

### 5. 🎯 Visual PoC & Exploit Diagnostic Studios
* **Clickjacking Diagnostic Studio (`/preview/clickjacking`)**:
  * Interactive framing test bench with live iframe rendering.
  * Opacity slider for UI redressing proof-of-concept demonstrations.
  * Burst tester and pointer-events toggles.
  * Live HTTP security headers analyzer (`/api/preview/check-headers`).
* **Universal Test & Browser Preview Studio (`/preview/viewer`)**: Safely inspect target endpoints and rendered responses in an isolated browser preview container.

### 6. 🔐 Secrets & API Keys Vault
* Encrypted client-side API Vault for managing OSINT and assessment keys (Shodan, SecurityTrails, VirusTotal, Censys, GitHub, AWS, OpenAI, Anthropic, Custom Bearer Tokens).
* Configured secrets are automatically injected into executing command environments and template substitutions.

### 7. 📄 Comprehensive Audit Reports
* Generate standalone, self-contained HTML audit reports (`/project/<id>/report`).
* Includes executive summary metrics, severity breakdown, CVSS scores, remediation recommendations, affected endpoints matrix, and evidence logs.

---

## 🚀 Quick Start

### Prerequisites
* Python 3.9+
* pip

### Installation & Setup

1. **Clone or navigate to the repository:**
   ```bash
   cd /home/kali/Documents/tools/vectis
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the application:**
   ```bash
   python app.py
   ```

4. **Access the Dashboard:**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

*The SQLite database is initialized automatically at `instance/webpt.db` on first run, and the checklist library is automatically seeded from `seed/checklists/*.json`.*

---

## 🛠️ CLI Diagnostic Scanner

Vectis includes a standalone CLI runner for running automated diagnostic scanners against target URLs:

```bash
# Run clickjacking / framing header diagnostic
python3 scanner_cli.py clickjacking https://example.com/login

# Run security headers audit
python3 scanner_cli.py headers https://example.com

# Run all applicable scanners
python3 scanner_cli.py all https://example.com/api/v1/users
```

---

## 📁 Project Structure

```
vectis/
├── app.py                     # Main Flask application, API routes, command execution & SSE streaming
├── models.py                  # SQLAlchemy database schema (Projects, Endpoints, Checklists, Statuses)
├── extensions.py              # Shared SQLAlchemy database instance
├── burp_parser.py             # XML parser for Burp Suite sitemap exports
├── vuln_engine.py             # Heuristic engine deciding checklist applicability per endpoint
├── scanner_cli.py             # Standalone CLI runner for scanner diagnostics
├── requirements.txt           # Python package dependencies
├── instance/                  # SQLite database storage (webpt.db)
├── assessments/               # Assessment directories with isolated tool outputs & artifacts
│   └── <project_id>_<name>/   # Project-specific logs, tool scans, and output files
├── scanners/                  # Pluggable automated security scanners
│   ├── base.py                # BaseScanner abstract class & ScanFinding dataclass
│   ├── registry.py            # Scanner registry and execution dispatch
│   ├── clickjacking.py        # Clickjacking & framing header scanner
│   ├── security_headers.py    # Security headers and disclosure scanner
│   └── README.md              # Guide for building custom scanner plugins
├── seed/                      # Checklist definitions and import templates
│   ├── checklists/            # Built-in checklist JSON files (WSTG, API Top 10, Mobile, Cloud, K8s)
│   ├── template/              # Official JSON schema template for custom checklists
│   └── sample_burp_export.xml # Sample Burp Suite sitemap for testing
├── templates/                 # Jinja2 HTML templates
│   ├── base.html              # Base layout
│   ├── dashboard.html         # Projects overview, checklist library manager & API vault
│   ├── project.html           # Project workspace, sitemap tree, checklist matrix & terminal
│   ├── report.html            # Standalone client-ready HTML audit report
│   ├── preview_clickjacking.html # Clickjacking PoC and framing test studio
│   └── preview_viewer.html    # Universal browser preview studio
└── static/                    # Front-end styling and JavaScript
    ├── css/style.css          # Dark-mode cyberpunk/terminal stylesheet
    └── js/app.js              # Single-page UI state management, SSE terminal & API handlers
```

---

## 🧩 Extending Vectis with Custom Scanners

Adding an automated security check is straightforward and requires creating only a single file in `scanners/`:

```python
# scanners/cors_scanner.py
from . import BaseScanner, ScanFinding, register

@register
class CorsScanner(BaseScanner):
    id = "cors_misconfig"
    name = "CORS Misconfiguration Check"
    description = "Checks for arbitrary origin reflection in CORS headers."
    covers = ["WSTG-CLNT-07"]

    def applies_to(self, endpoint):
        return endpoint.is_api or endpoint.has_params

    def scan(self, endpoint):
        # Perform HTTP request (never raise unhandled exceptions)
        # Return list of ScanFinding objects
        return [
            ScanFinding(
                vuln_id="WSTG-CLNT-07",
                status="pass",        # 'pass' | 'fail' | 'info' | 'error'
                summary="CORS Access-Control-Allow-Origin is properly restricted.",
                evidence={"origin_tested": "https://evil.com"},
                confidence="high",    # 'high' confidence sets status on untested checks
            )
        ]
```

*The scanner will automatically register at startup and be available in both the Web UI and the CLI runner.*

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
