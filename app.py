import glob
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime
import requests
import urllib3

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    abort,
    Response,
    send_file,
    send_from_directory,
)
import re

from extensions import db
from models import (
    ChecklistType,
    Project,
    Endpoint,
    VulnCheck,
    EndpointVulnStatus,
    ProjectVulnStatus,
    project_vuln_endpoints,
)
from burp_parser import parse_burp_xml
from vuln_engine import applicable_checks_for_endpoint, phase_scope
from scanners import applicable_scanners, run_all as run_all_scanners

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SEED_DIR = os.path.join(BASE_DIR, "seed")
CHECKLISTS_DIR = os.path.join(SEED_DIR, "checklists")
TEMPLATE_PATH = os.path.join(SEED_DIR, "template", "checklist_template.json")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        BASE_DIR, "instance", "webpt.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB upload cap

    db.init_app(app)

    @app.template_filter("from_json")
    def from_json_filter(s):
        try:
            return json.loads(s) if s else []
        except (TypeError, ValueError):
            return []

    @app.template_filter("pretty_json")
    def pretty_json_filter(s):
        try:
            return json.dumps(json.loads(s), indent=2) if s else "{}"
        except (TypeError, ValueError):
            return s or "{}"

    with app.app_context():
        db.create_all()
        # Ensure SQLite table schemas are up-to-date across migrations
        ensure_columns(db.engine, "vuln_check", {
            "checklist_type_id": "VARCHAR(60) DEFAULT 'web-owasp-wstg'",
            "mitre_tactic": "VARCHAR(100) DEFAULT ''",
            "mitre_technique": "TEXT DEFAULT '[]'",
            "recommendation": "TEXT DEFAULT ''",
            "cvss_score": "VARCHAR(50) DEFAULT ''",
            "command_template": "TEXT DEFAULT ''",
            "references": "TEXT DEFAULT '[]'",
        })
        ensure_columns(db.engine, "endpoint_vuln_status", {
            "automated": "BOOLEAN DEFAULT 0",
            "last_scan_at": "DATETIME",
            "scan_evidence": "TEXT DEFAULT ''",
        })
        ensure_columns(db.engine, "project_vuln_status", {
            "custom_affected": "TEXT DEFAULT '[]'",
        })
        cleanup_orphaned_records(db.engine)
        seed_all_checklists()

    register_routes(app)
    return app


def ensure_columns(engine, table, columns):
    """Lightweight auto-migration: adds any missing columns to an existing SQLite table."""
    with engine.connect() as conn:
        try:
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for col, decl in columns.items():
                if col not in existing:
                    conn.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN "{col}" {decl}')
            conn.commit()
        except Exception as e:
            print(f"ensure_columns warning for {table}: {e}")


def cleanup_orphaned_records(engine):
    """Clean up any orphaned records in SQLite association and child tables."""
    with engine.connect() as conn:
        try:
            conn.exec_driver_sql("DELETE FROM project_checklists WHERE project_id NOT IN (SELECT id FROM project)")
            conn.exec_driver_sql("DELETE FROM project_checklists WHERE checklist_id NOT IN (SELECT id FROM checklist_type)")
            conn.exec_driver_sql("DELETE FROM endpoint WHERE project_id NOT IN (SELECT id FROM project)")
            conn.exec_driver_sql("DELETE FROM project_vuln_status WHERE project_id NOT IN (SELECT id FROM project)")
            conn.exec_driver_sql("DELETE FROM project_vuln_status WHERE vuln_id NOT IN (SELECT id FROM vuln_check)")
            conn.exec_driver_sql("DELETE FROM endpoint_vuln_status WHERE endpoint_id NOT IN (SELECT id FROM endpoint)")
            conn.exec_driver_sql("DELETE FROM endpoint_vuln_status WHERE vuln_id NOT IN (SELECT id FROM vuln_check)")
            conn.exec_driver_sql("DELETE FROM project_vuln_endpoints WHERE status_id NOT IN (SELECT id FROM project_vuln_status)")
            conn.exec_driver_sql("DELETE FROM project_vuln_endpoints WHERE endpoint_id NOT IN (SELECT id FROM endpoint)")
            conn.commit()
        except Exception as e:
            print(f"cleanup_orphaned_records warning: {e}")


def import_checklist_dict(data, is_builtin=False):
    """Parses a dictionary representation of a checklist and inserts or updates
    its ChecklistType and VulnCheck items."""
    checklist_id = data.get("id", "").strip()
    name = data.get("name", "").strip()
    if not checklist_id or not name:
        raise ValueError("Checklist must specify both an 'id' and a 'name'.")

    ct = db.session.get(ChecklistType, checklist_id)
    if not ct:
        ct = ChecklistType(
            id=checklist_id,
            name=name,
            description=data.get("description", ""),
            category=data.get("category", "Custom"),
            icon=data.get("icon", "📋"),
            version=data.get("version", "1.0"),
            is_builtin=is_builtin,
        )
        db.session.add(ct)
    else:
        ct.name = name
        ct.description = data.get("description", ct.description)
        ct.category = data.get("category", ct.category)
        ct.icon = data.get("icon", ct.icon)
        ct.version = data.get("version", ct.version)

    items_count = 0
    phases = data.get("phases", [])
    if not phases and "items" in data:
        phases = [
            {
                "id": "GENERAL",
                "name": "General Assessment",
                "scope": data.get("scope", "endpoint"),
                "items": data["items"],
            }
        ]

    for phase in phases:
        p_id = phase.get("id", "GENERAL")
        p_name = phase.get("name", "General Checks")
        p_scope = phase.get("scope", "endpoint")
        for item in phase.get("items", []):
            item_id = item.get("id", "").strip()
            if not item_id:
                continue
            v = db.session.get(VulnCheck, item_id)
            if not v:
                v = VulnCheck(
                    id=item_id,
                    checklist_type_id=ct.id,
                    phase_id=p_id,
                    phase_name=p_name,
                    name=item.get("name", item_id),
                )
                db.session.add(v)
            v.checklist_type_id = ct.id
            v.phase_id = p_id
            v.phase_name = p_name
            v.scope = p_scope
            v.name = item.get("name", v.name)
            v.sev = item.get("sev", "info")
            v.how = item.get("how", item.get("description", ""))
            v.cases = (
                json.dumps(item.get("cases", []))
                if isinstance(item.get("cases"), list)
                else (item.get("cases") or "[]")
            )
            v.expected = item.get("expected", item.get("expected_results", ""))
            v.recommendation = item.get(
                "recommendation", item.get("default_recommendation", "")
            )
            v.cwe = (
                json.dumps(item.get("cwe", []))
                if isinstance(item.get("cwe"), list)
                else (item.get("cwe") or "[]")
            )
            v.mitre = (
                json.dumps(item.get("mitre", []))
                if isinstance(item.get("mitre"), list)
                else (item.get("mitre") or "[]")
            )
            v.mitre_tactic = item.get(
                "mitre_tactic", item.get("mitre_framework", "")
            )
            v.mitre_technique = (
                json.dumps(item.get("mitre_technique", []))
                if isinstance(item.get("mitre_technique"), list)
                else (item.get("mitre_technique") or "[]")
            )
            v.cvss_score = item.get("cvss_score", item.get("cvss", ""))
            v.command_template = item.get(
                "command_template", item.get("command", item.get("script", ""))
            )
            v.tools = (
                json.dumps(item.get("tools", []))
                if isinstance(item.get("tools"), list)
                else (item.get("tools") or "[]")
            )
            v.references = (
                json.dumps(item.get("references", []))
                if isinstance(item.get("references"), list)
                else (item.get("references") or "[]")
            )
            items_count += 1

    db.session.commit()
    return ct, items_count


def export_checklist_dict(checklist_type):
    """Exports a ChecklistType and all its VulnCheck records as a clean JSON dict."""
    phases_map = defaultdict(lambda: {"id": "", "name": "", "scope": "endpoint", "items": []})
    for check in checklist_type.checks.order_by(VulnCheck.phase_id, VulnCheck.id).all():
        p_entry = phases_map[check.phase_id]
        p_entry["id"] = check.phase_id
        p_entry["name"] = check.phase_name
        p_entry["scope"] = check.scope
        p_entry["items"].append({
            "id": check.id,
            "name": check.name,
            "sev": check.sev,
            "mitre_tactic": check.mitre_tactic,
            "mitre_technique": json.loads(check.mitre_technique) if check.mitre_technique else [],
            "mitre": json.loads(check.mitre) if check.mitre else [],
            "cwe": json.loads(check.cwe) if check.cwe else [],
            "cvss_score": check.cvss_score,
            "how": check.how,
            "cases": json.loads(check.cases) if check.cases else [],
            "expected": check.expected,
            "recommendation": check.recommendation,
            "tools": json.loads(check.tools) if check.tools else [],
            "command_template": check.command_template,
            "references": json.loads(check.references) if check.references else [],
        })
    return {
        "id": checklist_type.id,
        "name": checklist_type.name,
        "description": checklist_type.description,
        "category": checklist_type.category,
        "icon": checklist_type.icon,
        "version": checklist_type.version,
        "is_builtin": checklist_type.is_builtin,
        "phases": list(phases_map.values()),
    }


def seed_all_checklists():
    """Scans seed/checklists/ directory and loads all JSON checklists."""
    if not os.path.exists(CHECKLISTS_DIR):
        return
    checklist_files = glob.glob(os.path.join(CHECKLISTS_DIR, "*.json"))
    for file_path in checklist_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                import_checklist_dict(data, is_builtin=True)
        except Exception as e:
            print(f"Error seeding checklist from {file_path}: {e}")


def build_sitemap_tree(endpoints):
    """Turns a flat endpoint list into a nested dict tree keyed by host then path segments."""
    tree = {}
    for ep in endpoints:
        host_node = tree.setdefault(
            ep.host or "(unknown host)", {"__children__": {}, "__endpoints__": []}
        )
        segments = [s for s in ep.path.split("/") if s]
        node = host_node
        for seg in segments:
            node = node["__children__"].setdefault(
                seg, {"__children__": {}, "__endpoints__": []}
            )
        node["__endpoints__"].append(ep)
    return tree


def compute_endpoint_vuln_counts(project):
    """Calculates vulnerability counts by severity for every endpoint in the project."""
    endpoint_vulns = {}
    for ep in project.endpoints:
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
        }
        # Check ProjectVulnStatus affected endpoints
        for st in ep.affected_vuln_statuses:
            if st.project_id == project.id and st.status == "fail":
                sev = (st.vuln.sev if st.vuln else "info").lower()
                counts[sev] = counts.get(sev, 0) + 1
                counts["total"] += 1

        # Also support legacy EndpointVulnStatus findings if present
        for st in ep.statuses:
            if st.status == "fail":
                sev = (st.vuln.sev if st.vuln else "info").lower()
                # avoid double counting if also in ProjectVulnStatus
                if not any(ps.vuln_id == st.vuln_id and ps.status == "fail" for ps in ep.affected_vuln_statuses):
                    counts[sev] = counts.get(sev, 0) + 1
                    counts["total"] += 1

        endpoint_vulns[ep.id] = counts
    return endpoint_vulns


def apply_scan_findings(endpoint):
    scanners = applicable_scanners(endpoint)
    findings = run_all_scanners(endpoint)
    now = datetime.utcnow()
    stamp = now.strftime("%Y-%m-%d %H:%M UTC")
    results = []

    for finding in findings:
        vuln = db.session.get(VulnCheck, finding.vuln_id)
        if not vuln:
            continue

        status_row = EndpointVulnStatus.query.filter_by(
            endpoint_id=endpoint.id, vuln_id=finding.vuln_id
        ).first()
        if not status_row:
            status_row = EndpointVulnStatus(
                endpoint_id=endpoint.id,
                vuln_id=finding.vuln_id,
                status="untested",
                notes="",
                cvss="",
            )
            db.session.add(status_row)

        auto_note = f"[AUTO {stamp}] {finding.summary}"
        status_row.notes = (
            f"{status_row.notes}\n\n{auto_note}".strip()
            if status_row.notes
            else auto_note
        )
        status_row.scan_evidence = json.dumps(finding.evidence)
        status_row.automated = True
        status_row.last_scan_at = now

        if (
            finding.confidence == "high"
            and finding.status in ("pass", "fail")
            and status_row.status == "untested"
        ):
            status_row.status = finding.status

        # Also update ProjectVulnStatus to attach affected endpoint if fail
        if finding.status == "fail":
            proj_status = ProjectVulnStatus.query.filter_by(
                project_id=endpoint.project_id, vuln_id=finding.vuln_id
            ).first()
            if not proj_status:
                proj_status = ProjectVulnStatus(
                    project_id=endpoint.project_id,
                    vuln_id=finding.vuln_id,
                    status="fail",
                    notes=auto_note,
                    cvss="",
                )
                db.session.add(proj_status)
            if endpoint not in proj_status.affected_endpoints:
                proj_status.affected_endpoints.append(endpoint)

        db.session.commit()
        results.append({
            "vuln_id": finding.vuln_id,
            "status": status_row.status,
            "notes": status_row.notes,
            "auto_status_suggestion": finding.status,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "last_scan_at": now.strftime("%Y-%m-%d %H:%M UTC"),
        })

    return {"ok": True, "results": results, "scanners_run": [s.id for s in scanners]}


def register_routes(app):

    # ---------------------------------------------------------- dashboard
    @app.route("/")
    def dashboard():
        projects = Project.query.order_by(Project.created_at.desc()).all()
        checklist_types = ChecklistType.query.order_by(
            ChecklistType.is_builtin.desc(), ChecklistType.category, ChecklistType.name
        ).all()
        return render_template(
            "dashboard.html", projects=projects, checklist_types=checklist_types
        )

    @app.route("/projects", methods=["POST"])
    def create_project():
        name = request.form.get("name", "").strip()
        if not name:
            flash("Project name is required.", "error")
            return redirect(url_for("dashboard"))

        selected_checklist_ids = request.form.getlist("checklist_types")
        # Deduplicate IDs while preserving selection order
        selected_checklist_ids = list(dict.fromkeys(selected_checklist_ids))
        if not selected_checklist_ids:
            selected_checklist_ids = ["web-owasp-wstg"]

        p = Project(
            name=name,
            target=request.form.get("target", "").strip(),
            tester=request.form.get("tester", "").strip(),
            env=request.form.get("env", "Staging").strip(),
            tech_stack=request.form.get("tech_stack", "").strip(),
            notes=request.form.get("notes", "").strip(),
        )
        db.session.add(p)

        for c_id in selected_checklist_ids:
            ct = db.session.get(ChecklistType, c_id)
            if ct and ct not in p.checklist_types:
                p.checklist_types.append(ct)

        db.session.commit()
        flash(f"Project '{p.name}' created with {len(p.checklist_types)} checklist(s).", "success")
        return redirect(url_for("project_view", project_id=p.id))

    @app.route("/projects/<int:project_id>/delete", methods=["POST"])
    def delete_project(project_id):
        p = Project.query.get_or_404(project_id)
        p.checklist_types.clear()
        db.session.delete(p)
        db.session.commit()
        flash(f"Project '{p.name}' deleted.", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------ checklist management
    @app.route("/checklists/template", methods=["GET"])
    def download_template():
        """Download official JSON checklist template."""
        if not os.path.exists(TEMPLATE_PATH):
            abort(404)
        return send_file(
            TEMPLATE_PATH,
            as_attachment=True,
            download_name="webpt_checklist_template.json",
            mimetype="application/json",
        )

    @app.route("/checklists/<type_id>/export", methods=["GET"])
    def export_checklist(type_id):
        """Export a specific checklist type as JSON."""
        ct = ChecklistType.query.get_or_404(type_id)
        data = export_checklist_dict(ct)
        json_str = json.dumps(data, indent=2)
        return Response(
            json_str,
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={type_id}_checklist.json"
            },
        )

    @app.route("/checklists/import", methods=["POST"])
    def import_checklist():
        """Upload and import a custom JSON checklist file."""
        f = request.files.get("checklist_file")
        if not f or f.filename == "":
            flash("Please choose a JSON checklist file to upload.", "error")
            return redirect(url_for("dashboard"))

        try:
            content = f.read().decode("utf-8")
            data = json.loads(content)
        except Exception as e:
            flash(f"Invalid JSON format: {e}", "error")
            return redirect(url_for("dashboard"))

        try:
            if isinstance(data, list):
                imported_names = []
                for item in data:
                    ct, count = import_checklist_dict(item, is_builtin=False)
                    imported_names.append(f"{ct.name} ({count} checks)")
                flash(f"Successfully imported {len(data)} checklist(s): {', '.join(imported_names)}.", "success")
            else:
                ct, count = import_checklist_dict(data, is_builtin=False)
                custom_path = os.path.join(CHECKLISTS_DIR, f"{ct.id}.json")
                with open(custom_path, "w", encoding="utf-8") as out:
                    json.dump(export_checklist_dict(ct), out, indent=2)
                flash(f"Checklist '{ct.name}' imported successfully with {count} items.", "success")
        except Exception as e:
            flash(f"Failed to import checklist: {e}", "error")

        return redirect(url_for("dashboard"))

    @app.route("/checklists/<type_id>/delete", methods=["POST"])
    def delete_checklist(type_id):
        ct = ChecklistType.query.get_or_404(type_id)
        if ct.is_builtin:
            flash("Built-in checklists cannot be deleted.", "error")
            return redirect(url_for("dashboard"))

        name = ct.name
        custom_path = os.path.join(CHECKLISTS_DIR, f"{type_id}.json")
        if os.path.exists(custom_path):
            os.remove(custom_path)

        db.session.delete(ct)
        db.session.commit()
        flash(f"Checklist '{name}' deleted.", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------- project view
    @app.route("/project/<int:project_id>")
    def project_view(project_id):
        project = Project.query.get_or_404(project_id)

        # Legacy project compatibility: if no checklist types associated, assign default web checklist
        if not project.checklist_types:
            default_ct = db.session.get(ChecklistType, "web-owasp-wstg")
            if default_ct and default_ct not in project.checklist_types:
                project.checklist_types.append(default_ct)
                db.session.commit()

        active_type_ids = [ct.id for ct in project.checklist_types]
        all_checks = (
            VulnCheck.query.filter(VulnCheck.checklist_type_id.in_(active_type_ids))
            .order_by(VulnCheck.checklist_type_id, VulnCheck.phase_id, VulnCheck.id)
            .all()
        )

        endpoints = project.endpoints.order_by(Endpoint.host, Endpoint.path).all()
        tree = build_sitemap_tree(endpoints)
        endpoint_vulns = compute_endpoint_vuln_counts(project)

        # Build project_statuses dict
        project_statuses = {s.vuln_id: s for s in project.checklist_statuses}

        # Calculate project stats
        total_checks = len(all_checks)
        tested_checks = sum(1 for c in all_checks if project_statuses.get(c.id) and project_statuses[c.id].status != "untested")
        failed_checks = sum(1 for c in all_checks if project_statuses.get(c.id) and project_statuses[c.id].status == "fail")

        selected_endpoint_id = request.args.get("filter_endpoint", type=int)
        selected_endpoint = db.session.get(Endpoint, selected_endpoint_id) if selected_endpoint_id else None

        return render_template(
            "project.html",
            project=project,
            tree=tree,
            endpoints=endpoints,
            endpoint_vulns=endpoint_vulns,
            all_checks=all_checks,
            project_statuses=project_statuses,
            active_checklists=project.checklist_types,
            stats={
                "endpoints": len(endpoints),
                "total": total_checks,
                "tested": tested_checks,
                "failed": failed_checks,
                "pct": (
                    round(100 * tested_checks / total_checks)
                    if total_checks
                    else 0
                ),
            },
            selected_endpoint=selected_endpoint,
        )

    # -------------------------------------------------------- burp import
    @app.route("/project/<int:project_id>/import-burp", methods=["POST"])
    def import_burp(project_id):
        project = Project.query.get_or_404(project_id)
        f = request.files.get("burp_file")
        if not f or f.filename == "":
            flash("Choose a Burp Suite XML sitemap export first.", "error")
            return redirect(url_for("project_view", project_id=project.id))
        try:
            xml_bytes = f.read()
            parsed = parse_burp_xml(
                xml_bytes, tech_stack_hint=project.tech_stack or ""
            )
        except Exception as e:
            flash(
                f"Could not parse that file as a Burp XML sitemap export: {e}", "error"
            )
            return redirect(url_for("project_view", project_id=project.id))

        if not parsed:
            flash(
                "No <item> entries found in that file. Export from Burp: Target > Site map > "
                "right-click host(s) > 'Save selected items' (XML format).",
                "error",
            )
            return redirect(url_for("project_view", project_id=project.id))

        added, updated = 0, 0
        for ep_data in parsed:
            existing = Endpoint.query.filter_by(
                project_id=project.id,
                method=ep_data["method"],
                url=ep_data["url"],
            ).first()
            if existing:
                for k, v in ep_data.items():
                    if k in ("query_params", "body_params"):
                        setattr(existing, k, json.dumps(v))
                    else:
                        setattr(existing, k, v)
                updated += 1
            else:
                ep = Endpoint(
                    project_id=project.id,
                    method=ep_data["method"],
                    host=ep_data["host"],
                    path=ep_data["path"],
                    url=ep_data["url"],
                    query_params=json.dumps(ep_data["query_params"]),
                    body_params=json.dumps(ep_data["body_params"]),
                    content_type=ep_data["content_type"],
                    status_code=ep_data["status_code"],
                    mimetype=ep_data["mimetype"],
                    has_params=ep_data["has_params"],
                    is_state_changing=ep_data["is_state_changing"],
                    is_auth_path=ep_data["is_auth_path"],
                    is_api=ep_data["is_api"],
                    is_dotnet=ep_data["is_dotnet"],
                    has_file_upload=ep_data["has_file_upload"],
                    has_id_param=ep_data["has_id_param"],
                    is_admin_path=ep_data["is_admin_path"],
                    source="burp",
                )
                db.session.add(ep)
                added += 1
        db.session.commit()
        flash(
            f"Sitemap import complete — {added} new endpoint(s), {updated} updated.",
            "success",
        )
        return redirect(url_for("project_view", project_id=project.id))

    @app.route(
        "/project/<int:project_id>/endpoint/<int:endpoint_id>/delete",
        methods=["POST"],
    )
    def delete_endpoint(project_id, endpoint_id):
        ep = Endpoint.query.get_or_404(endpoint_id)
        if ep.project_id != project_id:
            abort(404)
        db.session.delete(ep)
        db.session.commit()
        return redirect(url_for("project_view", project_id=project_id))

    # ------------------------------------------------------- automated scans
    @app.route("/api/endpoint/<int:endpoint_id>/scan", methods=["POST"])
    def scan_endpoint(endpoint_id):
        ep = Endpoint.query.get_or_404(endpoint_id)
        result = apply_scan_findings(ep)
        return jsonify(result)

    @app.route("/project/<int:project_id>/scan-all", methods=["POST"])
    def scan_all_endpoints(project_id):
        project = Project.query.get_or_404(project_id)
        endpoints = project.endpoints.all()
        totals = {
            "endpoints_scanned": 0,
            "findings_written": 0,
            "pass": 0,
            "fail": 0,
            "errors": 0,
        }
        for i, ep in enumerate(endpoints):
            r = apply_scan_findings(ep)
            if r["scanners_run"]:
                totals["endpoints_scanned"] += 1
            for row in r["results"]:
                totals["findings_written"] += 1
                if row["status"] == "pass":
                    totals["pass"] += 1
                elif row["status"] == "fail":
                    totals["fail"] += 1
                if row["auto_status_suggestion"] == "error":
                    totals["errors"] += 1
            if i < len(endpoints) - 1:
                time.sleep(0.3)
        flash(
            f"Automated scan complete — {totals['endpoints_scanned']} endpoint(s) scanned, "
            f"{totals['findings_written']} check(s) updated with evidence "
            f"({totals['fail']} fail, {totals['pass']} pass).",
            "success" if totals["errors"] == 0 else "error",
        )
        return redirect(url_for("project_view", project_id=project.id))

    # ------------------------------------------------------------- APIs
    @app.route("/api/project/<int:project_id>/checklist/<vuln_id>", methods=["POST"])
    def update_project_vuln(project_id, vuln_id):
        project = Project.query.get_or_404(project_id)
        VulnCheck.query.get_or_404(vuln_id)
        data = request.get_json(force=True) or {}

        status = ProjectVulnStatus.query.filter_by(
            project_id=project_id, vuln_id=vuln_id
        ).first()
        if not status:
            status = ProjectVulnStatus(
                project_id=project_id, vuln_id=vuln_id, status="untested", notes="", cvss=""
            )
            db.session.add(status)

        if "status" in data:
            status.status = data["status"]
        if "notes" in data:
            status.notes = data["notes"]
        if "cvss" in data:
            status.cvss = data["cvss"]
        if "custom_affected" in data:
            if isinstance(data["custom_affected"], list):
                status.custom_affected = json.dumps(data["custom_affected"])
            elif isinstance(data["custom_affected"], str):
                status.custom_affected = data["custom_affected"]

        if "affected_endpoint_ids" in data:
            ids = data["affected_endpoint_ids"] or []
            status.affected_endpoints = [
                ep for ep in project.endpoints if ep.id in ids
            ]

        status.updated_at = datetime.utcnow()
        db.session.commit()

        # Return updated affected endpoints list and sitemap counts
        affected_list = [
            {"id": ep.id, "method": ep.method, "path": ep.path, "host": ep.host, "url": ep.url}
            for ep in status.affected_endpoints
        ]
        custom_list = json.loads(status.custom_affected) if status.custom_affected else []
        endpoint_vulns = compute_endpoint_vuln_counts(project)

        return jsonify({
            "ok": True,
            "status": status.status,
            "notes": status.notes,
            "cvss": status.cvss,
            "affected_endpoints": affected_list,
            "custom_affected": custom_list,
            "endpoint_vulns": endpoint_vulns,
        })

    @app.route(
        "/api/project/<int:project_id>/checklist/<vuln_id>/affected-endpoints",
        methods=["POST"],
    )
    def manage_affected_endpoints(project_id, vuln_id):
        project = Project.query.get_or_404(project_id)
        VulnCheck.query.get_or_404(vuln_id)
        data = request.get_json(force=True) or {}

        status = ProjectVulnStatus.query.filter_by(
            project_id=project_id, vuln_id=vuln_id
        ).first()
        if not status:
            status = ProjectVulnStatus(
                project_id=project_id, vuln_id=vuln_id, status="untested", notes="", cvss=""
            )
            db.session.add(status)

        action = data.get("action", "add")
        endpoint_id = data.get("endpoint_id")
        custom_url = data.get("custom_url", "").strip()

        if action == "add" and endpoint_id:
            ep = db.session.get(Endpoint, endpoint_id)
            if ep and ep.project_id == project.id and ep not in status.affected_endpoints:
                status.affected_endpoints.append(ep)
        elif action == "remove" and endpoint_id:
            ep = db.session.get(Endpoint, endpoint_id)
            if ep and ep in status.affected_endpoints:
                status.affected_endpoints.remove(ep)
        elif action == "add_custom" and custom_url:
            custom_list = json.loads(status.custom_affected) if status.custom_affected else []
            if custom_url not in custom_list:
                custom_list.append(custom_url)
                status.custom_affected = json.dumps(custom_list)
        elif action == "remove_custom" and custom_url:
            custom_list = json.loads(status.custom_affected) if status.custom_affected else []
            if custom_url in custom_list:
                custom_list.remove(custom_url)
                status.custom_affected = json.dumps(custom_list)

        status.updated_at = datetime.utcnow()
        db.session.commit()

        affected_list = [
            {"id": ep.id, "method": ep.method, "path": ep.path, "host": ep.host, "url": ep.url}
            for ep in status.affected_endpoints
        ]
        custom_list = json.loads(status.custom_affected) if status.custom_affected else []
        endpoint_vulns = compute_endpoint_vuln_counts(project)

        return jsonify({
            "ok": True,
            "vuln_id": vuln_id,
            "affected_endpoints": affected_list,
            "custom_affected": custom_list,
            "endpoint_vulns": endpoint_vulns,
        })

    # ----------------------------------------------------------- report
    @app.route("/project/<int:project_id>/report")
    def report(project_id):
        project = Project.query.get_or_404(project_id)
        active_type_ids = [ct.id for ct in project.checklist_types]
        all_checks = VulnCheck.query.filter(
            VulnCheck.checklist_type_id.in_(active_type_ids)
        ).all()

        endpoints = project.endpoints.order_by(Endpoint.host, Endpoint.path).all()
        endpoint_vulns = compute_endpoint_vuln_counts(project)

        # Collect all failed checks as findings with their affected endpoints
        findings = []
        proj_statuses = {s.vuln_id: s for s in project.checklist_statuses}
        for c in all_checks:
            st = proj_statuses.get(c.id)
            if st and st.status == "fail":
                affected_eps = list(st.affected_endpoints)
                custom_eps = json.loads(st.custom_affected) if st.custom_affected else []
                findings.append((c, st, affected_eps, custom_eps))

        # Sort findings by severity
        findings.sort(key=lambda f: SEV_ORDER.get(f[0].sev, 5))

        return render_template(
            "report.html",
            project=project,
            endpoints=endpoints,
            endpoint_vulns=endpoint_vulns,
            findings=findings,
            all_checks=all_checks,
            generated=datetime.utcnow(),
        )

    # ----------------------------------------------- interactive tool runner & preview studio
    RUNNING_PROCESSES = {}
    PROCESS_LOCK = threading.Lock()

    def ensure_assessment_wordlists(assessment_dir):
        """Populates common starter wordlists in the assessment directory if they don't exist."""
        default_files = {
            "usernames.txt": "admin\nadministrator\nroot\nuser\ntest\nguest\napi\nsupport\nservice\ndemo\ndev\ninfo\ncontact\nstaff\nmanager\noperator\nwebmaster\nsecurity\naudit\nbackup\n",
            "passwords.txt": "password\n123456\nadmin\nadmin123\nroot\ntoor\nPass1234\npassword123\nqwerty\nletmein\nwelcome\nchangeme\n",
            "emails.txt": "admin@example.com\ntest@example.com\nuser@example.com\nsupport@example.com\ninfo@example.com\n",
            "extensions.txt": "php\naspx\nasp\njsp\njspx\nhtml\njs\njson\nxml\ntxt\nbak\nold\nzip\ntar.gz\nsql\nenv\nyml\nyaml\nconf\nini\n",
            "subs.txt": "www\nmail\napi\ndev\ntest\nstage\nstaging\nadmin\nportal\napp\nvpn\nremote\nsecure\nauth\ninternal\n",
            "wordlist.txt": "admin\napi\napp\nbackup\nbin\nconfig\ncss\ndashboard\ndata\ndb\ndebug\ndev\ndoc\ndocs\ndownload\nfiles\nimages\nimg\ninclude\nincludes\njs\nlib\nlogin\nlogout\nmedia\npanel\nportal\npublic\nrobots.txt\nsitemap.xml\nsrc\nstatic\ntemp\ntest\ntmp\nupload\nuploads\nuser\nusers\nv1\nv2\nwp-admin\nwp-content\nwp-includes\n",
        }
        for fname, content in default_files.items():
            fpath = os.path.join(assessment_dir, fname)
            if not os.path.exists(fpath):
                try:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(content)
                except Exception:
                    pass

    @app.route("/api/tools/run-command", methods=["POST"])
    def run_tool_command():
        data = request.get_json(force=True) or {}
        command = data.get("command", "").strip()
        project_id = data.get("project_id")
        api_keys = data.get("api_keys") or {}
        if not command:
            return jsonify({"error": "No command specified"}), 400

        project = db.session.get(Project, project_id) if project_id else None
        if project:
            safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", project.name).strip("_") or f"project_{project.id}"
            assessment_dir = os.path.join(BASE_DIR, "assessments", f"{project.id}_{safe_name}")
            assessment_name = project.name
        else:
            assessment_dir = os.path.join(BASE_DIR, "assessments", "general")
            assessment_name = "General"

        os.makedirs(assessment_dir, exist_ok=True)
        ensure_assessment_wordlists(assessment_dir)
        process_id = str(uuid.uuid4())

        def stream_output():
            start_time = time.time()
            yield f"data: {json.dumps({'type': 'start', 'process_id': process_id, 'command': command, 'assessment_dir': assessment_dir, 'assessment_name': assessment_name})}\n\n"

            # Set unbuffered python output so CLI scripts flush immediately
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["ASSESSMENT_DIR"] = assessment_dir
            env["OUTPUT_DIR"] = assessment_dir
            env["PROJECT_DIR"] = assessment_dir
            env["ASSESSMENT_NAME"] = assessment_name
            env["PROJECT_NAME"] = assessment_name
            env["PROJECT_ID"] = str(project.id) if project else "0"
            if project:
                env["TARGET_URL"] = project.target or ""
                env["TARGET_HOST"] = project.target or ""
                env["TECH_STACK"] = project.tech_stack or ""
                env["ENVIRONMENT"] = project.env or ""

            # Inject all configured API keys & custom variables into the subprocess environment
            if isinstance(api_keys, dict):
                for k, v in api_keys.items():
                    if k and str(v).strip():
                        env[str(k).strip()] = str(v).strip()

            try:
                proc = subprocess.Popen(
                    command,
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=assessment_dir,
                    env=env,
                    preexec_fn=os.setsid,
                )

                with PROCESS_LOCK:
                    RUNNING_PROCESSES[process_id] = proc

                for line in iter(proc.stdout.readline, ""):
                    yield f"data: {json.dumps({'type': 'stdout', 'text': line})}\n\n"

                proc.stdout.close()
                proc.wait()
                exit_code = proc.returncode
            except Exception as e:
                exit_code = -1
                yield f"data: {json.dumps({'type': 'error', 'text': f'Error executing command: {e}'})}\n\n"
            finally:
                with PROCESS_LOCK:
                    RUNNING_PROCESSES.pop(process_id, None)

                duration = round(time.time() - start_time, 2)
                yield f"data: {json.dumps({'type': 'exit', 'code': exit_code, 'duration': duration, 'assessment_dir': assessment_dir})}\n\n"

        return Response(
            stream_output(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.route("/api/tools/send-input", methods=["POST"])
    def send_tool_input():
        data = request.get_json(force=True) or {}
        process_id = data.get("process_id")
        user_input = data.get("input", "")
        if not process_id:
            return jsonify({"ok": False, "error": "No process_id provided"}), 400

        with PROCESS_LOCK:
            proc = RUNNING_PROCESSES.get(process_id)
            if proc and proc.poll() is None and proc.stdin:
                try:
                    if not user_input.endswith("\n"):
                        user_input += "\n"
                    proc.stdin.write(user_input)
                    proc.stdin.flush()
                    return jsonify({"ok": True, "sent": True})
                except Exception as e:
                    return jsonify({"ok": False, "error": str(e)}), 500
        return jsonify({"ok": False, "message": "Process not found or already ended"})

    @app.route("/api/tools/stop-command", methods=["POST"])
    def stop_tool_command():
        data = request.get_json(force=True) or {}
        process_id = data.get("process_id")
        if not process_id:
            return jsonify({"ok": False, "error": "No process_id provided"}), 400

        with PROCESS_LOCK:
            proc = RUNNING_PROCESSES.get(process_id)
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                return jsonify({"ok": True, "stopped": True})
        return jsonify({"ok": False, "message": "Process not found or already ended"})

    # ------------------------------------------------ assessment artifacts explorer
    @app.route("/api/project/<int:project_id>/artifacts", methods=["GET"])
    def get_project_artifacts(project_id):
        project = Project.query.get_or_404(project_id)
        safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", project.name).strip("_") or f"project_{project.id}"
        assessment_dir = os.path.join(BASE_DIR, "assessments", f"{project.id}_{safe_name}")
        os.makedirs(assessment_dir, exist_ok=True)

        files = []
        for root, dirs, filenames in os.walk(assessment_dir):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                relpath = os.path.relpath(fpath, assessment_dir)
                try:
                    stat = os.stat(fpath)
                    files.append({
                        "name": fname,
                        "relpath": relpath,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except Exception:
                    pass
        return jsonify({
            "ok": True,
            "assessment_dir": assessment_dir,
            "assessment_name": project.name,
            "files": sorted(files, key=lambda x: x["modified"], reverse=True),
        })

    @app.route("/api/project/<int:project_id>/artifacts/download/<path:filename>", methods=["GET"])
    def download_project_artifact(project_id, filename):
        project = Project.query.get_or_404(project_id)
        safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", project.name).strip("_") or f"project_{project.id}"
        assessment_dir = os.path.join(BASE_DIR, "assessments", f"{project.id}_{safe_name}")
        return send_from_directory(assessment_dir, filename, as_attachment=True)

    @app.route("/api/project/<int:project_id>/artifacts/view/<path:filename>", methods=["GET"])
    def view_project_artifact(project_id, filename):
        project = Project.query.get_or_404(project_id)
        safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", project.name).strip("_") or f"project_{project.id}"
        assessment_dir = os.path.join(BASE_DIR, "assessments", f"{project.id}_{safe_name}")
        full_path = os.path.join(assessment_dir, filename)
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            abort(404)

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(100000)  # max 100KB preview
            return jsonify({"ok": True, "filename": filename, "content": content})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.route("/api/project/<int:project_id>/checklist/<vuln_id>/append-notes", methods=["POST"])
    def append_project_notes(project_id, vuln_id):
        Project.query.get_or_404(project_id)
        VulnCheck.query.get_or_404(vuln_id)
        data = request.get_json(force=True) or {}
        notes_addition = data.get("notes", "").strip()
        auto_status = data.get("status")

        if not notes_addition:
            return jsonify({"ok": False, "error": "No notes content provided"}), 400

        status = ProjectVulnStatus.query.filter_by(
            project_id=project_id, vuln_id=vuln_id
        ).first()
        if not status:
            status = ProjectVulnStatus(
                project_id=project_id, vuln_id=vuln_id, status="untested", notes="", cvss=""
            )
            db.session.add(status)

        current_notes = status.notes or ""
        if current_notes.strip():
            status.notes = f"{current_notes.strip()}\n\n{notes_addition}"
        else:
            status.notes = notes_addition

        if auto_status and auto_status in ("pass", "fail", "untested", "na"):
            status.status = auto_status

        status.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            "ok": True,
            "status": status.status,
            "notes": status.notes,
            "cvss": status.cvss,
        })

    # ----------------------------------------------- universal preview & clickjacking studio
    @app.route("/preview/clickjacking")
    def preview_clickjacking():
        target_url = request.args.get("url", "").strip() or request.args.get("target", "").strip()
        project_id = request.args.get("project_id", type=int)
        vuln_id = request.args.get("vuln_id", "WSTG-CLNT-09").strip()

        if target_url and not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        headers_info = {
            "xfo": None,
            "csp": "",
            "frame_ancestors": None,
            "is_protected": False,
        }

        if target_url:
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(target_url, verify=False, timeout=6, allow_redirects=True)
                xfo = r.headers.get("X-Frame-Options")
                csp = r.headers.get("Content-Security-Policy", "")
                fa = None
                if "frame-ancestors" in csp:
                    for directive in csp.split(";"):
                        if "frame-ancestors" in directive:
                            fa = directive.strip()
                            break

                headers_info["xfo"] = xfo
                headers_info["csp"] = csp
                headers_info["frame_ancestors"] = fa
                headers_info["is_protected"] = bool(xfo or fa)
            except Exception:
                pass

        return render_template(
            "preview_clickjacking.html",
            target_url=target_url or "https://example.com",
            headers_info=headers_info,
            project_id=project_id,
            vuln_id=vuln_id,
        )

    @app.route("/preview/clickjacking/poc")
    def preview_clickjacking_poc():
        target_url = request.args.get("url", "https://example.com").strip()
        if target_url and not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        poc_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Clickjacking PoC - {target_url}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; background: #0c1017; color: #c9d1d9; }}
    .hdr {{ background: #161b22; border: 1px solid #30363d; border-left: 4px solid #00ff41; padding: 14px 18px; margin-bottom: 20px; border-radius: 4px; }}
    .hdr h2 {{ margin: 0 0 6px 0; color: #00ff41; font-size: 16px; letter-spacing: 1px; }}
    .stage {{ position: relative; width: 1024px; height: 700px; border: 2px dashed #ff0055; margin: 0 auto; background: #000; overflow: hidden; }}
    .victim-frame {{ width: 100%; height: 100%; border: none; opacity: 0.5; position: absolute; top: 0; left: 0; z-index: 1; }}
    .decoy-layer {{ position: absolute; top: 160px; left: 280px; z-index: 2; pointer-events: none; background: rgba(13,17,23,0.92); border: 1px solid #ff0055; padding: 28px; border-radius: 8px; text-align: center; box-shadow: 0 8px 24px rgba(0,0,0,0.8); }}
    .decoy-btn {{ background: #ff0055; color: #fff; font-size: 15px; font-weight: bold; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }}
  </style>
</head>
<body>
  <div class="hdr">
    <h2>🎯 WebPT Clickjacking / UI Redressing Live Proof of Concept</h2>
    <div style="font-size:12px;color:#8b949e">Target Frame: <b style="color:#58a6ff">{target_url}</b></div>
  </div>
  <div class="stage">
    <iframe class="victim-frame" src="{target_url}"></iframe>
    <div class="decoy-layer">
      <h3 style="color:#ff0055;margin:0 0 10px 0">EXCLUSIVE REWARD</h3>
      <p style="margin:0 0 16px 0;font-size:13px">Click below to claim your complimentary assessment voucher:</p>
      <button class="decoy-btn">CLAIM REWARD NOW</button>
    </div>
  </div>
</body>
</html>"""
        return Response(poc_html, mimetype="text/html")

    @app.route("/api/preview/check-headers")
    def check_preview_headers():
        url = request.args.get("url", "").strip()
        if not url:
            return jsonify({"error": "No url provided"}), 400

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(url, verify=False, timeout=6, allow_redirects=True)
            xfo = r.headers.get("X-Frame-Options")
            csp = r.headers.get("Content-Security-Policy", "")
            fa = None
            if "frame-ancestors" in csp:
                for directive in csp.split(";"):
                    if "frame-ancestors" in directive:
                        fa = directive.strip()
                        break

            return jsonify({
                "ok": True,
                "url": r.url,
                "status_code": r.status_code,
                "xfo": xfo,
                "csp": csp,
                "frame_ancestors": fa,
                "is_protected": bool(xfo or fa),
            })
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    @app.route("/preview/viewer")
    def preview_viewer():
        target = request.args.get("target", "").strip() or request.args.get("host", "").strip()
        port = request.args.get("port", "").strip()
        path = request.args.get("path", "/").strip()
        scheme = request.args.get("scheme", "http").strip()

        if target.startswith("http://"):
            scheme = "http"
            target = target[7:]
        elif target.startswith("https://"):
            scheme = "https"
            target = target[8:]

        host = target.split("/")[0].split(":")[0] if target else "127.0.0.1"
        if not port and ":" in target.split("/")[0]:
            port = target.split("/")[0].split(":")[1]
        if not port:
            port = "80" if scheme == "http" else "443"

        if not path or path == "":
            path = "/"
        if not path.startswith("/"):
            path = "/" + path

        full_url = f"{scheme}://{host}"
        if port and not (scheme == "http" and port == "80") and not (scheme == "https" and port == "443"):
            full_url += f":{port}"
        full_url += path

        return render_template(
            "preview_viewer.html",
            host=host,
            port=port,
            path=path,
            scheme=scheme,
            full_url=full_url,
        )


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)


