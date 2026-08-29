"""
Database models for WebPT.

ChecklistType      -> master assessment type (Web OWASP WSTG, Mobile Android, Mobile iOS, API, Custom)
Project            -> one pentest engagement
Endpoint           -> one URL+method discovered from a Burp Suite sitemap import
VulnCheck          -> master checklist item belonging to a ChecklistType
EndpointVulnStatus -> tester's finding for a (endpoint, vuln check) pair (legacy support / scans)
ProjectVulnStatus  -> tester's checklist test result and finding for a project check,
                      including attached affected endpoints
"""
from datetime import datetime
from extensions import db

# Many-to-many relationship between projects and selected checklist types
project_checklists = db.Table(
    "project_checklists",
    db.Column("project_id", db.Integer, db.ForeignKey("project.id", ondelete="CASCADE"), primary_key=True),
    db.Column("checklist_id", db.String(60), db.ForeignKey("checklist_type.id", ondelete="CASCADE"), primary_key=True),
)

# Many-to-many relationship between a test case finding (ProjectVulnStatus) and affected endpoints
project_vuln_endpoints = db.Table(
    "project_vuln_endpoints",
    db.Column("status_id", db.Integer, db.ForeignKey("project_vuln_status.id", ondelete="CASCADE"), primary_key=True),
    db.Column("endpoint_id", db.Integer, db.ForeignKey("endpoint.id", ondelete="CASCADE"), primary_key=True),
)


class ChecklistType(db.Model):
    """Assessment type definition (e.g. Web App OWASP WSTG, Mobile Android, Mobile iOS, API Top 10, or custom)."""
    __tablename__ = "checklist_type"

    id = db.Column(db.String(60), primary_key=True)   # e.g. 'web-owasp-wstg', 'mobile-android', 'mobile-ios'
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    category = db.Column(db.String(50), default="General")  # Web, Mobile, API, Network, Custom
    icon = db.Column(db.String(30), default="📋")
    version = db.Column(db.String(30), default="1.0")
    is_builtin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    checks = db.relationship(
        "VulnCheck", backref="checklist_type", cascade="all, delete-orphan", lazy="dynamic"
    )


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(300), default="")
    tester = db.Column(db.String(200), default="")
    env = db.Column(db.String(50), default="Staging")
    tech_stack = db.Column(db.String(300), default="")
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    checklist_types = db.relationship(
        "ChecklistType", secondary=project_checklists, backref=db.backref("projects", lazy="dynamic")
    )
    endpoints = db.relationship(
        "Endpoint", backref="project", cascade="all, delete-orphan", lazy="dynamic"
    )
    checklist_statuses = db.relationship(
        "ProjectVulnStatus", backref="project", cascade="all, delete-orphan", lazy="dynamic"
    )


class Endpoint(db.Model):
    __tablename__ = "endpoint"
    __table_args__ = (
        db.UniqueConstraint("project_id", "method", "url", name="uq_endpoint_identity"),
    )

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)

    method = db.Column(db.String(10), default="GET")
    host = db.Column(db.String(255), default="")
    path = db.Column(db.String(1000), default="/")
    url = db.Column(db.String(2000), default="")
    query_params = db.Column(db.Text, default="[]")   # JSON list of names
    body_params = db.Column(db.Text, default="[]")     # JSON list of names
    content_type = db.Column(db.String(200), default="")
    status_code = db.Column(db.String(10), default="")
    mimetype = db.Column(db.String(100), default="")

    # heuristic flags computed at import time
    has_params = db.Column(db.Boolean, default=False)
    is_state_changing = db.Column(db.Boolean, default=False)
    is_auth_path = db.Column(db.Boolean, default=False)
    is_api = db.Column(db.Boolean, default=False)
    is_dotnet = db.Column(db.Boolean, default=False)
    has_file_upload = db.Column(db.Boolean, default=False)
    has_id_param = db.Column(db.Boolean, default=False)
    is_admin_path = db.Column(db.Boolean, default=False)

    source = db.Column(db.String(50), default="burp")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    statuses = db.relationship(
        "EndpointVulnStatus", backref="endpoint", cascade="all, delete-orphan", lazy="dynamic"
    )


class VulnCheck(db.Model):
    """Master checklist item belonging to a ChecklistType. Shared across projects."""
    __tablename__ = "vuln_check"

    id = db.Column(db.String(60), primary_key=True)   # e.g. 'INJ-01', 'MASTG-STORAGE-01'
    checklist_type_id = db.Column(db.String(60), db.ForeignKey("checklist_type.id", ondelete="CASCADE"), nullable=True, default="web-owasp-wstg")
    phase_id = db.Column(db.String(60), nullable=False)
    phase_name = db.Column(db.String(150), nullable=False)
    scope = db.Column(db.String(20), default="endpoint")  # 'endpoint' or 'project'
    name = db.Column(db.String(300), nullable=False)
    sev = db.Column(db.String(20), default="info")
    how = db.Column(db.Text, default="")
    cases = db.Column(db.Text, default="[]")     # JSON list
    expected = db.Column(db.Text, default="")
    recommendation = db.Column(db.Text, default="")  # Default remediation guidance
    cwe = db.Column(db.Text, default="[]")        # JSON list
    mitre = db.Column(db.Text, default="[]")      # JSON list
    mitre_tactic = db.Column(db.String(100), default="")  # e.g. Reconnaissance, Initial Access, Credential Access
    mitre_technique = db.Column(db.Text, default="[]")    # JSON list of technique strings
    cvss_score = db.Column(db.String(50), default="")     # e.g. '8.6 (High)'
    command_template = db.Column(db.Text, default="")     # parameterized tool command script
    tools = db.Column(db.Text, default="[]")      # JSON list
    references = db.Column(db.Text, default="[]") # JSON list


class EndpointVulnStatus(db.Model):
    __tablename__ = "endpoint_vuln_status"
    __table_args__ = (
        db.UniqueConstraint("endpoint_id", "vuln_id", name="uq_endpoint_vuln"),
    )

    id = db.Column(db.Integer, primary_key=True)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("endpoint.id"), nullable=False)
    vuln_id = db.Column(db.String(60), db.ForeignKey("vuln_check.id"), nullable=False)

    status = db.Column(db.String(20), default="untested")  # untested/pass/fail/na
    notes = db.Column(db.Text, default="")
    cvss = db.Column(db.String(20), default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # automated-scan metadata
    automated = db.Column(db.Boolean, default=False)
    last_scan_at = db.Column(db.DateTime, nullable=True)
    scan_evidence = db.Column(db.Text, default="")  # JSON blob of the last scan's evidence

    vuln = db.relationship("VulnCheck")


class ProjectVulnStatus(db.Model):
    """Stores the test finding for a checklist check on a project, including affected endpoints."""
    __tablename__ = "project_vuln_status"
    __table_args__ = (
        db.UniqueConstraint("project_id", "vuln_id", name="uq_project_vuln"),
    )

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    vuln_id = db.Column(db.String(60), db.ForeignKey("vuln_check.id"), nullable=False)

    status = db.Column(db.String(20), default="untested")
    notes = db.Column(db.Text, default="")
    cvss = db.Column(db.String(20), default="")
    custom_affected = db.Column(db.Text, default="[]")  # JSON list of custom URL/endpoint strings
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vuln = db.relationship("VulnCheck")
    affected_endpoints = db.relationship(
        "Endpoint", secondary=project_vuln_endpoints, backref=db.backref("affected_vuln_statuses", lazy="dynamic")
    )
