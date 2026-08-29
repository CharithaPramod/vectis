"""
Shared types for the automated scanner plugin system.

A "scanner" is anything that can look at an Endpoint and produce evidence
(and, where it's confident enough, a pass/fail verdict) for one or more
VulnCheck items from seed/phases.json. Scanners are intentionally decoupled
from the web layer -- they don't touch the database or Flask; app.py is
responsible for taking a scanner's findings and writing them onto the
relevant EndpointVulnStatus rows.

This is the seam meant for growth: today there's one scanner
(clickjacking/header analysis). Adding an active SQLi prober, a TLS/cipher
checker, a JWT-alg-confusion checker, etc. later just means adding another
file in this package -- see scanners/README.md.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ScanFinding:
    vuln_id: str
    # 'pass' | 'fail' -> a real verdict the scanner is prepared to assert.
    # 'info'          -> evidence worth recording, but not a full test of
    #                     this check on its own (don't auto-set status).
    # 'error'         -> the scan itself failed (network error, etc).
    status: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    # 'high' confidence + pass/fail status is the only combination that is
    # allowed to auto-set a check's status (and only when the tester hasn't
    # already recorded a manual verdict). Everything else is logged as
    # supporting evidence for the tester to review.
    confidence: str = "low"


class BaseScanner:
    id: str = "base"
    name: str = "Base Scanner"
    description: str = ""
    # VulnCheck ids (from seed/phases.json) this scanner can produce
    # findings for. Used so the UI can say "N automated scanners available
    # for this endpoint" without running anything.
    covers = []

    def applies_to(self, endpoint) -> bool:
        """Cheap check: is it even worth attempting this scan on this endpoint?"""
        return bool(endpoint.url)

    def scan(self, endpoint):
        """Returns a list[ScanFinding]. Must not raise -- catch and return
        an 'error' finding instead, so one bad scanner can't break a bulk run."""
        raise NotImplementedError
