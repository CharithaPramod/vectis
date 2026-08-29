"""
Registry that scanner plugins attach themselves to via @register.
app.py and the UI only ever talk to this module -- never to individual
scanner classes directly -- so new scanners "just show up" once they're
dropped into this package.
"""
SCANNERS = {}


def register(scanner_cls):
    """Class decorator: @register on a BaseScanner subclass instantiates it
    and adds it to the registry keyed by its .id."""
    instance = scanner_cls()
    SCANNERS[instance.id] = instance
    return scanner_cls


def all_scanners():
    return list(SCANNERS.values())


def applicable_scanners(endpoint):
    return [s for s in SCANNERS.values() if s.applies_to(endpoint)]


def run_all(endpoint):
    """Runs every scanner that applies to this endpoint and returns a flat
    list[ScanFinding]. A scanner raising is turned into a single 'error'
    finding rather than aborting the whole run."""
    findings = []
    for scanner in applicable_scanners(endpoint):
        try:
            findings.extend(scanner.scan(endpoint))
        except Exception as e:  # defensive: one broken scanner shouldn't kill a bulk run
            for vuln_id in scanner.covers:
                findings.append(
                    _error_finding(vuln_id, f"{scanner.name} raised an unexpected error: {e}")
                )
    return findings


def _error_finding(vuln_id, message):
    from .base import ScanFinding
    return ScanFinding(vuln_id=vuln_id, status="error", summary=message, confidence="low")
