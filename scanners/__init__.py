"""
Automated scanner plugins for WebPT.

To add a new automated check:
  1. Create scanners/your_check.py
  2. Subclass BaseScanner, set .id / .name / .covers (VulnCheck ids from
     seed/phases.json this scanner can speak to), implement .scan()
  3. Decorate the class with @register

That's it -- no changes needed in app.py or templates. This file
auto-imports every module in the package at startup so the decorator runs.
See scanners/README.md for the full contract and a template to copy.
"""
import importlib
import pkgutil

from .base import BaseScanner, ScanFinding  # noqa: F401  (re-exported for scanner modules)
from .registry import SCANNERS, register, all_scanners, applicable_scanners, run_all  # noqa: F401

for _, module_name, _ in pkgutil.iter_modules(__path__):
    if module_name not in ("base", "registry"):
        importlib.import_module(f"{__name__}.{module_name}")
