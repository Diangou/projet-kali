# vuln_scanner/__init__.py
from .scanner import VulnerabilityScanner
from .trivy_tool import TrivyTool

from vuln_scanner.nmap_tool import (
    NmapScanResult,
    NmapTool,
    save_nmap_result,
)
__all__ = ['VulnerabilityScanner', 'TrivyTool']
