# vuln_scanner/utils/severity.py
SEVERITY_MAPPING = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "ERROR": "high",
    "MEDIUM": "medium",
    "WARNING": "medium",
    "LOW": "low",
    "INFO": "info",
    "INFORMATIONAL": "info",
    "UNKNOWN": "unknown",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def normalize(severity):
    if severity is None:
        return "unknown"

    return SEVERITY_MAPPING.get(
        str(severity).upper(),
        str(severity).lower(),
    )
