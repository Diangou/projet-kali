# vuln_scanner/utils/models.py
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Vulnerability:
    tool: str
    id: Optional[str]
    title: str
    description: Optional[str]
    severity: str
    target: Optional[str]
    location: Optional[str]
    cve: Optional[str]
    cvss: Optional[float]
    recommendation: Optional[str]
    references: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
