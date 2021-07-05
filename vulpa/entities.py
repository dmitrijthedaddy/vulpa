"""
entities.py

Provides dataclasses that represent entities from RedCheck reports
"""

from dataclasses import dataclass
from typing import Dict, List, AnyStr

@dataclass
class ScanTarget:
    inner_id: str
    address: str
    name: str
    description: str
    cpe: str

@dataclass
class VulnerabilityDefinition:
    inner_id: str
    title: str
    cpe: str
    description: str
    severity: str
    remediation: str
    references: Dict[AnyStr, AnyStr]
    targets: List[ScanTarget]
    fixed: bool