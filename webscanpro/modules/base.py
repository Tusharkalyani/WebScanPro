from dataclasses import dataclass
from typing import Optional, List
import requests

@dataclass
class FindingData:
    vuln_type: str
    category: str
    cwe_id: str
    cvss_score: float
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str      # CONFIRMED, LIKELY, SUSPECTED
    status: str          # Confirmed Finding, Potential Finding, Passed, Error, Not Tested
    endpoint: str
    parameter: str
    http_method: str
    evidence: str
    explanation: str
    remediation: str
    manual_verification_steps: Optional[str] = None


class BaseSecurityModule:
    """
    Abstract base class for all WebScanPro security assessment modules.
    Enforces consistent detection metadata, OWASP mappings, and safe heuristics.
    """
    module_id: str = "base"
    name: str = "Base Security Module"
    description: str = "Abstract base module"
    owasp_category: str = "A00:2021-General"
    default_cwe: str = "CWE-Other"

    def __init__(self, session: Optional[requests.Session] = None, logger=None):
        self.session = session or requests.Session()
        self.logger = logger or (lambda level, msg: None)

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        """
        Executes module testing logic against target and crawled resources.
        Returns list of FindingData objects.
        """
        raise NotImplementedError("Subclasses must implement the run() method.")
