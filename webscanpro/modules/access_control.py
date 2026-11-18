import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs
import requests
from webscanpro.modules.base import BaseSecurityModule, FindingData

class AccessControlModule(BaseSecurityModule):
    module_id = "access_control"
    name = "Access Control & IDOR Analyzer"
    description = "Controlled two-account differential authorization and unauthenticated object-level access verification."
    owasp_category = "A01:2021-Broken Access Control"
    default_cwe = "CWE-639"

    # Strictly sensitive user PII attributes (excludes public product fields like description, price)
    SENSITIVE_USER_ATTRIBUTES = [
        "email", "password", "password_hash", "credit_card", "ssn", "balance",
        "phone", "totpsecret", "private_key", "secret", "billing_address",
        "national_id", "auth_token", "api_key"
    ]

    # Explicit sensitive object paths
    SENSITIVE_OBJECT_PATTERN = re.compile(
        r"/(?:users|accounts|profiles|orders|invoices|documents|wallets|customers)/(\d+)",
        re.IGNORECASE
    )

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        findings: List[FindingData] = []
        self.logger("INFO", "Running Access Control & IDOR Analyzer...")

        auth_cfg = scan_config.get("auth", {})
        account_a = auth_cfg.get("account_a", {})  # e.g. {"token": "...", "resource_url": "..."}
        account_b = auth_cfg.get("account_b", {})  # e.g. {"token": "...", "resource_url": "..."}

        # 1. Controlled Two-Account Differential IDOR Test (if both test accounts are provided)
        if account_a.get("token") and account_b.get("token") and account_a.get("resource_url"):
            self._test_two_account_idor(account_a, account_b, findings)

        # 2. Heuristic Audit: Unauthenticated Object-Level Resource Access on Sensitive Entities
        tested_urls = set()
        for res in crawled_resources:
            url = res.url
            if url in tested_urls:
                continue
            tested_urls.add(url)

            # Check if URL matches a sensitive object path or has a private user object query parameter
            has_sensitive_obj = bool(self.SENSITIVE_OBJECT_PATTERN.search(url))
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            has_user_id_param = any(p.lower() in ("user_id", "account_id", "order_id", "profile_id") for p in qs.keys())

            if has_sensitive_obj or has_user_id_param:
                self._test_unauth_object_access(url, res, findings)

        self.logger("INFO", f"Access Control & IDOR audit completed. Discovered {len(findings)} findings.")
        return findings

    def _test_two_account_idor(self, account_a: dict, account_b: dict, findings: list):
        """
        Executes controlled cross-account testing between two authorized test accounts.
        """
        resource_a_url = account_a["resource_url"]
        header_name = account_a.get("header_name", "Authorization")
        
        session_a = requests.Session()
        session_a.headers.update({header_name: account_a["token"]})

        session_b = requests.Session()
        session_b.headers.update({header_name: account_b["token"]})

        try:
            # Baseline: Account A accesses its own resource
            resp_a = session_a.get(resource_a_url, timeout=5, verify=False)
            if resp_a.status_code not in (200, 201):
                self.logger("WARNING", f"IDOR test baseline failed: Account A returned status {resp_a.status_code}")
                return

            # Cross-account test: Account B attempts to access Account A's resource
            resp_b = session_b.get(resource_a_url, timeout=5, verify=False)

            # Check if Account B was granted access
            if resp_b.status_code == 200:
                body_a = resp_a.text.strip()
                body_b = resp_b.text.strip()

                if body_a == body_b or len(body_b) > 20:
                    curl_a = f"curl -s -H '{header_name}: {account_a['token']}' '{resource_a_url}'"
                    curl_b = f"curl -s -H '{header_name}: {account_b['token']}' '{resource_a_url}'"

                    findings.append(FindingData(
                        vuln_type="Broken Object Level Authorization (BOLA / Horizontal IDOR)",
                        category=self.owasp_category,
                        cwe_id="CWE-639",
                        cvss_score=8.8,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=resource_a_url,
                        parameter="object_identifier",
                        http_method="GET",
                        evidence=(
                            f"Resource Owner: Test Account A\n"
                            f"Attacking Identity: Test Account B (Auth: {header_name})\n"
                            f"Account A Baseline: HTTP {resp_a.status_code} ({len(body_a)} bytes)\n"
                            f"Account B Access: HTTP {resp_b.status_code} ({len(body_b)} bytes)\n\n"
                            f"Reproduction Commands:\n"
                            f"1. As Account A: {curl_a}\n"
                            f"2. As Account B: {curl_b}\n\n"
                            f"Response Snippet Disclosed to Account B:\n{body_b[:300]}"
                        ),
                        explanation=(
                            f"Test Account B was able to access Test Account A's private resource at {resource_a_url}. "
                            "The backend validated that the user was authenticated, but failed to verify object ownership "
                            "before returning the requested entity."
                        ),
                        remediation=(
                            "1. Implement strict object-level access control checks in application code or data access layers.\n"
                            "2. Validate that the authenticated subject (session user ID) matches the resource owner ID before querying or mutating the database.\n"
                            "3. Use indirect reference maps or non-sequential identifiers (e.g. UUIDv4)."
                        ),
                        manual_verification_steps=(
                            f"1. Run Account A command: {curl_a}\n"
                            f"2. Run Account B command: {curl_b}\n"
                            f"3. Verify that Account B receives Account A's private object data without HTTP 403 Forbidden."
                        )
                    ))
        except Exception as e:
            self.logger("WARNING", f"Error in two-account IDOR test: {str(e)}")

    def _test_unauth_object_access(self, url: str, res, findings: list):
        """
        Tests whether an object-level resource exposes private/sensitive state without authentication.
        """
        try:
            # Issue unauthenticated request
            resp = self.session.get(url, timeout=5, verify=False)
            content_type = resp.headers.get("Content-Type", "").lower()
            if resp.status_code == 200 and ("application/json" in content_type or "text/html" in content_type):
                text_lower = resp.text.lower()
                exposed_keys = [k for k in self.SENSITIVE_USER_ATTRIBUTES if k in text_lower]

                # Only flag if sensitive user PII is actually disclosed in the body
                if exposed_keys:
                    curl_cmd = f"curl -s -i '{url}'"
                    findings.append(FindingData(
                        vuln_type="Unauthenticated Object-Level Resource Access (Missing Access Control)",
                        category=self.owasp_category,
                        cwe_id="CWE-284",
                        cvss_score=7.5,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=url,
                        parameter="URL Path / Identifier",
                        http_method="GET",
                        evidence=(
                            f"Endpoint: GET {url}\n"
                            f"Unauthenticated Status: HTTP {resp.status_code}\n"
                            f"Sensitive Attributes Disclosed: {', '.join(exposed_keys)}\n\n"
                            f"Reproduction Command:\n{curl_cmd}\n\n"
                            f"Response Sample:\n{resp.text[:300]}"
                        ),
                        explanation=(
                            f"The endpoint at {url} returned HTTP 200 to an unauthenticated client "
                            f"and disclosed sensitive user attributes ({', '.join(exposed_keys)})."
                        ),
                        remediation="Require authentication and enforce access control policies on all sensitive object-level endpoints.",
                        manual_verification_steps=f"Execute: {curl_cmd} and confirm if private user records are returned without credentials."
                    ))
        except Exception as e:
            self.logger("WARNING", f"Error in unauth object access test on {url}: {str(e)}")
