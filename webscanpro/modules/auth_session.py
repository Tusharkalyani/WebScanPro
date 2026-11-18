from typing import List, Optional
from urllib.parse import urlparse, urljoin
import requests
from webscanpro.modules.base import BaseSecurityModule, FindingData

class AuthSessionModule(BaseSecurityModule):
    module_id = "auth_session"
    name = "Authentication & Session Management Auditor"
    description = "Evaluates HTTPS enforcement, cleartext credential transport, session token entropy, and logout invalidation."
    owasp_category = "A07:2021-Identification and Authentication Failures"
    default_cwe = "CWE-384"

    LOGOUT_CANDIDATE_PATHS = [
        "/logout", "/api/logout", "/auth/logout", "/user/logout", "/signout"
    ]

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        findings: List[FindingData] = []
        self.logger("INFO", "Running Authentication & Session Management Auditor...")

        auth_cfg = scan_config.get("auth", {})
        session_cookie_name = auth_cfg.get("cookie_name", "session")
        session_cookie_val = auth_cfg.get("session_token", "")
        test_logout_url = auth_cfg.get("logout_url", "")
        test_protected_url = auth_cfg.get("protected_url", "")

        parsed_target = urlparse(target_base_url)

        # 1. Audit Plain HTTP Authentication / Transmission (External Non-Loopback Targets)
        is_loopback = parsed_target.hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
        if parsed_target.scheme == "http" and not is_loopback:
            findings.append(FindingData(
                vuln_type="Insecure Transmission of Authentication over Unencrypted HTTP",
                category=self.owasp_category,
                cwe_id="CWE-319",
                cvss_score=7.4,
                severity="HIGH",
                confidence="CONFIRMED",
                status="Confirmed Finding",
                endpoint=target_base_url,
                parameter="N/A",
                http_method="ALL",
                evidence=(
                    f"Target URL: {target_base_url}\n"
                    f"Host: {parsed_target.netloc} (External Network Target)\n"
                    f"Protocol: Cleartext HTTP (TLS Not Enforced)\n\n"
                    f"Reproduction Command:\ncurl -sI '{target_base_url}'"
                ),
                explanation=(
                    "The application allows authentication or session interaction over cleartext HTTP. "
                    "All credentials, session tokens, and personal data can be intercepted by network adversaries (MITM)."
                ),
                remediation="Enforce TLS (HTTPS) across all endpoints with mandatory HSTS (Strict-Transport-Security).",
                manual_verification_steps="Attempt to navigate to http:// and check if automatic redirect to https:// occurs."
            ))

        # 2. Check for Password / Login Forms on Crawled Pages
        for res in crawled_resources:
            for form in res.forms:
                inputs = form.get("inputs", [])
                has_password_field = any(i.get("type") == "password" for i in inputs)
                if has_password_field:
                    action_url = form.get("action", res.url)
                    form_parsed = urlparse(action_url)
                    form_is_loopback = form_parsed.hostname in ("localhost", "127.0.0.1", "::1") if form_parsed.hostname else is_loopback

                    # If form submits over HTTP to non-localhost
                    if form_parsed.scheme == "http" and not form_is_loopback:
                        findings.append(FindingData(
                            vuln_type="Password Form Submits via Insecure HTTP",
                            category=self.owasp_category,
                            cwe_id="CWE-319",
                            cvss_score=8.1,
                            severity="HIGH",
                            confidence="CONFIRMED",
                            status="Confirmed Finding",
                            endpoint=action_url,
                            parameter="password",
                            http_method=form.get("method", "POST"),
                            evidence=(
                                f"Page URL: {res.url}\n"
                                f"Login Form Action: {action_url}\n"
                                f"Method: {form.get('method', 'POST')}\n"
                                f"Vulnerability: Password field submitted over cleartext HTTP protocol."
                            ),
                            explanation="User credentials entered into this form are transmitted in cleartext over the network.",
                            remediation="Ensure the form action points to an https:// endpoint.",
                            manual_verification_steps=f"Inspect form action in {res.url} source code."
                        ))

        # 3. Session Token Entropy & Predictability Evaluation
        cookies_to_audit = {}
        if session_cookie_val:
            cookies_to_audit[session_cookie_name] = session_cookie_val
        for c in self.session.cookies:
            cookies_to_audit[c.name] = c.value

        for name, val in cookies_to_audit.items():
            if any(term in name.lower() for term in ("sess", "token", "auth", "jwt", "id")):
                # Check for weak or trivial numeric session IDs
                if val.isdigit() and len(val) < 10:
                    findings.append(FindingData(
                        vuln_type="Predictable / Weak Numeric Session Identifier",
                        category=self.owasp_category,
                        cwe_id="CWE-330",
                        cvss_score=8.6,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=name,
                        http_method="COOKIE",
                        evidence=(
                            f"Cookie Parameter: '{name}'\n"
                            f"Observed Value: '{val}' (Numeric, {len(val)} digits)\n"
                            f"Entropy Assessment: Insufficient entropy (< 32 bits)."
                        ),
                        explanation=(
                            f"The session identifier cookie '{name}' contains a short or sequential numeric value. "
                            f"Attackers can easily enumerate or predict other users' valid session IDs."
                        ),
                        remediation="Generate session identifiers using a cryptographically secure pseudorandom number generator (CSPRNG) with at least 128 bits of entropy.",
                        manual_verification_steps=f"Inspect cookie '{name}' in multiple fresh browser sessions to see if it increments predictably."
                    ))

        # 4. Controlled Logout Invalidation Testing
        # If test account session & protected URL are configured
        if session_cookie_val and test_protected_url:
            self._test_logout_invalidation(
                target_base_url=target_base_url,
                session_cookie_name=session_cookie_name,
                session_cookie_val=session_cookie_val,
                protected_url=test_protected_url,
                logout_url=test_logout_url,
                findings=findings
            )

        self.logger("INFO", f"Authentication & Session audit finished. Discovered {len(findings)} findings.")
        return findings

    def _test_logout_invalidation(self, target_base_url: str, session_cookie_name: str,
                                 session_cookie_val: str, protected_url: str,
                                 logout_url: str, findings: list):
        try:
            test_session = requests.Session()
            test_session.cookies.set(session_cookie_name, session_cookie_val)

            # Step 1: Verify authenticated access works
            resp_pre = test_session.get(protected_url, timeout=5, verify=False)
            if resp_pre.status_code not in (200, 201):
                self.logger("INFO", f"Logout test skipped: Protected URL returned {resp_pre.status_code} with test token.")
                return

            # Step 2: Trigger logout
            target_logout = logout_url or urljoin(target_base_url, "/logout")
            test_session.get(target_logout, timeout=5, verify=False)

            # Step 3: Re-verify if old token is still accepted in a fresh session
            verify_session = requests.Session()
            verify_session.cookies.set(session_cookie_name, session_cookie_val)
            resp_post = verify_session.get(protected_url, timeout=5, verify=False)

            # Evidence reproduction commands
            curl_step1 = f"curl -s -o /dev/null -w '%{{http_code}}' -b '{session_cookie_name}={session_cookie_val}' '{protected_url}'"
            curl_step2 = f"curl -s -b '{session_cookie_name}={session_cookie_val}' '{target_logout}'"
            curl_step3 = f"curl -s -o /dev/null -w '%{{http_code}}' -b '{session_cookie_name}={session_cookie_val}' '{protected_url}'"

            if resp_post.status_code == 200 and len(resp_post.text) == len(resp_pre.text):
                findings.append(FindingData(
                    vuln_type="Improper Session Invalidation on Logout (Session Fixation / Replay)",
                    category=self.owasp_category,
                    cwe_id="CWE-613",
                    cvss_score=7.1,
                    severity="HIGH",
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=protected_url,
                    parameter=session_cookie_name,
                    http_method="GET",
                    evidence=(
                        f"Step 1: Authenticated Access to Protected URL:\n"
                        f"  GET {protected_url} -> HTTP {resp_pre.status_code} ({len(resp_pre.text)} bytes)\n"
                        f"  Command: {curl_step1}\n\n"
                        f"Step 2: Invoked Logout Action:\n"
                        f"  GET {target_logout}\n"
                        f"  Command: {curl_step2}\n\n"
                        f"Step 3: Replayed Token from Fresh Client Session:\n"
                        f"  GET {protected_url} -> HTTP {resp_post.status_code} ({len(resp_post.text)} bytes)\n"
                        f"  Command: {curl_step3}\n\n"
                        f"Outcome: Server accepted invalidated session token without re-authentication."
                    ),
                    explanation=(
                        "Invoking the logout endpoint does not invalidate the session on the server. "
                        "The previous session token remains active and can be replayed to access protected user resources."
                    ),
                    remediation="Explicitly destroy the session record on the server (or revoke the token in a revocation cache) upon user logout.",
                    manual_verification_steps=(
                        f"1. Check pre-logout access: {curl_step1}\n"
                        f"2. Trigger logout: {curl_step2}\n"
                        f"3. Verify post-logout rejection: {curl_step3} (Should return 401 or 302 to login, but returns 200)"
                    )
                ))
            else:
                self.logger("INFO", f"Logout successfully invalidated session: Post-logout status was {resp_post.status_code}")
        except Exception as e:
            self.logger("WARNING", f"Error in logout invalidation testing: {str(e)}")
