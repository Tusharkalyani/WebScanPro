from typing import List, Dict, Set
from urllib.parse import urlparse
from webscanpro.modules.base import BaseSecurityModule, FindingData

class HeadersCookiesModule(BaseSecurityModule):
    module_id = "headers_cookies"
    name = "Security Headers & Cookie Security Analyzer"
    description = "Audits HTTP response security headers and cookie security attributes (HttpOnly, Secure, SameSite)."
    owasp_category = "A05:2021-Security Misconfiguration"
    default_cwe = "CWE-16"

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "cvss": 5.4,
            "explanation": "Content-Security-Policy (CSP) is missing. CSP helps detect and mitigate Cross-Site Scripting (XSS), clickjacking, and data injection attacks by restricting origins from which scripts, images, and styles can be loaded.",
            "remediation": "Configure a Content-Security-Policy header, e.g.: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
            "manual_verify": "Inspect response headers in DevTools Network tab or run: curl -sI '{url}' | grep -i 'Content-Security-Policy'"
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "cwe": "CWE-16",
            "cvss": 3.7,
            "explanation": "X-Content-Type-Options is missing or not set to 'nosniff'. This allows older browsers to perform MIME-type sniffing, which can transform non-executable MIME types into executable code.",
            "remediation": "Add the header 'X-Content-Type-Options: nosniff' across all server responses.",
            "manual_verify": "Run: curl -sI '{url}' | grep -i 'X-Content-Type-Options'"
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "cvss": 4.3,
            "explanation": "X-Frame-Options (or CSP frame-ancestors directive) is missing. The page can be embedded within an <iframe> on external domains, exposing users to clickjacking / UI redressing attacks.",
            "remediation": "Set 'X-Frame-Options: SAMEORIGIN' or 'DENY', or implement CSP 'frame-ancestors 'self''.",
            "manual_verify": "Run: curl -sI '{url}' | grep -i 'X-Frame-Options'"
        },
        "Strict-Transport-Security": {
            "severity": "LOW",
            "cwe": "CWE-319",
            "cvss": 3.1,
            "explanation": "HTTP Strict Transport Security (HSTS) header is missing on an HTTPS service. HSTS instructs browsers to exclusively interact with the site over HTTPS, preventing SSL-stripping and cookie interception attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
            "manual_verify": "Run: curl -sI '{url}' | grep -i 'Strict-Transport-Security'"
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "cwe": "CWE-116",
            "cvss": 3.1,
            "explanation": "The Referrer-Policy header is missing. Browsers may send full URL paths (including query parameters with tokens or sensitive IDs) in the Referer header to third-party domains.",
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "manual_verify": "Run: curl -sI '{url}' | grep -i 'Referrer-Policy'"
        },
        "Permissions-Policy": {
            "severity": "INFO",
            "cwe": "CWE-16",
            "cvss": 2.0,
            "explanation": "The Permissions-Policy header is missing. Permissions-Policy allows site operators to restrict browser features such as camera, microphone, geolocation, and payment APIs.",
            "remediation": "Configure Permissions-Policy, e.g.: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "manual_verify": "Run: curl -sI '{url}' | grep -i 'Permissions-Policy'"
        }
    }

    INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        findings: List[FindingData] = []
        self.logger("INFO", "Running Security Headers & Cookie Security Analyzer...")

        is_https = target_base_url.lower().startswith("https://")
        
        # Gather all crawled resources (sample up to 10 unique paths)
        sample_resources = crawled_resources[:10] if crawled_resources else []

        # If crawled_resources is empty, fetch target_base_url directly
        if not sample_resources:
            try:
                resp = self.session.get(target_base_url, timeout=5, verify=False)
                headers_dict = dict(resp.headers)
            except Exception as e:
                self.logger("WARNING", f"Could not fetch target base URL {target_base_url}: {e}")
                headers_dict = {}
        else:
            headers_dict = sample_resources[0].headers

        # ---------------------------------------------------------
        # 1. Missing Security Headers (Deduplicated per target origin)
        # ---------------------------------------------------------
        # Track which headers are missing across sampled endpoints
        missing_header_endpoints: Dict[str, List[str]] = {h: [] for h in self.RECOMMENDED_HEADERS}
        present_headers: Dict[str, str] = {}

        # Collect headers from base response and sample resources
        endpoints_to_check = sample_resources if sample_resources else [{"url": target_base_url, "headers": headers_dict, "method": "GET"}]

        for res in endpoints_to_check:
            res_url = res.url if hasattr(res, "url") else res.get("url", target_base_url)
            res_hdrs = res.headers if hasattr(res, "headers") else res.get("headers", {})

            for header_name in self.RECOMMENDED_HEADERS.keys():
                if header_name == "Strict-Transport-Security" and not is_https:
                    continue

                val = next((v for k, v in res_hdrs.items() if k.lower() == header_name.lower()), None)
                if val:
                    present_headers[header_name] = val
                else:
                    if res_url not in missing_header_endpoints[header_name]:
                        missing_header_endpoints[header_name].append(res_url)

        # Generate findings for missing headers (reported once per missing header)
        for header_name, affected_urls in missing_header_endpoints.items():
            if header_name == "Strict-Transport-Security" and not is_https:
                continue

            # If the header was missing across all or primary checked endpoints
            if affected_urls:
                meta = self.RECOMMENDED_HEADERS[header_name]
                primary_url = affected_urls[0]
                sample_hdrs_str = "\n".join([f"{k}: {v}" for k, v in list(headers_dict.items())[:10]])

                findings.append(FindingData(
                    vuln_type=f"Missing Security Header: {header_name}",
                    category=self.owasp_category,
                    cwe_id=meta["cwe"],
                    cvss_score=meta["cvss"],
                    severity=meta["severity"],
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=primary_url,
                    parameter=header_name,
                    http_method="GET",
                    evidence=(
                        f"Target Origin: {target_base_url}\n"
                        f"Missing Header: {header_name}\n"
                        f"Sampled Endpoints Missing Header ({len(affected_urls)}):\n" +
                        "\n".join([f"  - {u}" for u in affected_urls[:5]]) + "\n\n"
                        f"Observed Headers for {primary_url}:\n{sample_hdrs_str}\n\n"
                        f"Reproduction Command:\ncurl -sI '{primary_url}' | grep -i '^{header_name}'"
                    ),
                    explanation=meta["explanation"],
                    remediation=meta["remediation"],
                    manual_verification_steps=meta["manual_verify"].format(url=primary_url)
                ))

        # ---------------------------------------------------------
        # 2. Technology Fingerprints & Information Disclosure (Deduplicated)
        # ---------------------------------------------------------
        # Map: (info_hdr, banner_val) -> list of URLs where observed
        detected_banners: Dict[str, Dict[str, List[str]]] = {}
        for res in endpoints_to_check:
            res_url = res.url if hasattr(res, "url") else res.get("url", target_base_url)
            res_hdrs = res.headers if hasattr(res, "headers") else res.get("headers", {})

            for info_hdr in self.INFO_LEAK_HEADERS:
                val = next((v for k, v in res_hdrs.items() if k.lower() == info_hdr.lower()), None)
                if val and any(char.isdigit() for char in val):
                    if info_hdr not in detected_banners:
                        detected_banners[info_hdr] = {}
                    if val not in detected_banners[info_hdr]:
                        detected_banners[info_hdr][val] = []
                    if res_url not in detected_banners[info_hdr][val]:
                        detected_banners[info_hdr][val].append(res_url)

        for info_hdr, val_map in detected_banners.items():
            for val, affected_urls in val_map.items():
                primary_url = affected_urls[0]
                findings.append(FindingData(
                    vuln_type="Server Technology Version Disclosure",
                    category=self.owasp_category,
                    cwe_id="CWE-200",
                    cvss_score=2.6,
                    severity="LOW",
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=primary_url,
                    parameter=info_hdr,
                    http_method="GET",
                    evidence=(
                        f"Disclosed Header: {info_hdr}: {val}\n"
                        f"Primary Endpoint: {primary_url}\n"
                        f"Observed on Endpoints ({len(affected_urls)}):\n" +
                        "\n".join([f"  - {u}" for u in affected_urls[:5]]) + "\n\n"
                        f"Reproduction Command:\ncurl -sI '{primary_url}' | grep -i '^{info_hdr}'"
                    ),
                    explanation=f"The server exposes granular software version information via the '{info_hdr}' header ({val}). Attackers use version banners to identify known CVEs.",
                    remediation=f"Configure the web server or reverse proxy to suppress or generalize the '{info_hdr}' banner.",
                    manual_verification_steps=f"Execute: curl -sI '{primary_url}' | grep -i '^{info_hdr}'"
                ))

        # ---------------------------------------------------------
        # 3. Cookie Security Attributes Audit (HttpOnly, Secure, SameSite)
        # ---------------------------------------------------------
        checked_cookies: Set[str] = set()

        # Collect raw Set-Cookie headers from initial probe and session
        try:
            resp = self.session.get(target_base_url, timeout=5, verify=False)
            set_cookie_headers = []
            if hasattr(resp, "raw") and hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
                set_cookie_headers.extend(resp.raw.headers.getlist("Set-Cookie"))
            elif "Set-Cookie" in resp.headers:
                set_cookie_headers.append(resp.headers["Set-Cookie"])

            # Also check session cookies
            for cookie in self.session.cookies:
                cookie_name = cookie.name
                if cookie_name in checked_cookies:
                    continue
                checked_cookies.add(cookie_name)

                # Cookie object flags
                has_httponly = bool(cookie._rest.get("httponly") or cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"))
                has_secure = bool(cookie.secure)
                # SameSite attribute check
                samesite = cookie._rest.get("samesite") or cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")

                if not has_httponly:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'HttpOnly' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-1004",
                        cvss_score=5.3,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=(
                            f"Cookie Name: {cookie_name}\n"
                            f"Target: {target_base_url}\n"
                            f"HttpOnly: False\n"
                            f"Reproduction: Inspect response headers: curl -sI '{target_base_url}' | grep -i 'Set-Cookie'"
                        ),
                        explanation=f"The cookie '{cookie_name}' was set without the 'HttpOnly' attribute. This permits client-side JavaScript to access the cookie value via document.cookie during an XSS attack.",
                        remediation=f"Set the HttpOnly flag when issuing cookies: Set-Cookie: {cookie_name}=<val>; HttpOnly; Path=/",
                        manual_verification_steps=f"Inspect Set-Cookie header via: curl -sI '{target_base_url}'"
                    ))

                if not has_secure and is_https:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'Secure' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-614",
                        cvss_score=4.8,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=(
                            f"Cookie Name: {cookie_name}\n"
                            f"Target: {target_base_url} (HTTPS)\n"
                            f"Secure: False\n"
                            f"Reproduction: curl -sI '{target_base_url}' | grep -i 'Set-Cookie'"
                        ),
                        explanation=f"The cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' attribute, allowing it to be transmitted over cleartext HTTP if a user is downgraded.",
                        remediation=f"Append the 'Secure' flag to all cookies set over HTTPS.",
                        manual_verification_steps=f"Verify cookie flags using browser storage inspector or curl -sI '{target_base_url}'."
                    ))

                if not samesite:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'SameSite' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-1275",
                        cvss_score=3.5,
                        severity="LOW",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=(
                            f"Cookie Name: {cookie_name}\n"
                            f"Target: {target_base_url}\n"
                            f"SameSite: Not set\n"
                            f"Reproduction: curl -sI '{target_base_url}' | grep -i 'Set-Cookie'"
                        ),
                        explanation=f"The cookie '{cookie_name}' lacks the 'SameSite' attribute, leaving the application susceptible to Cross-Site Request Forgery (CSRF).",
                        remediation=f"Add 'SameSite=Lax' or 'SameSite=Strict' to the cookie definition.",
                        manual_verification_steps="Check Set-Cookie header flags."
                    ))

            # Parse any raw Set-Cookie strings
            for raw_cookie in set_cookie_headers:
                parts = [p.strip() for p in raw_cookie.split(";")]
                cookie_name = parts[0].split("=")[0] if parts else "UnknownCookie"
                if cookie_name in checked_cookies:
                    continue
                checked_cookies.add(cookie_name)

                parts_lower = [p.lower() for p in parts]
                has_httponly = "httponly" in parts_lower
                has_secure = "secure" in parts_lower
                has_samesite = any("samesite" in p for p in parts_lower)

                if not has_httponly:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'HttpOnly' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-1004",
                        cvss_score=5.3,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=(
                            f"Set-Cookie Header: {raw_cookie}\n"
                            f"Reproduction Command:\ncurl -sI '{target_base_url}' | grep -i 'Set-Cookie'"
                        ),
                        explanation=f"The cookie '{cookie_name}' was set without the 'HttpOnly' attribute.",
                        remediation=f"Set the HttpOnly flag on cookie creation: Set-Cookie: {cookie_name}=<val>; HttpOnly; Path=/",
                        manual_verification_steps=f"Inspect Set-Cookie header in HTTP response for {target_base_url}."
                    ))

                if not has_secure and is_https:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'Secure' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-614",
                        cvss_score=4.8,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=f"Set-Cookie Header: {raw_cookie}",
                        explanation=f"The cookie '{cookie_name}' was transmitted over HTTPS but lacks the 'Secure' attribute.",
                        remediation="Append the 'Secure' flag to all cookies set over HTTPS.",
                        manual_verification_steps="Verify cookie flags using curl -sI."
                    ))

                if not has_samesite:
                    findings.append(FindingData(
                        vuln_type="Cookie Missing 'SameSite' Attribute",
                        category=self.owasp_category,
                        cwe_id="CWE-1275",
                        cvss_score=3.5,
                        severity="LOW",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=target_base_url,
                        parameter=cookie_name,
                        http_method="GET",
                        evidence=f"Set-Cookie Header: {raw_cookie}",
                        explanation=f"The cookie '{cookie_name}' lacks the 'SameSite' attribute.",
                        remediation="Add 'SameSite=Lax' or 'SameSite=Strict' to the cookie definition.",
                        manual_verification_steps="Check Set-Cookie header flags."
                    ))
        except Exception as e:
            self.logger("WARNING", f"Cookie analysis exception: {str(e)}")

        self.logger("INFO", f"Headers & Cookies audit complete. Generated {len(findings)} findings.")
        return findings
