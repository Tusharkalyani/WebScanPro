import secrets
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from webscanpro.modules.base import BaseSecurityModule, FindingData

class XSSModule(BaseSecurityModule):
    module_id = "xss"
    name = "Harmless Reflected Input & Output Encoding Analyzer (XSS)"
    description = "Detects unescaped input reflection and evaluates HTML/attribute/DOM encoding using benign canary markers."
    owasp_category = "A03:2021-Injection"
    default_cwe = "CWE-79"

    # Non-HTML content types where raw HTML tags do not execute in browser DOM
    NON_HTML_CONTENT_TYPES = [
        "application/json",
        "text/plain",
        "application/javascript",
        "text/javascript",
        "application/xml",
        "text/xml",
        "application/pdf",
        "image/"
    ]

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        findings: List[FindingData] = []
        self.logger("INFO", "Running Reflected Input & Output Encoding Analyzer (XSS)...")

        tested_params = set()

        for res in crawled_resources:
            # 1. Test Query Parameters on GET requests
            parsed = urlparse(res.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)

            for param_name in qs.keys():
                param_key = f"{res.path}:GET:{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                self._test_param_xss(
                    endpoint=res.url,
                    method="GET",
                    param_name=param_name,
                    all_params=qs,
                    findings=findings
                )

            # 2. Test Form Inputs (GET & POST)
            for form in res.forms:
                action_url = form.get("action", res.url)
                form_method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])

                base_data = {inp["name"]: inp.get("default_value", "test") for inp in inputs if inp.get("name")}
                for inp in inputs:
                    param_name = inp.get("name")
                    if not param_name or inp.get("type") in ("submit", "button", "reset"):
                        continue

                    param_key = f"{action_url}:{form_method}:{param_name}"
                    if param_key in tested_params:
                        continue
                    tested_params.add(param_key)

                    self._test_form_xss(
                        endpoint=action_url,
                        method=form_method,
                        param_name=param_name,
                        all_data=base_data,
                        findings=findings
                    )

        self.logger("INFO", f"Reflected XSS audit completed. Discovered {len(findings)} findings.")
        return findings

    def _is_html_content_type(self, resp) -> bool:
        if not hasattr(resp, "headers") or not resp.headers:
            return True  # Default to permissive if headers dict not present (e.g. basic mock)
        content_type = resp.headers.get("Content-Type", "").lower()
        if not content_type:
            return True  # Browser MIME-sniffing may treat missing Content-Type as HTML
        return not any(non_html in content_type for non_html in self.NON_HTML_CONTENT_TYPES)

    def _test_param_xss(self, endpoint: str, method: str, param_name: str, all_params: dict, findings: list):
        token = secrets.token_hex(4)
        # Harmless probe containing HTML tag markers without executable scripts
        canary_tag = f"wsp{token}<wsptag>"

        parsed = urlparse(endpoint)
        test_qs = {k: v[0] if isinstance(v, list) else v for k, v in all_params.items()}
        test_qs[param_name] = canary_tag

        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode(test_qs),
            ""
        ))

        try:
            resp = self.session.get(test_url, timeout=5, verify=False)
            if not resp.text:
                return

            # Check if response is intended to render HTML in the browser
            if not self._is_html_content_type(resp):
                # Non-HTML API responses (e.g. JSON) do not cause XSS in the browser DOM
                return

            self._analyze_reflection(
                resp_text=resp.text,
                canary_tag=canary_tag,
                raw_tag="<wsptag>",
                encoded_tag="&lt;wsptag&gt;",
                endpoint=test_url,
                param_name=param_name,
                method="GET",
                findings=findings
            )
        except Exception as e:
            self.logger("WARNING", f"Error in XSS param test {endpoint}: {str(e)}")

    def _test_form_xss(self, endpoint: str, method: str, param_name: str, all_data: dict, findings: list):
        token = secrets.token_hex(4)
        canary_tag = f"wsp{token}<wsptag>"

        test_data = dict(all_data)
        test_data[param_name] = canary_tag

        try:
            if method == "POST":
                resp = self.session.post(endpoint, data=test_data, timeout=5, verify=False)
            else:
                resp = self.session.get(endpoint, params=test_data, timeout=5, verify=False)

            if not resp.text:
                return

            if not self._is_html_content_type(resp):
                return

            self._analyze_reflection(
                resp_text=resp.text,
                canary_tag=canary_tag,
                raw_tag="<wsptag>",
                encoded_tag="&lt;wsptag&gt;",
                endpoint=endpoint,
                param_name=param_name,
                method=method,
                test_data=test_data if method == "POST" else None,
                findings=findings
            )
        except Exception as e:
            self.logger("WARNING", f"Error in XSS form test {endpoint}: {str(e)}")

    def _analyze_reflection(self, resp_text: str, canary_tag: str, raw_tag: str,
                            encoded_tag: str, endpoint: str, param_name: str,
                            method: str, findings: list, test_data: Optional[dict] = None):
        # 1. Check if raw unescaped tag is reflected in response
        if canary_tag in resp_text:
            # Context evaluation via HTML parser
            soup = BeautifulSoup(resp_text, "html.parser")
            in_script = False
            for s in soup.find_all("script"):
                if canary_tag in (s.string or "") or canary_tag in s.text:
                    in_script = True
                    break

            in_attribute = False
            for tag in soup.find_all():
                for attr_val in tag.attrs.values():
                    if isinstance(attr_val, str) and canary_tag in attr_val:
                        in_attribute = True
                        break
                    elif isinstance(attr_val, list) and any(canary_tag in str(item) for item in attr_val):
                        in_attribute = True
                        break
                if in_attribute:
                    break

            # Extract snippet of surrounding context
            idx = resp_text.find(canary_tag)
            start = max(0, idx - 80)
            end = min(len(resp_text), idx + len(canary_tag) + 80)
            snippet = resp_text[start:end].replace("\n", " ").strip()

            if method == "POST" and test_data:
                body_str = "&".join([f"{k}={v}" for k, v in test_data.items()])
                curl_cmd = f"curl -s -i -X POST '{endpoint}' -d '{body_str}'"
            else:
                curl_cmd = f"curl -s -i -X GET '{endpoint}'"

            if in_script:
                findings.append(FindingData(
                    vuln_type="Unescaped Input Reflected Inside Script Context (High Risk XSS)",
                    category=self.owasp_category,
                    cwe_id=self.default_cwe,
                    cvss_score=8.1,
                    severity="HIGH",
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=endpoint,
                    parameter=param_name,
                    http_method=method,
                    evidence=(
                        f"Reflected Canary Marker: '{canary_tag}'\n"
                        f"Target Parameter: '{param_name}' via {method}\n"
                        f"Reflection Context: Inside inline <script> block\n"
                        f"Raw HTML Tag Present: '{raw_tag}' was NOT converted to '{encoded_tag}'\n\n"
                        f"Response Excerpt:\n...{snippet}...\n\n"
                        f"Reproduction Command:\n{curl_cmd}"
                    ),
                    explanation=(
                        f"User input submitted via parameter '{param_name}' is reflected raw inside an inline JavaScript "
                        f"execution block. Without JavaScript-aware context serialization (e.g. JSON encoding), attackers "
                        f"can break out of JavaScript variable literals and execute arbitrary code."
                    ),
                    remediation=(
                        "1. Use context-aware encoding. For JavaScript contexts, use JSON serialization (e.g. json.dumps()) "
                        "instead of direct string interpolation.\n"
                        "2. Implement a strict Content-Security-Policy (CSP) that prohibits inline scripts ('unsafe-inline')."
                    ),
                    manual_verification_steps=(
                        f"1. Run: {curl_cmd}\n"
                        f"2. Inspect the HTML output and verify that '{canary_tag}' appears inside an inline <script> tag."
                    )
                ))
            elif in_attribute:
                findings.append(FindingData(
                    vuln_type="Unescaped Input Reflected in HTML Attribute Context (Reflected XSS Indicator)",
                    category=self.owasp_category,
                    cwe_id=self.default_cwe,
                    cvss_score=7.1,
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=endpoint,
                    parameter=param_name,
                    http_method=method,
                    evidence=(
                        f"Reflected Canary Marker: '{canary_tag}'\n"
                        f"Target Parameter: '{param_name}' via {method}\n"
                        f"Reflection Context: Inside HTML element attribute\n\n"
                        f"Response Excerpt:\n...{snippet}...\n\n"
                        f"Reproduction Command:\n{curl_cmd}"
                    ),
                    explanation=(
                        f"User input submitted via parameter '{param_name}' is reflected inside an HTML tag attribute "
                        f"without attribute-value escaping. An attacker could inject quotes to break out of the attribute."
                    ),
                    remediation="Apply HTML attribute encoding (&quot;, &#x27;) to all dynamic values placed in tag attributes.",
                    manual_verification_steps=f"Execute: {curl_cmd} and inspect tag attribute values."
                ))
            else:
                # Body / Element context
                findings.append(FindingData(
                    vuln_type="Unescaped Reflected Input / Missing HTML Entity Encoding (Reflected XSS Indicator)",
                    category=self.owasp_category,
                    cwe_id=self.default_cwe,
                    cvss_score=7.3,
                    severity="HIGH",
                    confidence="CONFIRMED",
                    status="Confirmed Finding",
                    endpoint=endpoint,
                    parameter=param_name,
                    http_method=method,
                    evidence=(
                        f"Reflected Marker: '{canary_tag}'\n"
                        f"Raw HTML Tag Present: '{raw_tag}' was NOT converted to '{encoded_tag}'\n"
                        f"Target Parameter: '{param_name}' via {method}\n"
                        f"Reflection Context: HTML Document Body\n\n"
                        f"Response Excerpt:\n...{snippet}...\n\n"
                        f"Reproduction Command:\n{curl_cmd}"
                    ),
                    explanation=(
                        f"User input supplied to parameter '{param_name}' is reflected in the HTTP response HTML body "
                        f"without entity encoding. The opening and closing angle brackets were rendered verbatim as raw markup tags."
                    ),
                    remediation=(
                        "1. Contextually encode all untrusted output before inserting it into HTML documents (e.g., convert "
                        "< to &lt;, > to &gt;, \" to &quot;, ' to &#x27;).\n"
                        "2. Utilize auto-escaping web template engines (e.g., Jinja2, React, Angular) and ensure safe filters are not bypassed."
                    ),
                    manual_verification_steps=(
                        f"1. Run: {curl_cmd}\n"
                        f"2. Confirm that the raw angle brackets appear unescaped in the HTML body."
                    )
                ))
        elif encoded_tag in resp_text:
            self.logger("INFO", f"Parameter '{param_name}' properly encodes HTML output: '{encoded_tag}' found.")
