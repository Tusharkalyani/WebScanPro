import re
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from webscanpro.modules.base import BaseSecurityModule, FindingData

class SQLInjectionModule(BaseSecurityModule):
    module_id = "sqli"
    name = "Safe SQL Injection Syntax & Differential Analyzer"
    description = "Non-destructive detection of unhandled SQL syntax errors and differential response anomalies."
    owasp_category = "A03:2021-Injection"
    default_cwe = "CWE-89"

    # Comprehensive database engine syntax error patterns
    DB_ERROR_PATTERNS = [
        # SQLite
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"SQLite/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"unrecognized token:",
        r"near\s+[\"'].*[\"']:\s+syntax\s+error",
        r"syntax error.*sqlite",
        
        # Node.js ORMs (Sequelize, TypeORM, Prisma)
        r"SequelizeDatabaseError",
        r"SequelizeForeignKeyConstraintError",
        r"TypeORMError",
        
        # MySQL / MariaDB
        r"You have an error in your SQL syntax",
        r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
        r"MySqlException",
        r"com\.mysql\.jdbc\.exceptions",
        r"mysqli?_fetch_",
        r"mysqli?_query",
        r"SQL syntax.*MySQL",
        
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"syntax error at or near",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"psycopg2\.(?:ProgrammingError|OperationalError|errors)",
        
        # Microsoft SQL Server
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"Unclosed quotation mark after the character string",
        r"Line \d+: Incorrect syntax near",
        r"System\.Data\.SqlClient\.SqlException",
        
        # Oracle
        r"ORA-[0-9]{5}",
        r"quoted string not properly terminated",
        
        # Standards / Generic
        r"SQLSTATE\[[0-9A-Z]{5}\]",
        r"org\.hibernate\.exception",
        r"django\.db\.utils\.OperationalError",
        r"django\.db\.utils\.ProgrammingError",
        r"ActiveRecord::StatementInvalid"
    ]

    # Non-destructive syntax probes (safe, low-impact test delimiters)
    SAFE_PROBES = [
        {"probe": "'", "balancer": "''", "desc": "Single-quote delimiter test"},
        {"probe": '"', "balancer": '""', "desc": "Double-quote delimiter test"},
        {"probe": "')", "balancer": "')--", "desc": "Parenthesis single-quote test"},
        {"probe": "'))", "balancer": "'))--", "desc": "Double-parenthesis single-quote test"},
    ]

    def _match_db_error(self, text: str) -> Optional[str]:
        if not text:
            return None
        for pattern in self.DB_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def run(self, target_base_url: str, crawled_resources: list, scan_config: dict) -> List[FindingData]:
        findings: List[FindingData] = []
        self.logger("INFO", "Running Safe SQL Injection Analyzer...")

        tested_params = set()

        for res in crawled_resources:
            # 1. Test Query Parameters on GET requests
            parsed = urlparse(res.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)

            for param_name, vals in qs.items():
                param_key = f"{res.path}:GET:{param_name}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                original_val = vals[0] if vals else "1"
                self._test_param_sqli(
                    endpoint=res.url,
                    base_path=res.path,
                    method="GET",
                    param_name=param_name,
                    orig_val=original_val,
                    all_params=qs,
                    findings=findings
                )

            # 2. Test Form Inputs (GET & POST)
            for form in res.forms:
                action_url = form.get("action", res.url)
                form_method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])

                # Build baseline payload
                base_data = {inp["name"]: inp.get("default_value", "test") for inp in inputs if inp.get("name")}
                for inp in inputs:
                    param_name = inp.get("name")
                    if not param_name or inp.get("type") in ("submit", "button", "reset"):
                        continue

                    param_key = f"{action_url}:{form_method}:{param_name}"
                    if param_key in tested_params:
                        continue
                    tested_params.add(param_key)

                    orig_val = base_data.get(param_name, "1")
                    self._test_form_sqli(
                        endpoint=action_url,
                        base_path=urlparse(action_url).path or "/",
                        method=form_method,
                        param_name=param_name,
                        orig_val=orig_val,
                        all_data=base_data,
                        findings=findings
                    )

        self.logger("INFO", f"SQL Injection scan completed. Discovered {len(findings)} findings.")
        return findings

    def _test_param_sqli(self, endpoint: str, base_path: str, method: str,
                         param_name: str, orig_val: str, all_params: dict, findings: list):
        parsed = urlparse(endpoint)
        try:
            # Send baseline request
            baseline_resp = self.session.get(endpoint, timeout=5, verify=False)
            baseline_err = self._match_db_error(baseline_resp.text)
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_resp.text or "")
            
            for probe_spec in self.SAFE_PROBES:
                probe_val = f"{orig_val}{probe_spec['probe']}"
                test_qs = {k: v[0] if isinstance(v, list) else v for k, v in all_params.items()}
                test_qs[param_name] = probe_val

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    urlencode(test_qs),
                    ""
                ))

                resp = self.session.get(test_url, timeout=5, verify=False)
                matched_err = self._match_db_error(resp.text)

                # Case A: Confirmed Error-Based SQL Injection
                if matched_err and not baseline_err:
                    evidence_curl = f"curl -s -i -X GET '{test_url}'"
                    # Extract surrounding error snippet
                    err_idx = resp.text.find(matched_err)
                    snippet_start = max(0, err_idx - 60)
                    snippet_end = min(len(resp.text), err_idx + len(matched_err) + 120)
                    context_snippet = resp.text[snippet_start:snippet_end].replace("\n", " ").strip()

                    findings.append(FindingData(
                        vuln_type="Unhandled SQL Syntax Error (Error-Based SQL Injection Indicator)",
                        category=self.owasp_category,
                        cwe_id=self.default_cwe,
                        cvss_score=8.5,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=endpoint,
                        parameter=param_name,
                        http_method="GET",
                        evidence=(
                            f"Target Endpoint: GET {endpoint}\n"
                            f"Tested Parameter: '{param_name}' with safe probe '{probe_spec['probe']}' ({probe_spec['desc']})\n"
                            f"Injected Test URL: {test_url}\n"
                            f"Database Error Signature Detected: '{matched_err}'\n"
                            f"Response Status: HTTP {resp.status_code}\n\n"
                            f"Matched Error Context:\n...{context_snippet}...\n\n"
                            f"Reproduction Command:\n{evidence_curl}"
                        ),
                        explanation=(
                            f"Injecting a single syntax test delimiter ('{probe_spec['probe']}') into parameter '{param_name}' "
                            f"elicited an unhandled database engine error ('{matched_err}'). This confirms that user input "
                            f"is directly concatenated into a dynamic SQL query without parameterization."
                        ),
                        remediation=(
                            "1. Use Parameterized Queries (Prepared Statements) for all database operations.\n"
                            "2. If using an ORM (e.g. SQLAlchemy, Sequelize, Django ORM), use model filtering rather than raw SQL interpolation.\n"
                            "3. Disable detailed database error messages and stack traces in production responses."
                        ),
                        manual_verification_steps=(
                            f"1. Run: {evidence_curl}\n"
                            f"2. Inspect the HTTP response body and verify that database error '{matched_err}' appears.\n"
                            f"3. Balance the query with a matching quote to confirm that the syntax error disappears."
                        )
                    ))
                    break  # Found confirmed finding for this parameter

                # Case B: Differential Server Failure with Neutral Control (Zero False Positives)
                elif resp.status_code == 500 and baseline_status == 200:
                    # Test a neutral control (e.g. orig_val + "0") to see if ANY change causes 500
                    neutral_val = f"{orig_val}0"
                    neutral_qs = dict(test_qs)
                    neutral_qs[param_name] = neutral_val
                    neutral_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(neutral_qs), ""))
                    neutral_resp = self.session.get(neutral_url, timeout=5, verify=False)

                    # Balanced probe
                    balanced_val = f"{orig_val}{probe_spec['balancer']}"
                    bal_qs = dict(test_qs)
                    bal_qs[param_name] = balanced_val
                    bal_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(bal_qs), ""))
                    bal_resp = self.session.get(bal_url, timeout=5, verify=False)

                    # Only flag if neutral input is normal (200) AND balanced recovers (200)
                    if neutral_resp.status_code == 200 and bal_resp.status_code == 200:
                        evidence_curl = f"curl -s -i -X GET '{test_url}'"
                        findings.append(FindingData(
                            vuln_type="Differential Syntax Anomaly (Potential Blind SQL Injection)",
                            category=self.owasp_category,
                            cwe_id=self.default_cwe,
                            cvss_score=6.5,
                            severity="MEDIUM",
                            confidence="LIKELY",
                            status="Potential Finding",
                            endpoint=endpoint,
                            parameter=param_name,
                            http_method="GET",
                            evidence=(
                                f"Baseline Request ({orig_val}): Status {baseline_status} ({baseline_len} bytes)\n"
                                f"Neutral Input Probe ({neutral_val}): Status {neutral_resp.status_code} (Valid Normal)\n"
                                f"Syntax Delimiter Probe ({probe_val}): Status {resp.status_code} (Server Error)\n"
                                f"Balanced Delimiter Probe ({balanced_val}): Status {bal_resp.status_code} (Recovered Normal)\n\n"
                                f"Reproduction Command:\n{evidence_curl}"
                            ),
                            explanation=(
                                f"Parameter '{param_name}' triggered an internal server error (HTTP 500) exclusively when "
                                f"syntax delimiter '{probe_spec['probe']}' was injected, but returned HTTP 200 for neutral input "
                                f"and recovered clean HTTP 200 behavior when the delimiter was balanced. This indicates a syntax interruption."
                            ),
                            remediation="Implement parameterized prepared statements and enforce strict input data type validation.",
                            manual_verification_steps=(
                                f"1. Compare baseline: curl -sI '{endpoint}'\n"
                                f"2. Compare probe: {evidence_curl}\n"
                                f"3. Compare balanced: curl -sI '{bal_url}'"
                            )
                        ))
                        break
        except Exception as e:
            self.logger("WARNING", f"Error checking SQLi on GET {endpoint} ({param_name}): {str(e)}")

    def _test_form_sqli(self, endpoint: str, base_path: str, method: str,
                         param_name: str, orig_val: str, all_data: dict, findings: list):
        try:
            # Baseline request
            if method == "POST":
                baseline_resp = self.session.post(endpoint, data=all_data, timeout=5, verify=False)
            else:
                baseline_resp = self.session.get(endpoint, params=all_data, timeout=5, verify=False)
            
            baseline_err = self._match_db_error(baseline_resp.text)
            baseline_status = baseline_resp.status_code

            for probe_spec in self.SAFE_PROBES:
                test_data = dict(all_data)
                test_data[param_name] = f"{orig_val}{probe_spec['probe']}"

                if method == "POST":
                    resp = self.session.post(endpoint, data=test_data, timeout=5, verify=False)
                else:
                    resp = self.session.get(endpoint, params=test_data, timeout=5, verify=False)

                matched_err = self._match_db_error(resp.text)
                if matched_err and not baseline_err:
                    post_body_str = "&".join([f"{k}={v}" for k, v in test_data.items()])
                    evidence_curl = f"curl -s -i -X {method} '{endpoint}' -d '{post_body_str}'"
                    err_idx = resp.text.find(matched_err)
                    snippet_start = max(0, err_idx - 60)
                    snippet_end = min(len(resp.text), err_idx + len(matched_err) + 120)
                    context_snippet = resp.text[snippet_start:snippet_end].replace("\n", " ").strip()

                    findings.append(FindingData(
                        vuln_type="Unhandled SQL Syntax Error in Form Input (SQL Injection Indicator)",
                        category=self.owasp_category,
                        cwe_id=self.default_cwe,
                        cvss_score=8.5,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        status="Confirmed Finding",
                        endpoint=endpoint,
                        parameter=param_name,
                        http_method=method,
                        evidence=(
                            f"Target: {method} {endpoint}\n"
                            f"Tested Form Field: '{param_name}' with safe probe '{probe_spec['probe']}' ({probe_spec['desc']})\n"
                            f"Database Signature Detected: '{matched_err}'\n"
                            f"Response Status: HTTP {resp.status_code}\n\n"
                            f"Matched Error Context:\n...{context_snippet}...\n\n"
                            f"Reproduction Command:\n{evidence_curl}"
                        ),
                        explanation=(
                            f"Submitting form field '{param_name}' with syntax character '{probe_spec['probe']}' "
                            f"elicited database error signature '{matched_err}'. The database query is constructed unsafely."
                        ),
                        remediation="Bind form inputs as query parameters via prepared statements or an ORM.",
                        manual_verification_steps=f"Execute: {evidence_curl}"
                    ))
                    break
        except Exception as e:
            self.logger("WARNING", f"Error checking SQLi on form {endpoint} ({param_name}): {str(e)}")
