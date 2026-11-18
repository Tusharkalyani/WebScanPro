import re
import pytest
import requests
from webscanpro.core.crawler import CrawledResource
from webscanpro.modules.headers_cookies import HeadersCookiesModule
from webscanpro.modules.sqli import SQLInjectionModule
from webscanpro.modules.xss import XSSModule

def is_service_reachable(url: str, timeout: float = 1.0) -> bool:
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code in (200, 302)
    except Exception:
        return False

def test_juiceshop_headers_accuracy():
    """
    Test Headers & Cookies module against OWASP Juice Shop.
    Verifies that present headers (X-Content-Type-Options, X-Frame-Options)
    are NOT falsely reported as missing, while missing CSP is accurately detected.
    """
    if not is_service_reachable("http://localhost:3000"):
        pytest.skip("OWASP Juice Shop not running on localhost:3000")

    module = HeadersCookiesModule()
    findings = module.run("http://localhost:3000", [], {})
    vuln_types = [f.vuln_type for f in findings]

    # CSP should be missing
    assert any("Content-Security-Policy" in v for v in vuln_types)

    # X-Content-Type-Options and X-Frame-Options are present in Juice Shop and must NOT be flagged
    assert not any("X-Content-Type-Options" in v for v in vuln_types)
    assert not any("X-Frame-Options" in v for v in vuln_types)

def test_juiceshop_sqlite_sqli_detection():
    """
    Test SQL injection module against OWASP Juice Shop product search endpoint.
    Verifies detection of SQLite syntax error (SQLITE_ERROR).
    """
    if not is_service_reachable("http://localhost:3000"):
        pytest.skip("OWASP Juice Shop not running on localhost:3000")

    module = SQLInjectionModule()
    res = CrawledResource(
        url="http://localhost:3000/rest/products/search?q=apple",
        path="/rest/products/search",
        method="GET"
    )

    findings = module.run("http://localhost:3000", [res], {})
    assert len(findings) > 0
    sqli_finding = findings[0]
    assert sqli_finding.confidence == "CONFIRMED"
    assert "SQL" in sqli_finding.vuln_type
    assert sqli_finding.cwe_id == "CWE-89"
    # Evidence must contain reproduction command
    assert "curl" in sqli_finding.evidence

def test_dvwa_mariadb_sqli_detection():
    """
    Test SQL injection module against DVWA with low security session.
    Verifies detection of MySQL/MariaDB syntax error signature.
    """
    if not is_service_reachable("http://127.0.0.1:4280"):
        pytest.skip("DVWA not running on 127.0.0.1:4280")

    s = requests.Session()
    r = s.get("http://127.0.0.1:4280/login.php")
    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", r.text)
    if not token_match:
        pytest.skip("Could not retrieve CSRF token from DVWA login page")

    token = token_match.group(1)
    login_resp = s.post("http://127.0.0.1:4280/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    })

    if "login.php" in login_resp.url and "index.php" not in login_resp.text:
        pytest.skip("DVWA login failed or database not initialized")

    # Set security to low
    sec_page = s.get("http://127.0.0.1:4280/security.php")
    sec_token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", sec_page.text)
    if sec_token_match:
        s.post("http://127.0.0.1:4280/security.php", data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": sec_token_match.group(1)
        })

    module = SQLInjectionModule(session=s)
    res = CrawledResource(
        url="http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit",
        path="/vulnerabilities/sqli/",
        method="GET"
    )

    findings = module.run("http://127.0.0.1:4280", [res], {})
    assert len(findings) > 0
    assert findings[0].confidence == "CONFIRMED"
    assert "SQL" in findings[0].vuln_type
    assert "You have an error in your SQL syntax" in findings[0].evidence

def test_dvwa_reflected_xss_detection():
    """
    Test XSS module against DVWA reflected XSS endpoint.
    Verifies detection of raw HTML tag reflection in document body.
    """
    if not is_service_reachable("http://127.0.0.1:4280"):
        pytest.skip("DVWA not running on 127.0.0.1:4280")

    s = requests.Session()
    r = s.get("http://127.0.0.1:4280/login.php")
    token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", r.text)
    if not token_match:
        pytest.skip("Could not retrieve CSRF token from DVWA login page")

    token = token_match.group(1)
    s.post("http://127.0.0.1:4280/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    })

    sec_page = s.get("http://127.0.0.1:4280/security.php")
    sec_token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", sec_page.text)
    if sec_token_match:
        s.post("http://127.0.0.1:4280/security.php", data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": sec_token_match.group(1)
        })

    module = XSSModule(session=s)
    res = CrawledResource(
        url="http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test",
        path="/vulnerabilities/xss_r/",
        method="GET"
    )

    findings = module.run("http://127.0.0.1:4280", [res], {})
    assert len(findings) > 0
    assert findings[0].confidence == "CONFIRMED"
    assert "Reflected" in findings[0].vuln_type
    assert findings[0].cwe_id == "CWE-79"
    assert "curl" in findings[0].evidence
