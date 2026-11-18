from unittest.mock import MagicMock
from urllib.parse import unquote
import requests
from webscanpro.core.crawler import CrawledResource
from webscanpro.modules.headers_cookies import HeadersCookiesModule
from webscanpro.modules.sqli import SQLInjectionModule
from webscanpro.modules.xss import XSSModule
from webscanpro.modules.auth_session import AuthSessionModule
from webscanpro.modules.access_control import AccessControlModule

def test_headers_module_missing_headers():
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
    mock_resp.raw.headers.getlist.return_value = ["session=abc123; Path=/"]
    mock_session.get.return_value = mock_resp

    module = HeadersCookiesModule(session=mock_session)
    res = CrawledResource(
        url="http://localhost:3000/",
        path="/",
        method="GET",
        headers={"Server": "Apache/2.4.41 (Ubuntu)"}
    )

    findings = module.run("http://localhost:3000", [res], {})
    vuln_types = [f.vuln_type for f in findings]

    assert any("Content-Security-Policy" in v for v in vuln_types)
    assert any("X-Content-Type-Options" in v for v in vuln_types)
    assert any("Server Technology Version Disclosure" in v for v in vuln_types)
    assert any("HttpOnly" in v for v in vuln_types)

def test_headers_deduplication():
    """Verify that multiple pages lacking CSP produce exactly 1 finding with aggregated endpoints."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_session.get.return_value = mock_resp

    module = HeadersCookiesModule(session=mock_session)
    resources = [
        CrawledResource(url=f"http://localhost:3000/page{i}", path=f"/page{i}", method="GET", headers={})
        for i in range(5)
    ]

    findings = module.run("http://localhost:3000", resources, {})
    csp_findings = [f for f in findings if "Content-Security-Policy" in f.vuln_type]
    # Must report exactly 1 finding for the whole site
    assert len(csp_findings) == 1
    # Evidence must list affected pages
    assert "Sampled Endpoints Missing Header (5)" in csp_findings[0].evidence

def test_sqli_module_error_signature_detection():
    mock_session = MagicMock()
    
    # Baseline returns normal response
    base_resp = MagicMock()
    base_resp.status_code = 200
    base_resp.text = "Product list: Apples, Oranges"

    # Injected probe returns SQLite error
    sqli_resp = MagicMock()
    sqli_resp.status_code = 500
    sqli_resp.text = "sqlite3.OperationalError: near \"'\": syntax error in SELECT"

    # Configure session.get to return base_resp first, then sqli_resp
    mock_session.get.side_effect = [base_resp, sqli_resp, sqli_resp, sqli_resp]

    module = SQLInjectionModule(session=mock_session)
    res = CrawledResource(
        url="http://localhost:3000/products?category=fruit",
        path="/products",
        method="GET"
    )

    findings = module.run("http://localhost:3000", [res], {})
    assert len(findings) > 0
    assert findings[0].confidence == "CONFIRMED"
    assert "SQL" in findings[0].vuln_type
    assert "sqlite3.OperationalError" in findings[0].evidence

def test_sqli_differential_with_neutral_control():
    """Verify differential SQL injection detection when syntax probe fails but neutral probe succeeds."""
    mock_session = MagicMock()

    base_resp = MagicMock(status_code=200, text="User details: ID 10")
    probe_err_resp = MagicMock(status_code=500, text="Internal Server Error")
    neutral_resp = MagicMock(status_code=200, text="User details: ID 100")
    balanced_resp = MagicMock(status_code=200, text="User details: ID 10''")

    # Order of calls:
    # 1. baseline_resp (200)
    # 2. probe_resp (500)
    # 3. neutral_resp (200)
    # 4. bal_resp (200)
    mock_session.get.side_effect = [base_resp, probe_err_resp, neutral_resp, balanced_resp]

    module = SQLInjectionModule(session=mock_session)
    res = CrawledResource(
        url="http://localhost:3000/users?id=10",
        path="/users",
        method="GET"
    )

    findings = module.run("http://localhost:3000", [res], {})
    assert len(findings) == 1
    assert findings[0].confidence == "LIKELY"
    assert "Differential Syntax Anomaly" in findings[0].vuln_type

def test_xss_module_reflection_detection():
    mock_session = MagicMock()
    
    def fake_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        if "wsp" in url:
            decoded_val = unquote(url.split("q=")[1])
            resp.text = f"<html><body>Search results for: {decoded_val}</body></html>"
        else:
            resp.text = "<html><body>Search page</body></html>"
        return resp

    mock_session.get.side_effect = fake_get

    module = XSSModule(session=mock_session)
    res = CrawledResource(
        url="http://localhost:3000/search?q=test",
        path="/search",
        method="GET"
    )

    findings = module.run("http://localhost:3000", [res], {})
    assert len(findings) > 0
    assert "Reflected" in findings[0].vuln_type
    assert findings[0].confidence == "CONFIRMED"
    assert findings[0].cwe_id == "CWE-79"

def test_xss_non_html_response_suppressed():
    """Verify that JSON API responses reflecting parameters do NOT trigger false positive XSS."""
    mock_session = MagicMock()
    
    def fake_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.text = '{"status": "ok", "query": "wsp123<wsptag>"}'
        return resp

    mock_session.get.side_effect = fake_get

    module = XSSModule(session=mock_session)
    res = CrawledResource(
        url="http://localhost:3000/api/items?q=test",
        path="/api/items",
        method="GET"
    )

    findings = module.run("http://localhost:3000", [res], {})
    # Should not produce XSS findings for application/json
    assert len(findings) == 0

def test_auth_session_insecure_http_password():
    module = AuthSessionModule()
    # Resource has a login form with password field on external HTTP host
    res = CrawledResource(
        url="http://192.168.1.50/login",
        path="/login",
        method="GET",
        forms=[{
            "action": "http://192.168.1.50/login",
            "method": "POST",
            "inputs": [{"name": "password", "type": "password"}]
        }]
    )

    findings = module.run("http://192.168.1.50", [res], {})
    vuln_types = [f.vuln_type for f in findings]
    assert any("Insecure Transmission" in v or "Password Form" in v for v in vuln_types)

def test_access_control_two_account_idor():
    resp_b = MagicMock()
    resp_b.status_code = 200
    resp_b.text = '{"user_id": 1, "username": "alice", "balance": "$5000"}'
    
    module = AccessControlModule()
    findings = []
    
    account_a = {"token": "token-alice", "resource_url": "http://localhost:3000/api/profile/1"}
    account_b = {"token": "token-bob"}

    import requests
    original_session = requests.Session
    try:
        class FakeSession:
            def __init__(self):
                self.headers = {}
            def get(self, url, **kwargs):
                return resp_b

        requests.Session = FakeSession
        module._test_two_account_idor(account_a, account_b, findings)
        assert len(findings) == 1
        assert "Broken Object Level Authorization" in findings[0].vuln_type
        assert findings[0].severity == "HIGH"
        assert findings[0].confidence == "CONFIRMED"
    finally:
        requests.Session = original_session
