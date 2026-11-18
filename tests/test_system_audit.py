import json
import pytest
from webscanpro import db
from webscanpro.models.target import Target
from webscanpro.models.scan import Scan, CrawledEndpoint, ScanLog
from webscanpro.models.finding import Finding
from webscanpro.core.reporter import SecurityReportGenerator

@pytest.fixture
def audit_data(app, sample_scan):
    # Enrich sample_scan with endpoint, log, and an additional finding
    scan = sample_scan
    ep = CrawledEndpoint(
        scan_id=scan.id,
        url=f"{scan.target.base_url}search",
        path="/search",
        method="GET",
        status_code=200,
        content_type="text/html"
    )
    db.session.add(ep)

    f2 = Finding(
        scan_id=scan.id,
        vuln_type="Unescaped Reflected Input (XSS Indicator)",
        category="A03:2021-Injection",
        cwe_id="CWE-79",
        cvss_score=7.3,
        severity="HIGH",
        confidence="CONFIRMED",
        status="Confirmed Finding",
        endpoint=f"{scan.target.base_url}search",
        parameter="q",
        http_method="GET",
        evidence="Injected probe: wsp<wsptag>\nRaw reflection observed in HTML body.",
        explanation="Unsanitized input rendered in DOM.",
        remediation="Apply HTML entity encoding.",
        manual_verification_steps="Send query param with tags and inspect page source."
    )
    db.session.add(f2)

    log = ScanLog(scan_id=scan.id, level="INFO", message="Audit scan test event.")
    db.session.add(log)
    db.session.commit()

    return scan.target.id, scan.id, f2.id


# =====================================================================
# 1. Verification of Web Console & Dashboard APIs
# =====================================================================

def test_audit_dashboard(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Security Posture" in resp.data
    assert b"Application Security Posture Score" in resp.data
    assert f"#{scan_id}".encode() in resp.data

def test_audit_scan_history_and_filters(client, audit_data):
    target_id, scan_id, _ = audit_data
    # All scans
    resp = client.get("/scans/")
    assert resp.status_code == 200
    assert f"#{scan_id}".encode() in resp.data

    # Filter by target
    resp_t = client.get(f"/scans/?target_id={target_id}")
    assert resp_t.status_code == 200
    assert f"#{scan_id}".encode() in resp_t.data

    # Filter by status
    resp_s = client.get("/scans/?status=COMPLETED")
    assert resp_s.status_code == 200
    assert f"#{scan_id}".encode() in resp_s.data

def test_audit_scan_detail_console(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get(f"/scans/{scan_id}")
    assert resp.status_code == 200
    assert f"Scan #{scan_id}".encode() in resp.data
    assert b"Surface Crawl" in resp.data
    assert b"Download PDF" in resp.data

def test_audit_scan_compare_tool(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get(f"/scans/compare?scan1={scan_id}&scan2={scan_id}")
    assert resp.status_code == 200
    assert b"Scan Comparison" in resp.data
    assert b"Persistent Findings" in resp.data

def test_audit_vulnerabilities_explorer_and_search(client, audit_data):
    target_id, scan_id, finding_id = audit_data
    # Index
    resp = client.get("/vulnerabilities/")
    assert resp.status_code == 200
    assert b"Vulnerabilities" in resp.data

    # Search filter
    resp_search = client.get("/vulnerabilities/?q=Reflected")
    assert resp_search.status_code == 200
    assert b"Unescaped Reflected Input" in resp_search.data

    # Severity filter
    resp_sev = client.get("/vulnerabilities/?severity=HIGH")
    assert resp_sev.status_code == 200
    assert b"Unescaped Reflected Input" in resp_sev.data

    # Detail
    resp_det = client.get(f"/vulnerabilities/{finding_id}")
    assert resp_det.status_code == 200
    assert b"Remediation Guidance" in resp_det.data
    assert b"Manual Verification Protocol" in resp_det.data

def test_audit_settings_and_documentation(client, audit_data):
    resp_set = client.get("/settings/")
    assert resp_set.status_code == 200
    assert b"Authorized Lab Targets" in resp_set.data or b"Lab Environments" in resp_set.data

    resp_doc = client.get("/settings/documentation")
    assert resp_doc.status_code == 200
    assert b"Architecture &amp; Data Flow" in resp_doc.data or b"Architecture" in resp_doc.data


# =====================================================================
# 2. REST API Endpoint Tests
# =====================================================================

def test_api_scan_status_telemetry(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get(f"/api/scans/{scan_id}/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == scan_id
    assert data["status"] == "COMPLETED"
    assert data["progress"] == 100
    assert data["total_findings"] >= 1
    assert "findings_by_severity" in data

def test_api_target_validate(client):
    # Authorized loopback target
    resp_valid = client.post("/api/targets/validate", json={
        "url": "http://127.0.0.1:5001/mock-lab/",
        "is_authorized": True
    })
    assert resp_valid.status_code == 200
    assert resp_valid.get_json()["valid"] is True

    # Unauthorized target
    resp_unauth = client.post("/api/targets/validate", json={
        "url": "http://127.0.0.1:5001/mock-lab/",
        "is_authorized": False
    })
    assert resp_unauth.status_code == 400
    assert resp_unauth.get_json()["valid"] is False

    # External unauthorized public target
    resp_pub = client.post("/api/targets/validate", json={
        "url": "https://example.com",
        "is_authorized": True
    })
    assert resp_pub.status_code == 400
    assert "Security Boundary Enforcement" in resp_pub.get_json()["error"]

def test_api_labs_health(client):
    resp = client.get("/api/labs/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "mock_lab" in data


# =====================================================================
# 3. Report Generation Verification (PDF & HTML)
# =====================================================================

def test_audit_html_report_view(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get(f"/reports/scan/{scan_id}/html")
    assert resp.status_code == 200
    assert b"WebScanPro" in resp.data
    assert b"Executive Severity Summary" in resp.data
    assert b"Detailed Technical Findings" in resp.data

def test_audit_pdf_report_download(client, audit_data):
    target_id, scan_id, _ = audit_data
    resp = client.get(f"/reports/scan/{scan_id}/pdf")
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type") == "application/pdf"
    # PDF Magic Header verification
    assert resp.data.startswith(b"%PDF-")
    assert len(resp.data) > 2000  # Valid non-empty PDF file


# =====================================================================
# 4. Database Persistence & Cascade Cleanup
# =====================================================================

def test_audit_scan_cancellation_api(client, sample_target):
    # Create running scan
    scan = Scan(target_id=sample_target.id, status="RUNNING")
    db.session.add(scan)
    db.session.commit()

    resp = client.post(f"/api/scans/{scan.id}/cancel")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    # Verify status in database
    db.session.refresh(scan)
    assert scan.status == "CANCELLED"

def test_audit_scan_delete_cascade(client, sample_target):
    scan = Scan(target_id=sample_target.id, status="COMPLETED")
    db.session.add(scan)
    db.session.commit()

    f = Finding(scan_id=scan.id, vuln_type="Test Vuln", category="A01", cwe_id="CWE-1", cvss_score=5.0,
                severity="MEDIUM", confidence="CONFIRMED", status="Confirmed", endpoint="/test",
                parameter="p", http_method="GET", evidence="E", explanation="X", remediation="R")
    log = ScanLog(scan_id=scan.id, level="INFO", message="M")
    ep = CrawledEndpoint(scan_id=scan.id, url="http://127.0.0.1/test", path="/test", method="GET", status_code=200)
    db.session.add_all([f, log, ep])
    db.session.commit()

    scan_id = scan.id
    finding_id = f.id

    # Execute delete
    resp = client.post(f"/scans/{scan_id}/delete", follow_redirects=True)
    assert resp.status_code == 200

    # Verify scan deleted from database
    assert db.session.get(Scan, scan_id) is None
    # Verify cascade deleted findings, logs, and endpoints
    assert db.session.get(Finding, finding_id) is None
    assert CrawledEndpoint.query.filter_by(scan_id=scan_id).count() == 0
    assert ScanLog.query.filter_by(scan_id=scan_id).count() == 0


# =====================================================================
# 5. Verification of No Fake Data
# =====================================================================

def test_audit_no_fake_demo_data(app):
    """Verify that no fake [DEMO] findings remain in the database."""
    demo_findings = Finding.query.filter(Finding.vuln_type.like("%[DEMO]%")).count()
    assert demo_findings == 0, f"Found {demo_findings} unpurged demo findings in live database!"
