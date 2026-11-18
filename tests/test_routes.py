def test_dashboard_route(client, sample_scan):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"WebScanPro" in resp.data
    assert b"Total Vulnerabilities" in resp.data

def test_scan_new_get(client):
    resp = client.get("/scans/new")
    assert resp.status_code == 200
    assert b"Target Specification" in resp.data
    assert b"Quick Select Authorized Lab Presets" in resp.data

def test_scan_new_post_unauthorized_rejects(client):
    resp = client.post("/scans/new", data={
        "target_url": "http://localhost:3000",
        "is_authorized": ""  # Unchecked!
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Explicit target authorization confirmation is required" in resp.data

def test_scan_new_post_public_domain_rejects(client):
    resp = client.post("/scans/new", data={
        "target_url": "http://example.com",
        "is_authorized": "1"
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Security Boundary Enforcement" in resp.data

from unittest.mock import patch

def test_scan_new_post_valid_target(client):
    with patch("webscanpro.routes.scan.ScanEngine.start_scan_async") as mock_start:
        resp = client.post("/scans/new", data={
            "target_url": "http://127.0.0.1:5000/mock-lab/",
            "target_name": "Test Mock Lab",
            "is_authorized": "1",
            "scan_mode": "QUICK",
            "modules": ["headers"]
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "/scans/" in resp.headers["Location"]
        assert mock_start.called

def test_scan_detail_route(client, sample_scan):
    resp = client.get(f"/scans/{sample_scan.id}")
    assert resp.status_code == 200
    assert f"Scan #{sample_scan.id}".encode() in resp.data

def test_scan_history_route(client, sample_scan):
    resp = client.get("/scans/")
    assert resp.status_code == 200
    assert b"Assessment History" in resp.data

def test_scan_compare_route(client, sample_scan):
    resp = client.get(f"/scans/compare?scan1={sample_scan.id}&scan2={sample_scan.id}")
    assert resp.status_code == 200
    assert b"Select Scans to Compare" in resp.data

def test_vulnerabilities_list(client, sample_scan):
    resp = client.get("/vulnerabilities/")
    assert resp.status_code == 200
    assert b"Missing Security Header" in resp.data

def test_vulnerability_detail(client, sample_scan):
    finding = sample_scan.findings.first()
    resp = client.get(f"/vulnerabilities/{finding.id}")
    assert resp.status_code == 200
    assert finding.vuln_type.encode() in resp.data
    assert b"Technical Analysis" in resp.data

def test_reports_index(client, sample_scan):
    resp = client.get("/reports/")
    assert resp.status_code == 200
    assert b"Executive" in resp.data

def test_api_scan_status(client, sample_scan):
    resp = client.get(f"/api/scans/{sample_scan.id}/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == sample_scan.id
    assert data["status"] == "COMPLETED"
    assert "findings_by_severity" in data

def test_settings_routes(client):
    resp1 = client.get("/settings/")
    assert resp1.status_code == 200
    assert b"Authorized Target Policy" in resp1.data

    resp2 = client.get("/settings/documentation")
    assert resp2.status_code == 200
    assert b"Architecture Overview" in resp2.data
