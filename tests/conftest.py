import pytest
from webscanpro import create_app, db
from webscanpro.models.target import Target
from webscanpro.models.scan import Scan
from webscanpro.models.finding import Finding

@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def sample_target(app):
    target = Target(
        name="Local Mock Lab",
        base_url="http://127.0.0.1:5000/mock-lab/",
        host="127.0.0.1",
        port=5000,
        is_authorized=True,
    )
    db.session.add(target)
    db.session.commit()
    return target

@pytest.fixture
def sample_scan(app, sample_target):
    scan = Scan(
        target_id=sample_target.id,
        status="COMPLETED",
        scan_mode="STANDARD",
        duration_seconds=5.2,
        total_requests_sent=15,
        endpoints_discovered=4,
        count_critical=0,
        count_high=1,
        count_medium=1,
        count_low=1,
        count_info=1
    )
    db.session.add(scan)
    db.session.commit()

    f1 = Finding(
        scan_id=scan.id,
        vuln_type="Missing Security Header: Content-Security-Policy",
        category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-1021",
        cvss_score=5.4,
        severity="MEDIUM",
        confidence="CONFIRMED",
        status="Confirmed Finding",
        endpoint=sample_target.base_url,
        parameter="Content-Security-Policy",
        http_method="GET",
        evidence="Missing CSP header",
        explanation="CSP is missing from response headers",
        remediation="Add Content-Security-Policy header"
    )
    db.session.add(f1)
    db.session.commit()
    return scan
