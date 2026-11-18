from datetime import datetime, timezone, timedelta
from webscanpro import db
from webscanpro.models.target import Target
from webscanpro.models.scan import Scan, ScanLog, CrawledEndpoint
from webscanpro.models.finding import Finding

def purge_demo_data():
    """
    Purges any seeded demo scans, demo targets, and demo findings from the database,
    ensuring only authentic dynamic scan results are retained.
    """
    demo_findings = Finding.query.filter(Finding.vuln_type.like('%[DEMO]%')).all()
    demo_scan_ids = list(set([f.scan_id for f in demo_findings]))
    
    deleted_scans_count = 0
    if demo_scan_ids:
        scans_to_delete = Scan.query.filter(Scan.id.in_(demo_scan_ids)).all()
        for s in scans_to_delete:
            db.session.delete(s)
            deleted_scans_count += 1
        db.session.commit()

    # Clean target names
    demo_targets = Target.query.filter(Target.name.like('%[DEMO]%')).all()
    for t in demo_targets:
        t.name = t.name.replace("[DEMO]", "").strip()
        t.authorization_notes = "Authorized local lab target."
    db.session.commit()
    return deleted_scans_count

def seed_demo_data():
    """
    Seeds safe, realistic sample scan results explicitly labelled as DEMO DATA.
    Provides immediate visualization of charts, reports, and comparisons.
    """
    # Check if demo target already exists
    demo_target = Target.query.filter_by(base_url="http://localhost:3000").first()
    if not demo_target:
        demo_target = Target(
            name="[DEMO] OWASP Juice Shop Lab",
            base_url="http://localhost:3000",
            host="localhost",
            port=3000,
            is_authorized=True,
            authorization_notes="Authorized local security training lab target (Demo Data)."
        )
        db.session.add(demo_target)
        db.session.commit()

    # Create Baseline Demo Scan #1 (older)
    scan1 = Scan.query.filter_by(target_id=demo_target.id, scan_mode="STANDARD").first()
    if not scan1:
        scan1 = Scan(
            target_id=demo_target.id,
            status="COMPLETED",
            scan_mode="STANDARD",
            created_at=datetime.now(timezone.utc) - timedelta(days=2),
            started_at=datetime.now(timezone.utc) - timedelta(days=2),
            completed_at=datetime.now(timezone.utc) - timedelta(days=2) + timedelta(seconds=14),
            duration_seconds=14.2,
            max_depth=3,
            max_pages=20,
            request_timeout=5,
            rate_limit_delay=0.05,
            total_requests_sent=42,
            endpoints_discovered=8,
            forms_discovered=3,
            count_critical=0,
            count_high=2,
            count_medium=2,
            count_low=2,
            count_info=1
        )
        db.session.add(scan1)
        db.session.commit()

        # Add sample endpoints
        ep1 = CrawledEndpoint(scan_id=scan1.id, url="http://localhost:3000/", path="/", method="GET", status_code=200, content_type="text/html")
        ep2 = CrawledEndpoint(scan_id=scan1.id, url="http://localhost:3000/#/search", path="/#/search", method="GET", status_code=200, content_type="text/html")
        ep3 = CrawledEndpoint(scan_id=scan1.id, url="http://localhost:3000/rest/products/search", path="/rest/products/search", method="GET", status_code=200, content_type="application/json")
        db.session.add_all([ep1, ep2, ep3])

        # Add demo findings for Scan 1
        f1 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Unhandled SQL Syntax Error in Search Query",
            category="A03:2021-Injection",
            cwe_id="CWE-89",
            cvss_score=8.6,
            severity="HIGH",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/rest/products/search?q=",
            parameter="q",
            http_method="GET",
            evidence=(
                "Probe Sent: GET /rest/products/search?q=apple'\n"
                "Response Code: 500 Internal Server Error\n"
                "Signature: SQL syntax error near ''': SQLite/3 syntax error"
            ),
            explanation="The search endpoint directly interpolates input parameter 'q' into an unparameterized SQL statement.",
            remediation="Adopt parameterized SQL queries using prepared statements or ORM filtering.",
            manual_verification_steps="Send single quote to search query param and observe raw database syntax error."
        )

        f2 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Reflected XSS via Unescaped Query Parameter",
            category="A03:2021-Injection",
            cwe_id="CWE-79",
            cvss_score=7.3,
            severity="HIGH",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/#/search?q=",
            parameter="q",
            http_method="GET",
            evidence=(
                "Probe Sent: wsp_chk_<wsptag>\n"
                "Response HTML: <div class='results'>Results for wsp_chk_<wsptag></div>\n"
                "Entity Encoding: Missing (raw < and > rendered)"
            ),
            explanation="Input parameter 'q' is reflected back into the browser DOM without context-aware HTML entity encoding.",
            remediation="Apply context-aware HTML entity encoding on output before rendering into the DOM.",
            manual_verification_steps="Check source of search page when a canary HTML tag is supplied."
        )

        f3 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Missing Content-Security-Policy Header",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-1021",
            cvss_score=5.4,
            severity="MEDIUM",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="Content-Security-Policy",
            http_method="GET",
            evidence="Response headers omit 'Content-Security-Policy'.",
            explanation="CSP restrictions are absent, leaving the application without defense-in-depth against XSS.",
            remediation="Define a strict Content-Security-Policy header restricting script-src and object-src.",
            manual_verification_steps="Inspect HTTP response headers via curl -I http://localhost:3000/"
        )

        f4 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Session Cookie Missing 'HttpOnly' Flag",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-1004",
            cvss_score=5.3,
            severity="MEDIUM",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="token",
            http_method="GET",
            evidence="Set-Cookie: token=eyJhbGciOi...; Path=/ (Lacks HttpOnly flag)",
            explanation="The authentication token cookie lacks HttpOnly and can be accessed by client-side scripts.",
            remediation="Append 'HttpOnly; Secure; SameSite=Lax' to the Set-Cookie directive.",
            manual_verification_steps="Check cookie flags in browser storage inspector."
        )

        f5 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Missing X-Content-Type-Options Header",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-16",
            cvss_score=3.7,
            severity="LOW",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="X-Content-Type-Options",
            http_method="GET",
            evidence="Header 'X-Content-Type-Options' is missing from HTTP response.",
            explanation="Absence of 'X-Content-Type-Options: nosniff' enables MIME-type sniffing in legacy clients.",
            remediation="Send 'X-Content-Type-Options: nosniff' on all responses.",
            manual_verification_steps="Verify headers with curl -I."
        )

        f6 = Finding(
            scan_id=scan1.id,
            vuln_type="[DEMO] Server Version Disclosure",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-200",
            cvss_score=2.6,
            severity="LOW",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="Server",
            http_method="GET",
            evidence="Server: Express/4.17.1",
            explanation="Discloses exact server framework and version number.",
            remediation="Suppress the 'Server' and 'X-Powered-By' header in Express configuration.",
            manual_verification_steps="Examine Server header output."
        )

        db.session.add_all([f1, f2, f3, f4, f5, f6])
        
        # Add sample logs
        l1 = ScanLog(scan_id=scan1.id, level="INFO", message="Scan initialized against http://localhost:3000 (DEMO DATA)")
        l2 = ScanLog(scan_id=scan1.id, level="SUCCESS", message="Crawl completed: 8 endpoints discovered.")
        l3 = ScanLog(scan_id=scan1.id, level="INFO", message="Security modules completed: 6 findings recorded.")
        db.session.add_all([l1, l2, l3])

        db.session.commit()

    # Create Follow-up Scan #2 (recent - shows resolved XSS and 1 new finding for Scan Comparison demonstration)
    scan2 = Scan.query.filter_by(target_id=demo_target.id, scan_mode="DEEP").first()
    if not scan2:
        scan2 = Scan(
            target_id=demo_target.id,
            status="COMPLETED",
            scan_mode="DEEP",
            created_at=datetime.now(timezone.utc) - timedelta(hours=3),
            started_at=datetime.now(timezone.utc) - timedelta(hours=3),
            completed_at=datetime.now(timezone.utc) - timedelta(hours=3) + timedelta(seconds=18),
            duration_seconds=18.5,
            max_depth=4,
            max_pages=35,
            request_timeout=5,
            rate_limit_delay=0.05,
            total_requests_sent=68,
            endpoints_discovered=12,
            forms_discovered=4,
            count_critical=1,
            count_high=1,
            count_medium=2,
            count_low=2,
            count_info=0
        )
        db.session.add(scan2)
        db.session.commit()

        # Add findings: SQLi remains, XSS resolved, new IDOR finding detected!
        f_sqli = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Unhandled SQL Syntax Error in Search Query",
            category="A03:2021-Injection",
            cwe_id="CWE-89",
            cvss_score=8.6,
            severity="HIGH",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/rest/products/search?q=",
            parameter="q",
            http_method="GET",
            evidence="Probe: ' -> SQLite/3 syntax error near ''':",
            explanation="Unescaped dynamic query construction still present.",
            remediation="Use parameterized queries.",
            manual_verification_steps="Test with quote delimiter."
        )

        f_idor = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Broken Object Level Authorization (BOLA / Horizontal IDOR)",
            category="A01:2021-Broken Access Control",
            cwe_id="CWE-639",
            cvss_score=9.1,
            severity="CRITICAL",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/api/BasketItems/1",
            parameter="BasketId",
            http_method="GET",
            evidence="Test Account B accessed Basket belonging to Account A (Status 200 OK, full cart items returned).",
            explanation="The application does not verify if the authenticated user owns the referenced basket entity.",
            remediation="Validate ownership before serving basket entities.",
            manual_verification_steps="Access another user's basket ID using Account B session."
        )

        f_csp = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Missing Content-Security-Policy Header",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-1021",
            cvss_score=5.4,
            severity="MEDIUM",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="Content-Security-Policy",
            http_method="GET",
            evidence="Response headers omit 'Content-Security-Policy'.",
            explanation="CSP restrictions are absent.",
            remediation="Define a strict CSP header.",
            manual_verification_steps="Inspect headers."
        )

        f_cookie = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Session Cookie Missing 'HttpOnly' Flag",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-1004",
            cvss_score=5.3,
            severity="MEDIUM",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="token",
            http_method="GET",
            evidence="Set-Cookie: token=... lacks HttpOnly.",
            explanation="Exposes token to script access.",
            remediation="Add HttpOnly flag.",
            manual_verification_steps="Inspect cookie flags."
        )

        f_opt = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Missing X-Content-Type-Options Header",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-16",
            cvss_score=3.7,
            severity="LOW",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="X-Content-Type-Options",
            http_method="GET",
            evidence="Missing nosniff header.",
            explanation="MIME sniffing vulnerability.",
            remediation="Set X-Content-Type-Options: nosniff.",
            manual_verification_steps="Check header."
        )

        f_server = Finding(
            scan_id=scan2.id,
            vuln_type="[DEMO] Server Version Disclosure",
            category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-200",
            cvss_score=2.6,
            severity="LOW",
            confidence="CONFIRMED",
            status="Confirmed Finding",
            endpoint="http://localhost:3000/",
            parameter="Server",
            http_method="GET",
            evidence="Server: Express/4.17.1",
            explanation="Exposes server version.",
            remediation="Suppress banner.",
            manual_verification_steps="Check Server header."
        )

        db.session.add_all([f_sqli, f_idor, f_csp, f_cookie, f_opt, f_server])
        db.session.commit()
