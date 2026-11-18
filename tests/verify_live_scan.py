import os
from webscanpro import create_app, db
from webscanpro.models.target import Target
from webscanpro.models.scan import Scan
from webscanpro.core.engine import ScanEngine
from webscanpro.core.reporter import SecurityReportGenerator

def test_live_scan_against_mock_lab():
    app = create_app("development")
    with app.app_context():
        # Setup target pointing to mock lab
        target_url = "http://127.0.0.1:5001/mock-lab/"
        target = Target.query.filter_by(base_url=target_url).first()
        if not target:
            target = Target(
                name="Built-in Mock Target Lab",
                base_url=target_url,
                host="127.0.0.1",
                port=5001,
                is_authorized=True,
                authorization_notes="Self-hosted local security testing lab."
            )
            db.session.add(target)
            db.session.commit()

        scan = Scan(
            target_id=target.id,
            status="PENDING",
            scan_mode="QUICK",
            max_depth=2,
            max_pages=15,
            enabled_modules_json='["headers", "sqli", "xss", "auth", "idor"]'
        )
        db.session.add(scan)
        db.session.commit()
        print(f"[+] Initialized live test scan #{scan.id} against {target_url}")

        # Run scan engine
        ScanEngine._run_scan_thread(app, scan.id)

        # Refresh
        db.session.expire_all()
        updated_scan = db.session.get(Scan, scan.id)
        print(f"[✓] Scan status: {updated_scan.status}")
        print(f"[✓] Endpoints discovered: {updated_scan.endpoints_discovered}")
        print(f"[✓] Duration: {updated_scan.duration_seconds:.2f}s")
        print(f"[✓] Total findings: {updated_scan.total_findings}")
        print(f"[✓] Findings breakdown: Critical={updated_scan.count_critical}, High={updated_scan.count_high}, Medium={updated_scan.count_medium}, Low={updated_scan.count_low}, Info={updated_scan.count_info}")

        for f in updated_scan.findings:
            print(f"    - [{f.severity}] {f.vuln_type} on {f.endpoint} ({f.status})")

        # Verify PDF report generation
        pdf_path = SecurityReportGenerator.generate_pdf_report(updated_scan)
        print(f"[✓] PDF Report generated at: {pdf_path} (Size: {os.path.getsize(pdf_path)} bytes)")

        assert updated_scan.status == "COMPLETED"
        assert updated_scan.total_findings > 0
        assert os.path.exists(pdf_path)
        print("\n[SUCCESS] Live scan verification completed successfully!")

if __name__ == "__main__":
    test_live_scan_against_mock_lab()
