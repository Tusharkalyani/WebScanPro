import threading
import time
from datetime import datetime, timezone
from flask import current_app
from webscanpro import db
from webscanpro.models.scan import Scan, CrawledEndpoint, ScanLog
from webscanpro.models.finding import Finding
from webscanpro.core.crawler import SafeCrawler
from webscanpro.core.reporter import SecurityReportGenerator
from webscanpro.modules import get_module

class ScanEngine:
    """
    Central scanning orchestrator. Manages thread lifecycle, safe crawling,
    dynamic module dispatching, database persistence, and automated report generation.
    """

    @classmethod
    def start_scan_async(cls, app, scan_id: int):
        thread = threading.Thread(
            target=cls._run_scan_thread,
            args=(app, scan_id),
            daemon=True,
            name=f"WebScanPro-Worker-Scan-{scan_id}"
        )
        thread.start()
        return thread

    @classmethod
    def _run_scan_thread(cls, app, scan_id: int):
        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            if not scan:
                return

            def log_event(level: str, message: str):
                try:
                    entry = ScanLog(scan_id=scan.id, level=level, message=message)
                    db.session.add(entry)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

            try:
                # 1. Initialize Scan State
                scan.status = "RUNNING"
                scan.started_at = datetime.now(timezone.utc)
                db.session.commit()
                start_perf = time.time()

                target_url = scan.target.base_url
                log_event("INFO", f"Scan #{scan.id} started against target: {target_url}")
                log_event("INFO", f"Scan Mode: {scan.scan_mode} | Enabled Modules: {', '.join(scan.enabled_modules)}")

                # 2. Stage: Safe Crawling & Parameter Extraction
                log_event("INFO", f"Initiating safe crawler (Depth: {scan.max_depth}, Page Limit: {scan.max_pages})...")
                crawler = SafeCrawler(
                    base_url=target_url,
                    max_depth=scan.max_depth,
                    max_pages=scan.max_pages,
                    timeout=scan.request_timeout,
                    rate_limit_delay=scan.rate_limit_delay,
                    logger_callback=log_event
                )
                crawled_resources = crawler.crawl()
                scan.total_requests_sent += crawler.request_count

                # Check if scan was cancelled during crawl
                db.session.refresh(scan)
                if scan.status == "CANCELLED":
                    log_event("WARNING", f"Scan #{scan.id} was cancelled by operator during crawl.")
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.duration_seconds = time.time() - start_perf
                    db.session.commit()
                    return

                # Persist discovered endpoints
                for res in crawled_resources:
                    endpoint_rec = CrawledEndpoint(
                        scan_id=scan.id,
                        url=res.url,
                        path=res.path,
                        method=res.method,
                        status_code=res.status_code,
                        content_type=res.content_type,
                    )
                    endpoint_rec.forms = res.forms
                    endpoint_rec.params = res.params
                    db.session.add(endpoint_rec)

                scan.endpoints_discovered = len(crawled_resources)
                scan.forms_discovered = sum(len(res.forms) for res in crawled_resources)
                db.session.commit()
                log_event("SUCCESS", f"Crawler finished: {scan.endpoints_discovered} endpoints and {scan.forms_discovered} forms indexed.")

                # 3. Stage: Execute Enabled Security Modules
                scan_config = {
                    "scan_mode": scan.scan_mode,
                    "timeout": scan.request_timeout,
                    "auth": scan.auth_config,
                }

                all_findings_count = 0
                for mod_name in scan.enabled_modules:
                    # Check for cancellation before executing each module
                    db.session.refresh(scan)
                    if scan.status == "CANCELLED":
                        log_event("WARNING", f"Scan #{scan.id} was cancelled by operator.")
                        scan.completed_at = datetime.now(timezone.utc)
                        scan.duration_seconds = time.time() - start_perf
                        db.session.commit()
                        return

                    module_inst = get_module(mod_name, session=crawler.session, logger=log_event)
                    if not module_inst:
                        log_event("WARNING", f"Module '{mod_name}' is not registered; skipping.")
                        continue

                    log_event("INFO", f"Executing module: {module_inst.name} ({module_inst.owasp_category})")
                    module_findings = module_inst.run(
                        target_base_url=target_url,
                        crawled_resources=crawled_resources,
                        scan_config=scan_config
                    )

                    # Persist findings to database
                    for fdata in module_findings:
                        # Deduplicate within same scan
                        existing = Finding.query.filter_by(
                            scan_id=scan.id,
                            vuln_type=fdata.vuln_type,
                            endpoint=fdata.endpoint,
                            parameter=fdata.parameter
                        ).first()
                        if existing:
                            continue

                        finding_rec = Finding(
                            scan_id=scan.id,
                            vuln_type=fdata.vuln_type,
                            category=fdata.category,
                            cwe_id=fdata.cwe_id,
                            cvss_score=fdata.cvss_score,
                            severity=fdata.severity,
                            confidence=fdata.confidence,
                            status=fdata.status,
                            endpoint=fdata.endpoint,
                            parameter=fdata.parameter,
                            http_method=fdata.http_method,
                            evidence=fdata.evidence,
                            explanation=fdata.explanation,
                            remediation=fdata.remediation,
                            manual_verification_steps=fdata.manual_verification_steps
                        )
                        db.session.add(finding_rec)
                        all_findings_count += 1

                    db.session.commit()

                # 4. Finalize Scan Metrics
                scan.recalculate_counts()
                scan.status = "COMPLETED"
                scan.completed_at = datetime.now(timezone.utc)
                scan.duration_seconds = time.time() - start_perf
                db.session.commit()

                log_event("SUCCESS", f"Scan completed in {round(scan.duration_seconds, 2)}s. Total findings recorded: {scan.total_findings}")

                # 5. Automatically pre-generate reports
                try:
                    SecurityReportGenerator.generate_pdf_report(scan)
                    log_event("INFO", "Executive PDF report generated successfully.")
                except Exception as rep_err:
                    log_event("WARNING", f"Report generation warning: {str(rep_err)}")

            except Exception as e:
                db.session.rollback()
                scan.status = "FAILED"
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
                log_event("ERROR", f"Scan terminated with fatal error: {str(e)}")
