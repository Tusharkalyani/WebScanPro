import os
from pathlib import Path
from flask import Blueprint, render_template, send_file, flash, redirect, url_for, abort
from webscanpro import db
from webscanpro.models.scan import Scan
from webscanpro.models.finding import Finding
from webscanpro.core.reporter import SecurityReportGenerator

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/")
def index():
    scans = Scan.query.filter_by(status="COMPLETED").order_by(Scan.id.desc()).all()
    return render_template("reports.html", scans=scans)

@reports_bp.route("/scan/<int:scan_id>/pdf")
def download_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for("reports.index"))

    pdf_path, _ = SecurityReportGenerator.get_report_paths(scan.id)
    if not pdf_path.exists():
        # Generate on the fly
        SecurityReportGenerator.generate_pdf_report(scan)

    return send_file(
        str(pdf_path),
        as_attachment=True,
        download_name=f"WebScanPro_Report_Scan_{scan.id}.pdf",
        mimetype="application/pdf"
    )

@reports_bp.route("/scan/<int:scan_id>/html")
def view_html(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        abort(404)

    findings = scan.findings.order_by(
        db.case(
            {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
            value=Finding.severity,
            else_=6
        ).asc(),
        Finding.id.asc()
    ).all()

    return render_template("report_template.html", scan=scan, findings=findings)
