from flask import Blueprint, render_template
from sqlalchemy import func
from webscanpro import db
from webscanpro.models.scan import Scan
from webscanpro.models.finding import Finding
from webscanpro.models.target import Target
from webscanpro.lab.health_checker import LabHealthChecker

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    # Overall summary metrics
    total_scans = Scan.query.count()
    completed_scans = Scan.query.filter_by(status="COMPLETED").count()
    running_scans = Scan.query.filter_by(status="RUNNING").count()
    total_targets = Target.query.count()

    total_findings = Finding.query.count()
    critical_findings = Finding.query.filter_by(severity="CRITICAL").count()
    high_findings = Finding.query.filter_by(severity="HIGH").count()
    medium_findings = Finding.query.filter_by(severity="MEDIUM").count()
    low_findings = Finding.query.filter_by(severity="LOW").count()
    info_findings = Finding.query.filter_by(severity="INFO").count()

    # Recent scans
    recent_scans = Scan.query.order_by(Scan.id.desc()).limit(6).all()

    # Top vulnerable endpoints
    top_endpoints = db.session.query(
        Finding.endpoint,
        func.count(Finding.id).label("count")
    ).group_by(Finding.endpoint).order_by(func.count(Finding.id).desc()).limit(5).all()

    # Lab environments health summary
    lab_statuses = LabHealthChecker.check_lab_status()

    # Calculate Security Posture Score
    # Baseline: 100 points, deducted based on active findings
    deductions = (critical_findings * 25) + (high_findings * 12) + (medium_findings * 5) + (low_findings * 1)
    if total_findings == 0:
        security_score = 100
        score_grade = "A+"
        risk_level = "SECURE"
    else:
        security_score = max(18, 100 - deductions)
        if security_score >= 90:
            score_grade = "A"
            risk_level = "MINIMAL RISK"
        elif security_score >= 75:
            score_grade = "B"
            risk_level = "LOW RISK"
        elif security_score >= 60:
            score_grade = "C"
            risk_level = "MODERATE RISK"
        elif security_score >= 45:
            score_grade = "D"
            risk_level = "ELEVATED RISK"
        else:
            score_grade = "F"
            risk_level = "CRITICAL RISK"

    # Recent scans trend data for Chart.js
    trend_scans = Scan.query.order_by(Scan.id.asc()).limit(8).all()
    trend_labels = [f"#{s.id}" for s in trend_scans]
    trend_findings_count = [s.total_findings for s in trend_scans]
    trend_critical_count = [s.count_critical or 0 for s in trend_scans]
    trend_high_count = [s.count_high or 0 for s in trend_scans]

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        completed_scans=completed_scans,
        running_scans=running_scans,
        total_targets=total_targets,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        medium_findings=medium_findings,
        low_findings=low_findings,
        info_findings=info_findings,
        recent_scans=recent_scans,
        top_endpoints=top_endpoints,
        lab_statuses=lab_statuses,
        security_score=security_score,
        score_grade=score_grade,
        risk_level=risk_level,
        trend_labels=trend_labels,
        trend_findings_count=trend_findings_count,
        trend_critical_count=trend_critical_count,
        trend_high_count=trend_high_count,
    )
