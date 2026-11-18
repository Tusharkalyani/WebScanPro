from flask import Blueprint, render_template, request, flash, redirect, url_for
from webscanpro import db
from webscanpro.models.finding import Finding
from webscanpro.models.scan import Scan
from webscanpro.models.target import Target

vuln_bp = Blueprint("vulnerabilities", __name__)

@vuln_bp.route("/")
def index():
    severity = request.args.get("severity")
    status = request.args.get("status")
    category = request.args.get("category")
    search_q = request.args.get("q", "").strip()
    target_id = request.args.get("target_id", type=int)

    query = Finding.query

    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status)
    if category:
        query = query.filter(Finding.category == category)
    if target_id:
        query = query.join(Scan).filter(Scan.target_id == target_id)
    if search_q:
        query = query.filter(
            (Finding.vuln_type.ilike(f"%{search_q}%")) |
            (Finding.endpoint.ilike(f"%{search_q}%")) |
            (Finding.parameter.ilike(f"%{search_q}%")) |
            (Finding.explanation.ilike(f"%{search_q}%"))
        )

    findings = query.order_by(
        db.case(
            {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
            value=Finding.severity,
            else_=6
        ).asc(),
        Finding.id.desc()
    ).all()

    targets = Target.query.order_by(Target.name.asc()).all()

    # Get distinct categories for filter dropdown
    categories = [c[0] for c in db.session.query(Finding.category).distinct().all()]

    return render_template(
        "vulnerabilities.html",
        findings=findings,
        targets=targets,
        categories=categories,
        selected_severity=severity,
        selected_status=status,
        selected_category=category,
        selected_target=target_id,
        search_query=search_q
    )

@vuln_bp.route("/<int:finding_id>")
def detail(finding_id):
    finding = db.session.get(Finding, finding_id)
    if not finding:
        flash("Finding not found.", "warning")
        return redirect(url_for("vulnerabilities.index"))

    return render_template("vulnerability_detail.html", finding=finding)
