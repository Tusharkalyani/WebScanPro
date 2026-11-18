import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from webscanpro import db
from webscanpro.models.scan import Scan, CrawledEndpoint, ScanLog
from webscanpro.models.target import Target
from webscanpro.models.finding import Finding
from webscanpro.core.target_validator import TargetValidator, TargetValidationError
from webscanpro.core.engine import ScanEngine
from config import Config

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/")
def history():
    target_filter = request.args.get("target_id", type=int)
    status_filter = request.args.get("status")

    query = Scan.query
    if target_filter:
        query = query.filter_by(target_id=target_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)

    scans = query.order_by(Scan.id.desc()).all()
    targets = Target.query.order_by(Target.name.asc()).all()

    return render_template(
        "scan_history.html",
        scans=scans,
        targets=targets,
        selected_target=target_filter,
        selected_status=status_filter
    )

@scan_bp.route("/new", methods=["GET", "POST"])
def new_scan():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        target_name = request.form.get("target_name", "").strip() or target_url
        is_authorized = bool(request.form.get("is_authorized"))
        scan_mode = request.form.get("scan_mode", "STANDARD")
        
        # Security validation
        try:
            val_result = TargetValidator.validate_target(
                url=target_url,
                is_explicitly_authorized=is_authorized
            )
        except TargetValidationError as err:
            flash(str(err), "danger")
            return render_template("scan_new.html", presets=Config.LAB_PRESETS, form_data=request.form)

        # Module selections
        selected_modules = request.form.getlist("modules")
        if not selected_modules:
            selected_modules = ["headers", "sqli", "xss", "auth", "idor"]

        # Depth and budget configurations
        max_depth = int(request.form.get("max_depth", 3))
        max_pages = int(request.form.get("max_pages", 30))
        rate_limit = float(request.form.get("rate_limit", 0.05))
        timeout = int(request.form.get("timeout", 5))

        # Authentication config
        auth_cookie_name = request.form.get("auth_cookie_name", "").strip()
        auth_session_token = request.form.get("auth_session_token", "").strip()
        auth_protected_url = request.form.get("auth_protected_url", "").strip()
        auth_logout_url = request.form.get("auth_logout_url", "").strip()

        # IDOR Two-account config
        idor_token_a = request.form.get("idor_token_a", "").strip()
        idor_resource_a = request.form.get("idor_resource_a", "").strip()
        idor_token_b = request.form.get("idor_token_b", "").strip()

        auth_config = {}
        if auth_session_token:
            auth_config["cookie_name"] = auth_cookie_name or "session"
            auth_config["session_token"] = auth_session_token
            auth_config["protected_url"] = auth_protected_url
            auth_config["logout_url"] = auth_logout_url

        if idor_token_a and idor_token_b:
            auth_config["account_a"] = {"token": idor_token_a, "resource_url": idor_resource_a}
            auth_config["account_b"] = {"token": idor_token_b}

        # Look up or create Target
        normalized_url = val_result["normalized_url"]
        target = Target.query.filter_by(base_url=normalized_url).first()
        if not target:
            target = Target(
                name=target_name,
                base_url=normalized_url,
                host=val_result["host"],
                port=val_result["port"],
                is_authorized=True,
                authorization_notes="Authorized by local operator via WebScanPro confirmation."
            )
            db.session.add(target)
            db.session.commit()

        # Create Scan record
        scan = Scan(
            target_id=target.id,
            status="PENDING",
            scan_mode=scan_mode,
            max_depth=max_depth,
            max_pages=max_pages,
            request_timeout=timeout,
            rate_limit_delay=rate_limit,
            enabled_modules_json=json.dumps(selected_modules),
            auth_config_json=json.dumps(auth_config)
        )
        db.session.add(scan)
        db.session.commit()

        # Launch scanning engine asynchronously in background thread
        app_obj = current_app._get_current_object()
        ScanEngine.start_scan_async(app_obj, scan.id)

        flash(f"Scan #{scan.id} initialized successfully against {normalized_url}!", "success")
        return redirect(url_for("scan.detail", scan_id=scan.id))

    return render_template("scan_new.html", presets=Config.LAB_PRESETS, form_data={})

@scan_bp.route("/<int:scan_id>")
def detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for("scan.history"))

    findings = scan.findings.order_by(
        db.case(
            {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5},
            value=Finding.severity,
            else_=6
        ).asc()
    ).all()
    endpoints = scan.endpoints.order_by(CrawledEndpoint.id.asc()).all()
    logs = scan.logs.order_by(ScanLog.id.desc()).limit(100).all()

    return render_template(
        "scan_detail.html",
        scan=scan,
        findings=findings,
        endpoints=endpoints,
        logs=logs
    )

@scan_bp.route("/compare")
def compare():
    scan_id_1 = request.args.get("scan1", type=int)
    scan_id_2 = request.args.get("scan2", type=int)

    all_scans = Scan.query.order_by(Scan.id.desc()).all()

    scan1 = db.session.get(Scan, scan_id_1) if scan_id_1 else None
    scan2 = db.session.get(Scan, scan_id_2) if scan_id_2 else None

    diff_data = None
    if scan1 and scan2:
        # Compare findings
        f1_keys = {(f.vuln_type, f.endpoint, f.parameter): f for f in scan1.findings}
        f2_keys = {(f.vuln_type, f.endpoint, f.parameter): f for f in scan2.findings}

        persistent = [f2_keys[k] for k in f1_keys.keys() & f2_keys.keys()]
        new_in_scan2 = [f2_keys[k] for k in f2_keys.keys() - f1_keys.keys()]
        resolved_in_scan2 = [f1_keys[k] for k in f1_keys.keys() - f2_keys.keys()]

        diff_data = {
            "persistent": persistent,
            "new": new_in_scan2,
            "resolved": resolved_in_scan2,
            "count_persistent": len(persistent),
            "count_new": len(new_in_scan2),
            "count_resolved": len(resolved_in_scan2),
        }

    return render_template(
        "scan_compare.html",
        all_scans=all_scans,
        scan1=scan1,
        scan2=scan2,
        diff_data=diff_data
    )

@scan_bp.route("/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for("scan.history"))

    from webscanpro.core.reporter import SecurityReportGenerator
    pdf_path, html_path = SecurityReportGenerator.get_report_paths(scan.id)
    if pdf_path.exists():
        try:
            pdf_path.unlink()
        except Exception:
            pass
    if html_path.exists():
        try:
            html_path.unlink()
        except Exception:
            pass

    target_name = scan.target.name if scan.target else "Target"
    deleted_id = scan.id
    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan #{deleted_id} against {target_name} and all associated findings were successfully deleted.", "info")
    return redirect(url_for("scan.history"))

