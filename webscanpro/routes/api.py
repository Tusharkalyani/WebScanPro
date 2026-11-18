from flask import Blueprint, jsonify, request
from webscanpro import db
from webscanpro.models.scan import Scan, ScanLog, CrawledEndpoint
from webscanpro.models.finding import Finding
from webscanpro.core.target_validator import TargetValidator, TargetValidationError
from webscanpro.lab.health_checker import LabHealthChecker

api_bp = Blueprint("api", __name__)

@api_bp.route("/scans/<int:scan_id>/status")
def scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Fetch last 30 logs
    since_log_id = request.args.get("since_log_id", type=int, default=0)
    logs_query = scan.logs.filter(ScanLog.id > since_log_id).order_by(ScanLog.id.asc()).limit(50)
    logs_data = [l.to_dict() for l in logs_query]

    # Calculate approximate progress %
    progress = 0
    if scan.status == "PENDING":
        progress = 5
    elif scan.status == "RUNNING":
        # Estimate based on crawled endpoints and findings
        base_progress = 20
        crawl_component = min(40, (scan.endpoints_discovered / max(1, scan.max_pages)) * 40)
        progress = int(base_progress + crawl_component + (20 if scan.endpoints_discovered > 0 else 0))
        progress = min(progress, 90)
    elif scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
        progress = 100

    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "progress": progress,
        "duration_seconds": round(scan.duration_seconds, 2) if scan.duration_seconds else 0,
        "total_requests": scan.total_requests_sent,
        "endpoints_count": scan.endpoints_discovered,
        "forms_count": scan.forms_discovered,
        "findings_by_severity": {
            "CRITICAL": scan.count_critical or 0,
            "HIGH": scan.count_high or 0,
            "MEDIUM": scan.count_medium or 0,
            "LOW": scan.count_low or 0,
            "INFO": scan.count_info or 0,
        },
        "total_findings": scan.total_findings,
        "new_logs": logs_data,
        "error_message": scan.error_message,
    })

@api_bp.route("/targets/validate", methods=["POST"])
def validate_target():
    data = request.get_json() or {}
    url = data.get("url", "")
    is_authorized = bool(data.get("is_authorized", False))

    try:
        val_result = TargetValidator.validate_target(url=url, is_explicitly_authorized=is_authorized)
        probe = TargetValidator.check_target_connectivity(url)
        return jsonify({
            "valid": True,
            "normalized_url": val_result["normalized_url"],
            "host": val_result["host"],
            "port": val_result["port"],
            "connectivity": probe
        })
    except TargetValidationError as e:
        return jsonify({"valid": False, "error": str(e)}), 400

@api_bp.route("/labs/health")
def labs_health():
    lab_key = request.args.get("lab")
    status = LabHealthChecker.check_lab_status(lab_key)
    return jsonify(status)

@api_bp.route("/scans/<int:scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
        return jsonify({"message": f"Scan is already {scan.status}"}), 200

    from datetime import datetime, timezone
    scan.status = "CANCELLED"
    scan.completed_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True, "message": f"Scan #{scan_id} marked as CANCELLED."})

