import json
from datetime import datetime, timezone
from webscanpro import db

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    status = db.Column(db.String(32), default="PENDING", nullable=False)  # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    scan_mode = db.Column(db.String(32), default="STANDARD", nullable=False)  # QUICK, STANDARD, DEEP
    
    # Timing
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, default=0.0)

    # Configuration options
    max_depth = db.Column(db.Integer, default=3)
    max_pages = db.Column(db.Integer, default=30)
    request_timeout = db.Column(db.Integer, default=5)
    rate_limit_delay = db.Column(db.Float, default=0.05)
    max_requests = db.Column(db.Integer, default=150)
    enabled_modules_json = db.Column(db.Text, default='["headers", "sqli", "xss", "auth", "idor"]')
    auth_config_json = db.Column(db.Text, default='{}')

    # Metrics
    total_requests_sent = db.Column(db.Integer, default=0)
    endpoints_discovered = db.Column(db.Integer, default=0)
    forms_discovered = db.Column(db.Integer, default=0)
    
    # Severity Counters
    count_critical = db.Column(db.Integer, default=0)
    count_high = db.Column(db.Integer, default=0)
    count_medium = db.Column(db.Integer, default=0)
    count_low = db.Column(db.Integer, default=0)
    count_info = db.Column(db.Integer, default=0)
    
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    findings = db.relationship("Finding", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    endpoints = db.relationship("CrawledEndpoint", backref="scan", lazy="dynamic", cascade="all, delete-orphan")
    logs = db.relationship("ScanLog", backref="scan", lazy="dynamic", cascade="all, delete-orphan", order_by="ScanLog.id.asc()")

    @property
    def enabled_modules(self):
        try:
            return json.loads(self.enabled_modules_json) if self.enabled_modules_json else []
        except Exception:
            return []

    @enabled_modules.setter
    def enabled_modules(self, value):
        self.enabled_modules_json = json.dumps(value)

    @property
    def auth_config(self):
        try:
            return json.loads(self.auth_config_json) if self.auth_config_json else {}
        except Exception:
            return {}

    @auth_config.setter
    def auth_config(self, value):
        self.auth_config_json = json.dumps(value)

    @property
    def total_findings(self):
        return (
            (self.count_critical or 0)
            + (self.count_high or 0)
            + (self.count_medium or 0)
            + (self.count_low or 0)
            + (self.count_info or 0)
        )

    def recalculate_counts(self):
        from webscanpro.models.finding import Finding
        self.count_critical = self.findings.filter_by(severity="CRITICAL").count()
        self.count_high = self.findings.filter_by(severity="HIGH").count()
        self.count_medium = self.findings.filter_by(severity="MEDIUM").count()
        self.count_low = self.findings.filter_by(severity="LOW").count()
        self.count_info = self.findings.filter_by(severity="INFO").count()

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_url": self.target.base_url if self.target else None,
            "target_name": self.target.name if self.target else None,
            "status": self.status,
            "scan_mode": self.scan_mode,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2) if self.duration_seconds else 0,
            "total_requests_sent": self.total_requests_sent,
            "endpoints_discovered": self.endpoints_discovered,
            "forms_discovered": self.forms_discovered,
            "total_findings": self.total_findings,
            "findings_by_severity": {
                "CRITICAL": self.count_critical,
                "HIGH": self.count_high,
                "MEDIUM": self.count_medium,
                "LOW": self.count_low,
                "INFO": self.count_info,
            },
            "enabled_modules": self.enabled_modules,
            "error_message": self.error_message,
        }


class CrawledEndpoint(db.Model):
    __tablename__ = "crawled_endpoints"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    url = db.Column(db.String(1024), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    method = db.Column(db.String(16), default="GET", nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    content_type = db.Column(db.String(128), nullable=True)
    forms_json = db.Column(db.Text, default='[]')
    params_json = db.Column(db.Text, default='[]')
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def forms(self):
        try:
            return json.loads(self.forms_json) if self.forms_json else []
        except Exception:
            return []

    @forms.setter
    def forms(self, value):
        self.forms_json = json.dumps(value)

    @property
    def params(self):
        try:
            return json.loads(self.params_json) if self.params_json else []
        except Exception:
            return []

    @params.setter
    def params(self, value):
        self.params_json = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "forms": self.forms,
            "params": self.params,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    level = db.Column(db.String(16), default="INFO")  # INFO, WARNING, ERROR, SUCCESS
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.strftime("%H:%M:%S") if self.timestamp else "",
        }
