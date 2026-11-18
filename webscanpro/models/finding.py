from datetime import datetime, timezone
from webscanpro import db

class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    
    # Core classification
    vuln_type = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(128), nullable=False)  # OWASP category
    cwe_id = db.Column(db.String(32), default="CWE-Other")
    cvss_score = db.Column(db.Float, default=0.0)
    
    # Severity & Confidence
    severity = db.Column(db.String(16), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = db.Column(db.String(16), nullable=False)  # CONFIRMED, LIKELY, SUSPECTED
    status = db.Column(db.String(32), default="Potential Finding", nullable=False)  # Confirmed Finding, Potential Finding, Passed, Error, Not Tested

    # Target location
    endpoint = db.Column(db.String(1024), nullable=False)
    parameter = db.Column(db.String(128), default="N/A", nullable=False)
    http_method = db.Column(db.String(16), default="GET", nullable=False)
    
    # Technical Details
    evidence = db.Column(db.Text, nullable=False)  # Request/response excerpts, reflection markers, header extracts
    explanation = db.Column(db.Text, nullable=False)  # Impact, technical cause
    remediation = db.Column(db.Text, nullable=False)  # Actionable mitigation guidelines
    manual_verification_steps = db.Column(db.Text, nullable=True)  # How a human analyst can safely verify

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def severity_badge_class(self):
        mapping = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
            "INFO": "badge-info",
        }
        return mapping.get(self.severity, "badge-secondary")

    @property
    def confidence_badge_class(self):
        mapping = {
            "CONFIRMED": "badge-confirmed",
            "LIKELY": "badge-likely",
            "SUSPECTED": "badge-suspected",
        }
        return mapping.get(self.confidence, "badge-secondary")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "vuln_type": self.vuln_type,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "http_method": self.http_method,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "manual_verification_steps": self.manual_verification_steps,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
