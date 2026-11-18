from datetime import datetime, timezone
from webscanpro import db

class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    base_url = db.Column(db.String(512), nullable=False, unique=True)
    host = db.Column(db.String(256), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    is_authorized = db.Column(db.Boolean, default=False, nullable=False)
    authorization_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    scans = db.relationship("Scan", backref="target", lazy="dynamic", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "base_url": self.base_url,
            "host": self.host,
            "port": self.port,
            "is_authorized": self.is_authorized,
            "authorization_notes": self.authorization_notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "scans_count": self.scans.count(),
        }
