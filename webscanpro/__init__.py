import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import config

db = SQLAlchemy()

def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure reports directory exists
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)

    # Register blueprints
    from webscanpro.routes.dashboard import dashboard_bp
    from webscanpro.routes.scan import scan_bp
    from webscanpro.routes.vulnerabilities import vuln_bp
    from webscanpro.routes.reports import reports_bp
    from webscanpro.routes.settings import settings_bp
    from webscanpro.routes.api import api_bp
    from webscanpro.lab.mock_app import mock_lab_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp, url_prefix="/scans")
    app.register_blueprint(vuln_bp, url_prefix="/vulnerabilities")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(mock_lab_bp, url_prefix="/mock-lab")

    with app.app_context():
        # Import models so tables are registered
        import webscanpro.models  # noqa
        db.create_all()

    return app
