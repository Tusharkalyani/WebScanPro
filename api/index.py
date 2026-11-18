import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for Vercel Serverless Function imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from webscanpro import create_app, db
from webscanpro.core.sample_data import seed_demo_data
from webscanpro.models import Scan

app = create_app()

class VercelPathFixer:
    """WSGI middleware to resolve PATH_INFO when deployed as a Vercel Serverless Function.

    When Vercel processes rewrites (e.g. /(.*) -> /api/index), Vercel invokes
    the serverless function with PATH_INFO set to the serverless function destination
    (/api/index or /api/index.py) while passing the actual browser path in
    HTTP_X_MATCHED_PATH / HTTP_X_VERCEL_MATCHED_PATH.
    This middleware restores the original path so Flask's URL routing matches correctly.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched_path = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_VERCEL_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("REQUEST_URI")
        )
        current_path = environ.get("PATH_INFO", "")
        if current_path in ("/api/index.py", "/api/index", "/api", "") or current_path.startswith("/api/index"):
            if matched_path and not matched_path.startswith("/api/index"):
                environ["PATH_INFO"] = matched_path.split("?")[0]
            else:
                environ["PATH_INFO"] = "/"
        elif matched_path and not matched_path.startswith("/api/index"):
            environ["PATH_INFO"] = matched_path.split("?")[0]

        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathFixer(app.wsgi_app)

# Fallback route in case direct access reaches Flask
@app.route("/api/index")
@app.route("/api/index.py")
def vercel_entrypoint_fallback():
    from flask import redirect
    return redirect("/")

with app.app_context():
    db.create_all()
    # On serverless cold start in /tmp, seed sample data so the dashboard displays full analytics immediately
    try:
        if not Scan.query.first():
            seed_demo_data()
    except Exception as e:
        print(f"Initial seed warning: {e}")
