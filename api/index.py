import os
import sys
import urllib.parse
from pathlib import Path
from flask import send_from_directory, redirect, abort

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

    Captures the real requested path from either:
    1. Vercel rewrite query parameter: __vercel_path=/$1
    2. Vercel routing headers: HTTP_X_MATCHED_PATH / HTTP_X_FORWARDED_URI / REQUEST_URI
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get("QUERY_STRING", "")
        qs = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        vercel_path = qs.pop("__vercel_path", [None])[0]

        if vercel_path:
            # Reconstruct clean QUERY_STRING without internal __vercel_path parameter
            environ["QUERY_STRING"] = urllib.parse.urlencode(qs, doseq=True)
            clean_path = "/" + vercel_path.lstrip("/").split("?")[0]
            environ["PATH_INFO"] = clean_path
        else:
            # Fallback to headers
            matched_path = (
                environ.get("HTTP_X_MATCHED_PATH")
                or environ.get("HTTP_X_VERCEL_MATCHED_PATH")
                or environ.get("HTTP_X_FORWARDED_URI")
                or environ.get("REQUEST_URI")
            )
            current_path = environ.get("PATH_INFO", "")
            if current_path in ("/api/index.py", "/api/index", "/api", "") or current_path.startswith("/api/index"):
                if matched_path and not matched_path.startswith("/api/index"):
                    environ["PATH_INFO"] = "/" + matched_path.lstrip("/").split("?")[0]
                else:
                    environ["PATH_INFO"] = "/"
            elif matched_path and not matched_path.startswith("/api/index"):
                environ["PATH_INFO"] = "/" + matched_path.lstrip("/").split("?")[0]

        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathFixer(app.wsgi_app)

# Fallback route for direct access to entrypoint paths
@app.route("/api/index")
@app.route("/api/index.py")
def vercel_entrypoint_fallback():
    return redirect("/")

# Static asset serving fallbacks for serverless environments
@app.route("/static/<path:filename>")
def serve_static(filename):
    for folder in [
        PROJECT_ROOT / "public" / "static",
        PROJECT_ROOT / "webscanpro" / "static",
    ]:
        if (folder / filename).is_file():
            return send_from_directory(folder, filename)
    abort(404)

@app.route("/css/<path:filename>")
def serve_css(filename):
    for folder in [
        PROJECT_ROOT / "public" / "css",
        PROJECT_ROOT / "webscanpro" / "static" / "css",
    ]:
        if (folder / filename).is_file():
            return send_from_directory(folder, filename)
    abort(404)

@app.route("/js/<path:filename>")
def serve_js(filename):
    for folder in [
        PROJECT_ROOT / "public" / "js",
        PROJECT_ROOT / "webscanpro" / "static" / "js",
    ]:
        if (folder / filename).is_file():
            return send_from_directory(folder, filename)
    abort(404)

with app.app_context():
    db.create_all()
    # On serverless cold start in /tmp, seed sample data so the dashboard displays full analytics immediately
    try:
        if not Scan.query.first():
            seed_demo_data()
    except Exception as e:
        print(f"Initial seed warning: {e}")
