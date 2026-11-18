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

with app.app_context():
    db.create_all()
    # On serverless cold start in /tmp, seed sample data so the dashboard displays full analytics immediately
    try:
        if not Scan.query.first():
            seed_demo_data()
    except Exception as e:
        print(f"Initial seed warning: {e}")
