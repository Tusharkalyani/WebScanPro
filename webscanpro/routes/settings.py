from flask import Blueprint, render_template, request, flash, redirect, url_for
from webscanpro.models.target import Target
from webscanpro.lab.health_checker import LabHealthChecker
from config import Config

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/")
def index():
    targets = Target.query.order_by(Target.created_at.desc()).all()
    lab_statuses = LabHealthChecker.check_lab_status()

    return render_template(
        "settings.html",
        targets=targets,
        lab_statuses=lab_statuses,
        allowed_hosts=Config.ALLOWED_TARGET_HOSTS,
        config=Config
    )

@settings_bp.route("/documentation")
def documentation():
    return render_template("documentation.html")
