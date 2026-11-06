import os
import json
import csv
import io

from datetime import datetime

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    Response
)

# ==========================================================
# FLASK CONFIGURATION
# ==========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "cloudsec-development-secret-change-this"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")

# ==========================================================
# AWS SCANNER IMPORTS
# ==========================================================

from aws.iam_scanner import scan_iam
from aws.ec2_scanner import scan_ec2
from aws.s3_scanner import scan_s3
from aws.vpc_scanner import scan_vpc


SCANNERS = {
    "IAM": scan_iam,
    "EC2": scan_ec2,
    "S3": scan_s3,
    "VPC": scan_vpc
}

ALL_SERVICES = ["IAM", "EC2", "S3", "VPC"]

# ==========================================================
# DEFAULT SETTINGS
# ==========================================================

DEFAULT_SETTINGS = {
    "services": ALL_SERVICES.copy(),
    "severity_level": "INFO",
    "refresh_interval": 0
}


def load_settings():

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as file:
            saved_settings = json.load(file)

        if not isinstance(saved_settings, dict):
            saved_settings = {}

        settings = {
            **DEFAULT_SETTINGS,
            **saved_settings
        }

        selected = settings.get("services", ALL_SERVICES)

        if not isinstance(selected, list):
            selected = ALL_SERVICES.copy()

        settings["services"] = [
            service.upper()
            for service in selected
            if isinstance(service, str)
            and service.upper() in ALL_SERVICES
        ]

        allowed_severities = [
            "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        ]

        severity = str(
            settings.get("severity_level", "INFO")
        ).upper()

        if severity not in allowed_severities:
            severity = "INFO"

        settings["severity_level"] = severity

        try:
            refresh_interval = int(
                settings.get("refresh_interval", 0)
            )
        except (ValueError, TypeError):
            refresh_interval = 0

        if refresh_interval not in [0, 30, 60, 300]:
            refresh_interval = 0

        settings["refresh_interval"] = refresh_interval

        return settings

    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return DEFAULT_SETTINGS.copy()


def save_settings(settings_data):

    with open(SETTINGS_FILE, "w", encoding="utf-8") as file:
        json.dump(settings_data, file, indent=4)


# ==========================================================
# SCAN CACHE
# ==========================================================

latest_scan_results = []

last_scan_time = None

scan_errors = []

# True when at least one selected scanner completed.
scan_completed = False

# Individual service scan statuses.
service_status = {
    service: "NOT_SCANNED"
    for service in ALL_SERVICES
}

# Possible service statuses:
# NOT_SELECTED
# NOT_SCANNED
# SCAN_FAILED
# HEALTHY
# ISSUES


# ==========================================================
# SECURITY SCORE
# ==========================================================

def calculate_security_score(findings):

    if not scan_completed:
        return None

    risk_weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
    }

    total_risk = sum(
        risk_weights.get(
            str(finding.get("severity", "INFO")).upper(),
            0
        )
        for finding in findings
    )

    # Gradual scoring: more findings lower the score,
    # without reaching zero too quickly.
    score = 100 / (1 + total_risk / 100)

    return round(score)


# ==========================================================
# RUN AWS SECURITY SCAN
# ==========================================================

def run_security_scan():

    global latest_scan_results
    global last_scan_time
    global scan_errors
    global scan_completed
    global service_status

    findings = []
    errors = []

    current_settings = load_settings()
    selected_services = current_settings["services"]

    # Reset individual service statuses for this scan.
    service_status = {
        service: (
            "NOT_SELECTED"
            if service not in selected_services
            else "NOT_SCANNED"
        )
        for service in ALL_SERVICES
    }

    if not selected_services:

        scan_errors = [
            "No AWS services selected in Settings."
        ]

        scan_completed = False

        flash(
            "Select at least one AWS service in Settings before scanning.",
            "warning"
        )

        return False

    successful_services = []

    for service in selected_services:

        scanner = SCANNERS.get(service)

        if scanner is None:

            errors.append(
                f"{service}: Scanner is not configured."
            )

            service_status[service] = "SCAN_FAILED"
            continue

        try:

            service_findings = scanner()

            if service_findings is None:
                service_findings = []

            if not isinstance(service_findings, list):

                raise TypeError(
                    "Scanner must return a list of findings."
                )

            valid_findings = []

            for original_finding in service_findings:

                if not isinstance(original_finding, dict):
                    continue

                finding = original_finding.copy()

                # Always use the actual scanner service name.
                finding["service"] = service

                finding["severity"] = str(
                    finding.get("severity", "INFO")
                ).upper()

                if finding["severity"] not in [
                    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
                ]:
                    finding["severity"] = "INFO"

                finding.setdefault(
                    "issue",
                    "Security finding"
                )

                finding.setdefault(
                    "resource",
                    "N/A"
                )

                valid_findings.append(finding)

            findings.extend(valid_findings)

            successful_services.append(service)

            if valid_findings:
                service_status[service] = "ISSUES"
            else:
                service_status[service] = "HEALTHY"

        except Exception as error:

            errors.append(
                f"{service}: {str(error)}"
            )

            service_status[service] = "SCAN_FAILED"

    # Save the latest scan results.
    latest_scan_results = findings

    last_scan_time = datetime.now().strftime(
        "%d-%m-%Y %I:%M:%S %p"
    )

    scan_errors = errors

    # A scan is completed if at least one scanner succeeds.
    scan_completed = len(successful_services) > 0

    return scan_completed


# ==========================================================
# SERVICE FINDINGS
# ==========================================================

def get_service_findings(service):

    return [
        finding
        for finding in latest_scan_results
        if finding.get("service", "").upper() == service.upper()
    ]


# ==========================================================
# DASHBOARD
# ==========================================================

@app.route("/")
def dashboard():

    current_settings = load_settings()

    selected_services = current_settings["services"]

    service_findings = {
        service: get_service_findings(service)
        for service in ALL_SERVICES
    }

    security_score = calculate_security_score(
        latest_scan_results
    )

    return render_template(
        "dashboard.html",

        findings=latest_scan_results,

        service_findings=service_findings,

        service_status=service_status,

        selected_services=selected_services,

        settings=current_settings,

        security_score=security_score,

        total_findings=len(latest_scan_results),

        last_scan_time=last_scan_time,

        scan_completed=scan_completed,

        scan_errors=scan_errors
    )


# ==========================================================
# LOGIN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        flash(
            "Login authentication is not configured.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ==========================================================
# AWS SCAN
# ==========================================================

@app.route("/scan", methods=["GET", "POST"])
def scan():

    success = run_security_scan()

    if success:

        if scan_errors:
            flash(
                "Scan partially completed. Check scanner warnings.",
                "warning"
            )
        else:
            flash(
                "AWS security scan completed successfully!",
                "success"
            )

    else:

        flash(
            "Scan could not complete. Check scanner errors.",
            "danger"
        )

    return redirect(url_for("dashboard"))


# ==========================================================
# REPORTS
# ==========================================================

@app.route("/reports")
def reports():

    findings = latest_scan_results

    total_findings = len(findings)

    critical_count = sum(
        1 for finding in findings
        if finding.get("severity") == "CRITICAL"
    )

    high_count = sum(
        1 for finding in findings
        if finding.get("severity") == "HIGH"
    )

    medium_count = sum(
        1 for finding in findings
        if finding.get("severity") == "MEDIUM"
    )

    low_count = sum(
        1 for finding in findings
        if finding.get("severity") == "LOW"
    )

    info_count = sum(
        1 for finding in findings
        if finding.get("severity") == "INFO"
    )

    service_counts = {
        service: 0
        for service in ALL_SERVICES
    }

    for finding in findings:

        service = finding.get("service", "UNKNOWN")

        if service in service_counts:
            service_counts[service] += 1

    security_score = calculate_security_score(findings)

    return render_template(
        "reports.html",

        findings=findings,

        total_findings=total_findings,

        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,

        service_counts=service_counts,

        security_score=security_score,

        last_scan_time=last_scan_time,

        scan_completed=scan_completed,

        scan_errors=scan_errors
    )


# ==========================================================
# EXPORT REPORT AS CSV
# ==========================================================

@app.route("/reports/export")
def export_report():

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Service",
        "Resource",
        "Issue",
        "Severity"
    ])

    for finding in latest_scan_results:

        resource = (
            finding.get("resource")
            or finding.get("instance_id")
            or finding.get("bucket_name")
            or finding.get("bucket")
            or finding.get("vpc_id")
            or finding.get("user")
            or "N/A"
        )

        writer.writerow([
            finding.get("service", "N/A"),
            resource,
            finding.get("issue", "N/A"),
            finding.get("severity", "INFO")
        ])

    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=cloud_security_report.csv"
        }
    )


# ==========================================================
# IAM
# ==========================================================

@app.route("/iam")
def iam():

    findings = get_service_findings("IAM")

    return render_template(
        "iam.html",
        findings=findings,
        service_findings=findings,
        last_scan_time=last_scan_time,
        scan_completed=scan_completed
    )


# ==========================================================
# EC2
# ==========================================================

@app.route("/ec2")
def ec2():

    findings = get_service_findings("EC2")

    return render_template(
        "ec2.html",
        findings=findings,
        service_findings=findings,
        last_scan_time=last_scan_time,
        scan_completed=scan_completed
    )


# ==========================================================
# S3
# ==========================================================

@app.route("/s3")
def s3():

    findings = get_service_findings("S3")

    return render_template(
        "s3.html",
        findings=findings,
        service_findings=findings,
        last_scan_time=last_scan_time,
        scan_completed=scan_completed
    )


# ==========================================================
# VPC
# ==========================================================

@app.route("/vpc")
def vpc():

    findings = get_service_findings("VPC")

    return render_template(
        "vpc.html",
        findings=findings,
        service_findings=findings,
        last_scan_time=last_scan_time,
        scan_completed=scan_completed
    )


# ==========================================================
# SETTINGS
# ==========================================================

@app.route("/settings", methods=["GET", "POST"])
def settings():

    current_settings = load_settings()

    account = {
        "username": app.config.get(
            "ADMIN_USERNAME",
            "Administrator"
        ),

        "email": app.config.get(
            "ADMIN_EMAIL",
            "Not configured"
        ),

        "created_at": app.config.get(
            "ACCOUNT_CREATED_AT",
            "Not available"
        )
    }

    if request.method == "POST":

        action = request.form.get("action")

        # SAVE SETTINGS
        if action == "save_settings":

            services = [
                service
                for service in request.form.getlist("services")
                if service.upper() in ALL_SERVICES
            ]

            severity = request.form.get(
                "severity_level",
                "INFO"
            ).upper()

            allowed_severities = [
                "INFO",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]

            if severity not in allowed_severities:
                severity = "INFO"

            try:

                refresh_interval = int(
                    request.form.get("refresh_interval", 0)
                )

            except (ValueError, TypeError):

                refresh_interval = 0

            if refresh_interval not in [0, 30, 60, 300]:
                refresh_interval = 0

            current_settings = {
                "services": services,
                "severity_level": severity,
                "refresh_interval": refresh_interval
            }

            save_settings(current_settings)

            flash(
                "Settings saved successfully!",
                "success"
            )

        # RESET SETTINGS
        elif action == "reset_settings":

            current_settings = {
                "services": ALL_SERVICES.copy(),
                "severity_level": "INFO",
                "refresh_interval": 0
            }

            save_settings(current_settings)

            flash(
                "Settings restored to default!",
                "success"
            )

        # PASSWORD CHANGE
        elif action == "change_password":

            flash(
                "Password updating is not connected to "
                "your authentication system yet.",
                "warning"
            )

        return redirect(url_for("settings"))

    return render_template(
        "settings.html",
        settings=current_settings,
        account=account
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    return redirect(url_for("login"))


# ==========================================================
# APPLICATION START
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )