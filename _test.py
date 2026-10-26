[1mdiff --git a/app.py b/app.py[m
[1mindex 8681840..fddb1a8 100644[m
[1m--- a/app.py[m
[1m+++ b/app.py[m
[36m@@ -1,17 +1,41 @@[m
 from flask import Flask, render_template,  redirect, url_for[m
[32m+[m[32mfrom aws.iam_scanner import scan_iam[m
 app = Flask(__name__)[m
 [m
 @app.route('/')[m
 def dashboard():[m
[31m-    return render_template('dashboard.html')[m
 [m
[32m+[m[32m    findings = scan_iam()[m
[32m+[m
[32m+[m[32m    iam_findings = [[m
[32m+[m[32m        finding for finding in findings[m
[32m+[m[32m        if finding["service"] == "IAM"[m
[32m+[m[32m    ][m
[32m+[m
[32m+[m[32m    if len(iam_findings) == 0:[m
[32m+[m[32m        security_score = 100[m
[32m+[m[32m    else:[m
[32m+[m[32m        security_score = max(0, 100 - (len(iam_findings) * 10))[m
[32m+[m
[32m+[m[32m    return render_template([m
[32m+[m[32m        'dashboard.html',[m
[32m+[m[32m        findings=findings,[m
[32m+[m[32m        iam_findings=iam_findings,[m
[32m+[m[32m        security_score=security_score[m
[32m+[m[32m    )[m
[32m+[m[41m    [m
 @app.route('/login')[m
 def login():[m
     return render_template('login.html')[m
 [m
 @app.route('/scan')[m
 def scan():[m
[31m-    return render_template('scan.html') [m
[32m+[m[32m    findings = scan_iam()[m
[32m+[m
[32m+[m[32m    return render_template([m
[32m+[m[32m        'scan.html',[m
[32m+[m[32m        findings=findings[m
[32m+[m[32m    )[m
 [m
 @app.route('/reports')[m
 def reports():[m
[1mdiff --git a/aws/iam_scanner.py b/aws/iam_scanner.py[m
[1mindex e69de29..60f0137 100644[m
[1m--- a/aws/iam_scanner.py[m
[1m+++ b/aws/iam_scanner.py[m
[36m@@ -0,0 +1,62 @@[m
[32m+[m[32mimport boto3[m
[32m+[m[32mfrom datetime import datetime, timezone[m
[32m+[m
[32m+[m
[32m+[m[32mdef scan_iam():[m
[32m+[m
[32m+[m[32m    iam = boto3.client("iam")[m
[32m+[m
[32m+[m[32m    findings = [][m
[32m+[m
[32m+[m[32m    response = iam.list_users()[m
[32m+[m
[32m+[m[32m    for user in response["Users"]:[m
[32m+[m
[32m+[m[32m        username = user["UserName"][m
[32m+[m
[32m+[m[32m        # -----------------------------[m
[32m+[m[32m        # Check MFA[m
[32m+[m[32m        # -----------------------------[m
[32m+[m
[32m+[m[32m        mfa_response = iam.list_mfa_devices([m
[32m+[m[32m            UserName=username[m
[32m+[m[32m        )[m
[32m+[m
[32m+[m[32m        if mfa_response["MFADevices"]:[m
[32m+[m
[32m+[m[32m            mfa_status = "ENABLED"[m
[32m+[m
[32m+[m[32m        else:[m
[32m+[m
[32m+[m[32m            mfa_status = "NOT ENABLED"[m
[32m+[m
[32m+[m[32m            findings.append({[m
[32m+[m[32m                "user": username,[m
[32m+[m[32m                "service": "IAM",[m
[32m+[m[32m                "issue": "MFA is not enabled",[m
[32m+[m[32m                "severity": "HIGH"[m
[32m+[m[32m            })[m
[32m+[m
[32m+[m[32m        # -----------------------------[m
[32m+[m[32m        # Check Access Keys[m
[32m+[m[32m        # -----------------------------[m
[32m+[m
[32m+[m[32m        keys_response = iam.list_access_keys([m
[32m+[m[32m            UserName=username[m
[32m+[m[32m        )[m
[32m+[m
[32m+[m[32m        for key in keys_response["AccessKeyMetadata"]:[m
[32m+[m
[32m+[m[32m            age = datetime.now(timezone.utc) - key["CreateDate"][m
[32m+[m
[32m+[m[32m            if key["Status"] == "Active" and age.days > 90:[m
[32m+[m
[32m+[m[32m                findings.append({[m
[32m+[m[32m                    "user": username,[m
[32m+[m[32m                    "service": "IAM",[m
[32m+[m[32m                    "issue": "Active access key is older than 90 days",[m
[32m+[m[32m                    "severity": "MEDIUM",[m
[32m+[m[32m                    "access_key": key["AccessKeyId"][m
[32m+[m[32m            })[m
[32m+[m
[32m+[m[32m    return findings[m
\ No newline at end of file[m
[1mdiff --git a/static/dashboard.css b/static/dashboard.css[m
[1mindex b96ff3b..ab867b1 100644[m
[1m--- a/static/dashboard.css[m
[1m+++ b/static/dashboard.css[m
[36m@@ -291,6 +291,8 @@[m [mbody {[m
 }[m
 [m
 [m
[32m+[m[32m/* ================= CARDS ================= */[m
[32m+[m
 /* ================= CARDS ================= */[m
 [m
 .cards {[m
[36m@@ -298,7 +300,7 @@[m [mbody {[m
     display: grid;[m
 [m
     grid-template-columns:[m
[31m-        repeat(5, minmax(170px, 1fr));[m
[32m+[m[32m        repeat(auto-fit, minmax(190px, 1fr));[m
 [m
     gap: 18px;[m
 [m
[36m@@ -379,43 +381,6 @@[m [mbody {[m
 }[m
 [m
 [m
[31m-/* ================= SERVICE COLORS ================= */[m
[31m-[m
[31m-.card.score {[m
[31m-[m
[31m-    border-top: 3px solid #3b82f6;[m
[31m-[m
[31m-}[m
[31m-[m
[31m-[m
[31m-.card.iam {[m
[31m-[m
[31m-    border-top: 3px solid #22c55e;[m
[31m-[m
[31m-}[m
[31m-[m
[31m-[m
[31m-.card.ec2 {[m
[31m-[m
[31m-    border-top: 3px solid #facc15;[m
[31m-[m
[31m-}[m
[31m-[m
[31m-[m
[31m-.card.s3 {[m
[31m-[m
[31m-    border-top: 3px solid #ef4444;[m
[31m-[m
[31m-}[m
[31m-[m
[31m-[m
[31m-.card.vpc {[m
[31m-[m
[31m-    border-top: 3px solid #38bdf8;[m
[31m-[m
[31m-}[m
[31m-[m
[31m-[m
 /* ================= STATUS COLORS ================= */[m
 [m
 .green {[m
[36m@@ -633,7 +598,7 @@[m [mtbody tr:hover {[m
     .cards {[m
 [m
         grid-template-columns:[m
[31m-            repeat(2, 1fr);[m
[32m+[m[32m            repeat(2, minmax(0, 1fr));[m
 [m
     }[m
 [m
[1mdiff --git a/templates/dashboard.html b/templates/dashboard.html[m
[1mindex aaa0889..8aaf68c 100644[m
[1m--- a/templates/dashboard.html[m
[1m+++ b/templates/dashboard.html[m
[36m@@ -13,7 +13,8 @@[m
 [m
     <!-- Font Awesome -->[m
     <link rel="stylesheet"[m
[31m-      href="{{ url_for('static', filename='css/dashboard.css') }}">[m
[32m+[m[32m          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">[m
[32m+[m
 </head>[m
 [m
 <body>[m
[36m@@ -213,221 +214,224 @@[m
 [m
         <!-- ================= SECURITY CARDS ================= -->[m
 [m
[31m-        <section class="cards">[m
[32m+[m[32m        <!-- ================= SECURITY CARDS ================= -->[m
 [m
[32m+[m[32m<section class="cards">[m
 [m
[31m-            <!-- Security Score -->[m
 [m
[31m-            <div class="card score">[m
[32m+[m[32m    <!-- ================= SECURITY SCORE ================= -->[m
 [m
[31m-                <h3>[m
[31m-                    Security Score[m
[31m-                </h3>[m
[32m+[m[32m    <div class="card score">[m
 [m
[31m-                <h1>[m
[31m-                    92%[m
[31m-                </h1>[m
[32m+[m[32m        <h3>[m
[32m+[m[32m            Security Score[m
[32m+[m[32m        </h3>[m
 [m
[31m-                <p>[m
[31m-                    Excellent Security[m
[31m-                </p>[m
[32m+[m[32m        <h1>[m
[32m+[m[32m            {{ security_score }}%[m
[32m+[m[32m        </h1>[m
 [m
[31m-            </div>[m
[32m+[m[32m        <p>[m
[32m+[m[32m            Security Score[m
[32m+[m[32m        </p>[m
 [m
[32m+[m[32m    </div>[m
 [m
[31m-            <!-- IAM -->[m
 [m
[31m-            <div class="card iam">[m
[32m+[m[32m    <!-- ================= IAM ================= -->[m
 [m
[31m-                <h3>[m
[31m-                    IAM[m
[31m-                </h3>[m
[32m+[m[32m    <div class="card iam">[m
 [m
[31m-                <h2>[m
[31m-                    Secure[m
[31m-                </h2>[m
[32m+[m[32m        <h3>[m
[32m+[m[32m            IAM[m
[32m+[m[32m        </h3>[m
 [m
[31m-                <span class="green">[m
[31m-                    ● Healthy[m
[31m-                </span>[m
[32m+[m[32m        {% if iam_findings %}[m
 [m
[31m-            </div>[m
[32m+[m[32m            <h2>[m
[32m+[m[32m                {{ iam_findings|length }} Issues[m
[32m+[m[32m            </h2>[m
 [m
[32m+[m[32m            <span class="yellow">[m
[32m+[m[32m                ● Warning[m
[32m+[m[32m            </span>[m
 [m
[31m-            <!-- EC2 -->[m
[32m+[m[32m        {% else %}[m
 [m
[31m-            <div class="card ec2">[m
[32m+[m[32m            <h2>[m
[32m+[m[32m                Secure[m
[32m+[m[32m            </h2>[m
 [m
[31m-                <h3>[m
[31m-                    EC2[m
[31m-                </h3>[m
[32m+[m[32m            <span class="green">[m
[32m+[m[32m                ● Healthy[m
[32m+[m[32m            </span>[m
 [m
[31m-                <h2>[m
[31m-                    2 Issues[m
[31m-                </h2>[m
[32m+[m[32m        {% endif %}[m
 [m
[31m-                <span class="yellow">[m
[31m-                    ● Warning[m
[31m-                </span>[m
[32m+[m[32m    </div>[m
 [m
[31m-            </div>[m
 [m
[32m+[m[32m    <!-- ================= EC2 ================= -->[m
 [m
[31m-            <!-- S3 -->[m
[32m+[m[32m    <div class="card ec2">[m
 [m
[31m-            <div class="card s3">[m
[32m+[m[32m        <h3>[m
[32m+[m[32m            EC2[m
[32m+[m[32m        </h3>[m
 [m
[31m-                <h3>[m
[31m-                    S3[m
[31m-                </h3>[m
[32m+[m[32m        <h2>[m
[32m+[m[32m            2 Issues[m
[32m+[m[32m        </h2>[m
 [m
[31m-                <h2>[m
[31m-                    Critical[m
[31m-                </h2>[m
[32m+[m[32m        <span class="yellow">[m
[32m+[m[32m            ● Warning[m
[32m+[m[32m        </span>[m
 [m
[31m-                <span class="red">[m
[31m-                    ● Public Bucket[m
[31m-                </span>[m
[32m+[m[32m    </div>[m
 [m
[31m-            </div>[m
 [m
[32m+[m[32m    <!-- ================= S3 ================= -->[m
 [m
[31m-            <!-- VPC -->[m
[32m+[m[32m    <div class="card s3">[m
 [m
[31m-            <div class="card vpc">[m
[32m+[m[32m        <h3>[m
[32m+[m[32m            S3[m
[32m+[m[32m        </h3>[m
 [m
[31m-                <h3>[m
[31m-                    VPC[m
[31m-                </h3>[m
[32m+[m[32m        <h2>[m
[32m+[m[32m            Critical[m
[32m+[m[32m        </h2>[m
 [m
[31m-                <h2>[m
[31m-                    Secure[m
[31m-                </h2>[m
[32m+[m[32m        <span class="red">[m
[32m+[m[32m            ● Public Bucket[m
[32m+[m[32m        </span>[m
 [m
[31m-                <span class="green">[m
[31m-                    ● Healthy[m
[31m-                </span>[m
[32m+[m[32m    </div>[m
 [m
[31m-            </div>[m
 [m
[31m-        </section>[m
[32m+[m[32m    <!-- ================= VPC ================= -->[m
 [m
[32m+[m[32m    <div class="card vpc">[m
 [m
[31m-        <!-- ================= RECENT FINDINGS ================= -->[m
[32m+[m[32m        <h3>[m
[32m+[m[32m            VPC[m
[32m+[m[32m        </h3>[m
 [m
[31m-        <section class="table-section">[m
[32m+[m[32m        <h2>[m
[32m+[m[32m            Secure[m
[32m+[m[32m        </h2>[m
 [m
[31m-            <h2>[m
[31m-                Recent Findings[m
[31m-            </h2>[m
[32m+[m[32m        <span class="green">[m
[32m+[m[32m            ● Healthy[m
[32m+[m[32m        </span>[m
[32m+[m
[32m+[m[32m    </div>[m
[32m+[m
[32m+[m
[32m+[m[32m</section>[m
[32m+[m
[32m+[m
[32m+[m[32m<!-- ================= RECENT FINDINGS ================= -->[m
[32m+[m
[32m+[m[32m<section class="table-section">[m
[32m+[m
[32m+[m[32m    <h2>[m
[32m+[m[32m        Recent Findings[m
[32m+[m[32m    </h2>[m
[32m+[m
[32m+[m
[32m+[m[32m    <table>[m
[32m+[m
[32m+[m[32m        <thead>[m
 [m
[32m+[m[32m            <tr>[m
 [m
[31m-            <table>[m
[32m+[m[32m                <th>[m
[32m+[m[32m                    Severity[m
[32m+[m[32m                </th>[m
 [m
[31m-                <thead>[m
[32m+[m[32m                <th>[m
[32m+[m[32m                    Service[m
[32m+[m[32m                </th>[m
 [m
[31m-                    <tr>[m
[32m+[m[32m                <th>[m
[32m+[m[32m                    Description[m
[32m+[m[32m                </th>[m
 [m
[31m-                        <th>[m
[31m-                            Severity[m
[31m-                        </th>[m
[32m+[m[32m                <th>[m
[32m+[m[32m                    Status[m
[32m+[m[32m                </th>[m
 [m
[31m-                        <th>[m
[31m-                            Service[m
[31m-                        </th>[m
[32m+[m[32m            </tr>[m
 [m
[31m-                        <th>[m
[31m-                            Description[m
[31m-                        </th>[m
[32m+[m[32m        </thead>[m
 [m
[31m-                        <th>[m
[31m-                            Status[m
[31m-                        </th>[m
 [m
[31m-                    </tr>[m
[32m+[m[32m        <tbody>[m
 [m
[31m-                </thead>[m
[32m+[m[32m            {% if findings %}[m
 [m
[32m+[m[32m                {% for finding in findings %}[m
 [m
[31m-                <tbody>[m
[32m+[m[32m                <tr>[m
 [m
[32m+[m[32m                    <td class="{{ finding.severity|lower }}">[m
 [m
[31m-                    <!-- Critical Finding -->[m
[32m+[m[32m                        {{ finding.severity }}[m
 [m
[31m-                    <tr>[m
[32m+[m[32m                    </td>[m
 [m
[31m-                        <td class="critical">[m
[31m-                            Critical[m
[31m-                        </td>[m
 [m
[31m-                        <td>[m
[31m-                            S3[m
[31m-                        </td>[m
[32m+[m[32m                    <td>[m
 [m
[31m-                        <td>[m
[31m-                            Bucket Public[m
[31m-                        </td>[m
[32m+[m[32m                        {{ finding.service }}[m
 [m
[31m-                        <td>[m
[31m-                            Open[m
[31m-                        </td>[m
[32m+[m[32m                    </td>[m
 [m
[31m-                    </tr>[m
 [m
[32m+[m[32m                    <td>[m
 [m
[31m-                    <!-- High Finding -->[m
[32m+[m[32m                        {{ finding.issue }}[m
 [m
[31m-                    <tr>[m
[32m+[m[32m                        <br>[m
 [m
[31m-                        <td class="high">[m
[31m-                            High[m
[31m-                        </td>[m
[32m+[m[32m                        <small>[m
[32m+[m[32m                            User: {{ finding.user }}[m
[32m+[m[32m                        </small>[m
 [m
[31m-                        <td>[m
[31m-                            EC2[m
[31m-                        </td>[m
[32m+[m[32m                    </td>[m
 [m
[31m-                        <td>[m
[31m-                            SSH Port 22 Open[m
[31m-                        </td>[m
 [m
[31m-                        <td>[m
[31m-                            Open[m
[31m-                        </td>[m
[32m+[m[32m                    <td>[m
[32m+[m[32m                        Open[m
[32m+[m[32m                    </td>[m
 [m
[31m-                    </tr>[m
[32m+[m[32m                </tr>[m
 [m
[32m+[m[32m                {% endfor %}[m
 [m
[31m-                    <!-- Medium Finding -->[m
[32m+[m[32m            {% else %}[m
 [m
[31m-                    <tr>[m
[32m+[m[32m                <tr>[m
 [m
[31m-                        <td class="medium">[m
[31m-                            Medium[m
[31m-                        </td>[m
[32m+[m[32m                    <td colspan="4">[m
 [m
[31m-                        <td>[m
[31m-                            IAM[m
[31m-                        </td>[m
[32m+[m[32m                        ✅ No security findings detected[m
 [m
[31m-                        <td>[m
[31m-                            MFA Disabled[m
[31m-                        </td>[m
[32m+[m[32m                    </td>[m
 [m
[31m-                        <td>[m
[31m-                            Pending[m
[31m-                        </td>[m
[32m+[m[32m                </tr>[m
 [m
[31m-                    </tr>[m
[32m+[m[32m            {% endif %}[m
 [m
[31m-                </tbody>[m
[32m+[m[32m        </tbody>[m
 [m
[31m-            </table>[m
[32m+[m[32m    </table>[m
 [m
[31m-        </section>[m
[32m+[m[32m</section>[m
 [m
 [m
[31m-        <!-- Scan Button -->[m
[32m+[m[32m<!-- ================= SCAN BUTTON ================= -->[m
 [m
 <div class="scan">[m
 [m
[36m@@ -446,6 +450,7 @@[m
 </div>[m
 [m
 [m
[32m+[m[41m        [m
     </main>[m
 [m
 </div>[m
[1mdiff --git a/templates/scan.html b/templates/scan.html[m
[1mindex 5337d08..e31ea98 100644[m
[1m--- a/templates/scan.html[m
[1m+++ b/templates/scan.html[m
[36m@@ -1,19 +1,360 @@[m
 <!DOCTYPE html>[m
[31m-<html>[m
[32m+[m[32m<html lang="en">[m
 [m
 <head>[m
[31m-    <title>AWS Scan</title>[m
[32m+[m
[32m+[m[32m    <meta charset="UTF-8">[m
[32m+[m
[32m+[m[32m    <meta name="viewport" content="width=device-width, initial-scale=1.0">[m
[32m+[m
[32m+[m[32m    <title>AWS Infrastructure Scan</title>[m
[32m+[m
[32m+[m[32m    <!-- CloudSec CSS -->[m
[32m+[m[32m    <link rel="stylesheet"[m
[32m+[m[32m          href="{{ url_for('static', filename='dashboard.css') }}">[m
[32m+[m
[32m+[m[32m    <!-- Font Awesome -->[m
[32m+[m[32m    <link rel="stylesheet"[m
[32m+[m[32m          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">[m
[32m+[m
 </head>[m
 [m
[32m+[m
 <body>[m
 [m
[31m-    <h1>AWS Infrastructure Scan</h1>[m
[32m+[m[32m<div class="container">[m
[32m+[m
[32m+[m
[32m+[m[32m    <!-- ================= SIDEBAR ================= -->[m
[32m+[m
[32m+[m[32m    <aside class="sidebar">[m
[32m+[m
[32m+[m[32m        <div class="logo">[m
[32m+[m
[32m+[m[32m            <i class="fa-solid fa-shield-halved"></i>[m
[32m+[m
[32m+[m[32m            <h2>CloudSec</h2>[m
[32m+[m
[32m+[m[32m        </div>[m
[32m+[m
[32m+[m
[32m+[m[32m        <ul>[m
[32m+[m
[32m+[m[32m            <li>[m
[32m+[m
[32m+[m[32m                <a href="{{ url_for('dashboard') }}" class="menu-link">[m
[32m+[m
[32m+[m[32m                    <i class="fa-solid fa-house"></i>[m
[32m+[m
[32m+[m[32m                    <span>Dashboard</span>[m
[32m+[m
[32m+[m[32m                </a>[m
[32m+[m
[32m+[m[32m            </li>[m
[32m+[m
[32m+[m
[32m+[m[32m            <li class="active">[m
[32m+[m
[32m+[m[32m                <a href="{{ url_for('scan') }}" class="menu-link">[m
[32m+[m
[32m+[m[32m                    <i class="fa-solid fa-cloud"></i>[m
[32m+[m
[32m+[m[32m                    <span>AWS Scan</span>[m
[32m+[m
[32m+[m[32m                </a>[m
[32m+[m
[32m+[m[32m            </li>[m
[32m+[m
[32m+[m
[32m+[m[32m            <li>[m
[32m+[m
[32m+[m[32m                <a href="{{ url_for('reports') }}" class="menu-link">[m
[32m+[m
[32m+[m[32m                    <i class="fa-solid fa-chart-column"></i>[m
[32m+[m
[32m+[m[32m                    <span>Reports</span>[m
[32m+[m
[32m+[m[32m                </a>[m
[32m+[m
[32m+[m[32m            </li>[m
[32m+[m
[32m+[m
[32m+[m[32m            <li>[m
[32m+[m
[32m+[m[32m                <a href="{{ url_for('iam') }}" class="menu-link">[m
[32m+[m
[32m+[m[32m                    <i class="fa-solid fa-user-shield"></i>[m
[32m+[m
[32m+[m[32m                    <span>IAM</span>[m
[32m+[m
[32m+[m[32m                </a>[m
[32m+[m
[32m+[m[32m            </li>[m
[32m+[