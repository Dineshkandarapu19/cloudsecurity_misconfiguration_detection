import boto3
from datetime import datetime, timezone


def scan_iam():

    iam = boto3.client("iam")

    findings = []

    response = iam.list_users()

    for user in response["Users"]:

        username = user["UserName"]

        # -----------------------------
        # Check MFA
        # -----------------------------

        mfa_response = iam.list_mfa_devices(
            UserName=username
        )

        if mfa_response["MFADevices"]:

            mfa_status = "ENABLED"

        else:

            mfa_status = "NOT ENABLED"

            findings.append({
                "user": username,
                "service": "IAM",
                "issue": "MFA is not enabled",
                "severity": "HIGH"
            })

        # -----------------------------
        # Check Access Keys
        # -----------------------------

        keys_response = iam.list_access_keys(
            UserName=username
        )

        for key in keys_response["AccessKeyMetadata"]:

            age = datetime.now(timezone.utc) - key["CreateDate"]

            if key["Status"] == "Active" and age.days > 90:

                findings.append({
                    "user": username,
                    "service": "IAM",
                    "issue": "Active access key is older than 90 days",
                    "severity": "MEDIUM",
                    "access_key": key["AccessKeyId"]
            })

    return findings