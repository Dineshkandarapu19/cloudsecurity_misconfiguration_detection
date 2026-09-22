import boto3
from datetime import datetime, timezone


# ==========================================
# Connect to AWS IAM
# ==========================================

iam = boto3.client("iam")

findings = []

# ==========================================
# Get all IAM users
# ==========================================

response = iam.list_users()


# ==========================================
# Check each IAM user
# ==========================================

for user in response["Users"]:

    username = user["UserName"]

    print("=" * 50)
    print("User:", username)

    # ------------------------------------------
    # Check MFA
    # ------------------------------------------

    mfa_response = iam.list_mfa_devices(
        UserName=username
    )

    if mfa_response["MFADevices"]:
        print("MFA: ENABLED")
    else:
        print("MFA: NOT ENABLED")
        print("⚠️ FINDING: MFA is not enabled")

        findings.append({
        "user": username,
        "issue": "MFA is not enabled",
        "severity": "HIGH"
        })
        

    # ------------------------------------------
    # Check Access Keys
    # ------------------------------------------

    keys_response = iam.list_access_keys(
        UserName=username
    )

    if keys_response["AccessKeyMetadata"]:

        print("Access Keys:")

        for key in keys_response["AccessKeyMetadata"]:

            print("  Key ID:", key["AccessKeyId"])
            print("  Status:", key["Status"])
            print("  Created:", key["CreateDate"])

            # Calculate access key age
            age = datetime.now(timezone.utc) - key["CreateDate"]

            print("  Age:", age.days, "days")

    else:

        print("Access Keys: NONE")


print("=" * 50)
print("\nSECURITY FINDINGS")

for finding in findings:
    print(finding)