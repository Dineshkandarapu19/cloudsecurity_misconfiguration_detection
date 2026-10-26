
import boto3


def scan_ec2():
    ec2 = boto3.client("ec2")
    findings = []

    # Retrieve EC2 instances
    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:

                instance_id = instance["InstanceId"]

                for group in instance.get("SecurityGroups", []):
                    group_id = group["GroupId"]

                    sg_response = ec2.describe_security_groups(
                        GroupIds=[group_id]
                    )

                    for security_group in sg_response["SecurityGroups"]:
                        for rule in security_group.get("IpPermissions", []):
                            protocol = rule.get("IpProtocol")
                            from_port = rule.get("FromPort")
                            to_port = rule.get("ToPort")

                            # Check whether the rule allows SSH
                            ssh_allowed = (
                                protocol == "-1"
                                or (
                                    protocol == "tcp"
                                    and from_port is not None
                                    and to_port is not None
                                    and from_port <= 22 <= to_port
                                )
                            )

                            if not ssh_allowed:
                                continue

                            # Check public IPv4 access
                            for ip_range in rule.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    findings.append({
                                        "service": "EC2",
                                        "instance_id": instance_id,
                                        "security_group_id": group_id,
                                        "issue": "SSH is open to the internet",
                                        "severity": "HIGH"
                                    })

    return findings


if __name__ == "__main__":
    results = scan_ec2()

    print("\nEC2 SECURITY SCAN RESULTS")
    print("=" * 40)

    for finding in results:
        print(finding)

    print("Total findings:", len(results))
