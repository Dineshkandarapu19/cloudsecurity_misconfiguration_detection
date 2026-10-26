import boto3


MONITORED_TCP_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
}

MONITORED_UDP_PORTS = {
    53: "DNS",
    123: "NTP",
    161: "SNMP",
    500: "IPsec/IKE",
}


def scan_ec2():
    """Scan EC2 instances for selected security misconfigurations."""

    ec2 = boto3.client("ec2")
    findings = []
    seen_findings = set()

    def add_finding(
        instance_id,
        group_id,
        issue,
        severity="HIGH",
    ):
        key = (instance_id, group_id, issue)

        if key in seen_findings:
            return

        seen_findings.add(key)

        findings.append({
            "service": "EC2",
            "instance_id": instance_id,
            "security_group_id": group_id,
            "issue": issue,
            "severity": severity,
        })

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "Unknown")

                # 1. Public IP exposure review.
                if instance.get("PublicIpAddress"):
                    add_finding(
                        instance_id,
                        "N/A",
                        "EC2 instance has a public IPv4 address",
                        "LOW",
                    )

                for interface in instance.get("NetworkInterfaces", []):
                    has_ipv6 = any(
                        item.get("Ipv6Address")
                        for item in interface.get("Ipv6Addresses", [])
                    )

                    if has_ipv6:
                        add_finding(
                            instance_id,
                            "N/A",
                            "EC2 instance has a public IPv6 address",
                            "LOW",
                        )

                # 2. IMDSv2 enforcement.
                metadata_options = instance.get("MetadataOptions", {})

                if metadata_options.get("HttpTokens") != "required":
                    add_finding(
                        instance_id,
                        "N/A",
                        "EC2 instance does not require IMDSv2",
                    )

                # 3. EBS encryption.
                for mapping in instance.get("BlockDeviceMappings", []):
                    ebs = mapping.get("Ebs", {})
                    volume_id = ebs.get("VolumeId")

                    if not volume_id:
                        continue

                    volume_response = ec2.describe_volumes(
                        VolumeIds=[volume_id]
                    )

                    for volume in volume_response.get("Volumes", []):
                        if not volume.get("Encrypted", False):
                            add_finding(
                                instance_id,
                                "N/A",
                                f"EBS volume {volume_id} is not encrypted",
                            )

                # 4. Attached security group rules.
                for attached_group in instance.get("SecurityGroups", []):
                    group_id = attached_group.get("GroupId")

                    if not group_id:
                        continue

                    response = ec2.describe_security_groups(
                        GroupIds=[group_id]
                    )

                    for group in response.get("SecurityGroups", []):
                        ingress_rules = group.get("IpPermissions", [])
                        egress_rules = group.get("IpPermissionsEgress", [])
                        group_name = group.get("GroupName", "")

                        # 5. Default security group inbound review.
                        if group_name == "default" and ingress_rules:
                            add_finding(
                                instance_id,
                                group_id,
                                "Default security group has inbound rules",
                                "MEDIUM",
                            )

                        # 6. Inspect inbound access.
                        for permission in ingress_rules:
                            public_ipv4 = any(
                                item.get("CidrIp") == "0.0.0.0/0"
                                for item in permission.get("IpRanges", [])
                            )

                            public_ipv6 = any(
                                item.get("CidrIpv6") == "::/0"
                                for item in permission.get("Ipv6Ranges", [])
                            )

                            if not (public_ipv4 or public_ipv6):
                                continue

                            protocol = permission.get("IpProtocol")

                            if protocol == "-1":
                                add_finding(
                                    instance_id,
                                    group_id,
                                    "All protocols and ports are open "
                                    "to the internet",
                                )
                                continue

                            if protocol not in ("tcp", "udp"):
                                continue

                            start = permission.get("FromPort")
                            end = permission.get("ToPort")

                            if start is None or end is None:
                                continue

                            monitored_ports = (
                                MONITORED_TCP_PORTS
                                if protocol == "tcp"
                                else MONITORED_UDP_PORTS
                            )

                            for port, service in monitored_ports.items():
                                if start <= port <= end:
                                    add_finding(
                                        instance_id,
                                        group_id,
                                        f"{service} is open to the internet",
                                    )

                            if any(
                                port not in monitored_ports
                                for port in range(start, end + 1)
                            ):
                                add_finding(
                                    instance_id,
                                    group_id,
                                    f"Unrestricted custom {protocol.upper()} "
                                    f"port range {start}-{end} is open "
                                    "to the internet",
                                )

                        # 7. Unrestricted outbound traffic review.
                        for permission in egress_rules:
                            if permission.get("IpProtocol") != "-1":
                                continue

                            public_egress = any(
                                item.get("CidrIp") == "0.0.0.0/0"
                                for item in permission.get("IpRanges", [])
                            ) or any(
                                item.get("CidrIpv6") == "::/0"
                                for item in permission.get("Ipv6Ranges", [])
                            )

                            if public_egress:
                                add_finding(
                                    instance_id,
                                    group_id,
                                    "Security group allows all outbound "
                                    "traffic to the internet",
                                    "LOW",
                                )

    return findings


if __name__ == "__main__":
    results = scan_ec2()

    if results:
        print("EC2 Security Findings:")
        for finding in results:
            print(finding)
    else:
        print("No EC2 security findings detected.")