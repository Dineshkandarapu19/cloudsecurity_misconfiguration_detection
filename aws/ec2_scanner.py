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
    """Detect EC2 security group and instance configuration issues."""

    ec2 = boto3.client("ec2")
    findings = []
    seen_findings = set()

    def add_finding(instance_id, group_id, issue, severity="HIGH"):
        """Add a finding only once."""
        finding_key = (instance_id, group_id, issue)

        if finding_key in seen_findings:
            return

        seen_findings.add(finding_key)

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

                # 1. Check whether IMDSv2 is required.
                metadata_options = instance.get("MetadataOptions", {})

                if metadata_options.get("HttpTokens") != "required":
                    add_finding(
                        instance_id,
                        "N/A",
                        "EC2 instance does not require IMDSv2",
                    )

                # 2. Check attached EBS volumes for encryption.
                for block_device in instance.get("BlockDeviceMappings", []):
                    ebs = block_device.get("Ebs")

                    if not ebs:
                        continue

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

                # 3. Check the instance's attached security groups.
                for security_group in instance.get("SecurityGroups", []):
                    group_id = security_group.get("GroupId")

                    if not group_id:
                        continue

                    response = ec2.describe_security_groups(
                        GroupIds=[group_id]
                    )

                    for group in response.get("SecurityGroups", []):
                        for permission in group.get("IpPermissions", []):
                            # Detect public IPv4 and IPv6 access.
                            public_ipv4 = any(
                                item.get("CidrIp") == "0.0.0.0/0"
                                for item in permission.get(
                                    "IpRanges", []
                                )
                            )

                            public_ipv6 = any(
                                item.get("CidrIpv6") == "::/0"
                                for item in permission.get(
                                    "Ipv6Ranges", []
                                )
                            )

                            if not (public_ipv4 or public_ipv6):
                                continue

                            protocol = permission.get("IpProtocol")

                            # Any protocol and port.
                            if protocol == "-1":
                                add_finding(
                                    instance_id,
                                    group_id,
                                    "All protocols and ports are open "
                                    "to the internet",
                                )
                                continue

                            # This scanner monitors TCP and UDP ports.
                            if protocol not in ("tcp", "udp"):
                                continue

                            from_port = permission.get("FromPort")
                            to_port = permission.get("ToPort")

                            if from_port is None or to_port is None:
                                continue

                            monitored_ports = (
                                MONITORED_TCP_PORTS
                                if protocol == "tcp"
                                else MONITORED_UDP_PORTS
                            )

                            # Detect monitored services exposed publicly.
                            for port, service_name in monitored_ports.items():
                                if from_port <= port <= to_port:
                                    add_finding(
                                        instance_id,
                                        group_id,
                                        f"{service_name} is open "
                                        "to the internet",
                                    )

                            # Detect custom ports not covered by our
                            # monitored service list.
                            has_custom_port = any(
                                port not in monitored_ports
                                for port in range(
                                    from_port,
                                    to_port + 1,
                                )
                            )

                            if has_custom_port:
                                protocol_name = protocol.upper()

                                add_finding(
                                    instance_id,
                                    group_id,
                                    f"Unrestricted custom "
                                    f"{protocol_name} port range "
                                    f"{from_port}-{to_port} is open "
                                    "to the internet",
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