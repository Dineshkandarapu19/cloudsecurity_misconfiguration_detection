import unittest
from unittest.mock import patch

from aws.ec2_scanner import scan_ec2


class TestEC2Scanner(unittest.TestCase):

    def run_scanner_with_rule(
        self,
        rule=None,
        http_tokens="required",
        block_device_mappings=None,
        volume_encrypted=True,
        public_ip=None,
        ipv6_addresses=None,
    ):
        with patch("aws.ec2_scanner.boto3.client") as mock_client:
            mock_ec2 = mock_client.return_value

            mock_ec2.get_paginator.return_value.paginate.return_value = [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-test123",
                                    "SecurityGroups": [
                                        {"GroupId": "sg-test123"}
                                    ],
                                    "MetadataOptions": {
                                        "HttpTokens": http_tokens
                                    },
                                    "BlockDeviceMappings":
                                        block_device_mappings or [],
                                    "PublicIpAddress": public_ip,
                                    "NetworkInterfaces": [
                                        {
                                            "Ipv6Addresses": [
                                                {"Ipv6Address": address}
                                                for address in (
                                                    ipv6_addresses or []
                                                )
                                            ]
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]

            permissions = [rule] if rule else []

            mock_ec2.describe_security_groups.return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-test123",
                        "IpPermissions": permissions,
                    }
                ]
            }

            mock_ec2.describe_volumes.return_value = {
                "Volumes": [
                    {
                        "VolumeId": "vol-test123",
                        "Encrypted": volume_encrypted,
                    }
                ]
            }

            return scan_ec2()

    def assert_finding(self, findings, expected_issue):
        matches = [
            finding
            for finding in findings
            if finding["issue"] == expected_issue
        ]

        self.assertEqual(len(matches), 1)
        finding = matches[0]

        self.assertEqual(finding["service"], "EC2")
        self.assertEqual(finding["instance_id"], "i-test123")

        if "public IPv" in expected_issue:
            self.assertEqual(finding["severity"], "LOW")
            self.assertEqual(finding["security_group_id"], "N/A")
        elif (
            "IMDSv2" in expected_issue
            or expected_issue.startswith("EBS volume")
        ):
            self.assertEqual(finding["severity"], "HIGH")
            self.assertEqual(finding["security_group_id"], "N/A")
        else:
            self.assertEqual(finding["severity"], "HIGH")
            self.assertEqual(
                finding["security_group_id"],
                "sg-test123",
            )

    # SSH tests

    def test_public_ssh_ipv4(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "SSH is open to the internet")

    def test_public_ssh_ipv6(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "SSH is open to the internet")

    def test_private_ssh_rule(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assertFalse(
            any("SSH is open to the internet" in f["issue"] for f in findings)
        )

    # RDP tests

    def test_public_rdp_ipv4(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "RDP is open to the internet")

    def test_public_rdp_ipv6(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "RDP is open to the internet")

    # Database tests

    def test_public_mysql_ipv4(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "MySQL is open to the internet")

    def test_public_postgresql_ipv6(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 5432,
            "ToPort": 5432,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "PostgreSQL is open to the internet")

    def test_private_mysql_rule(self):
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assertFalse(
            any("MySQL is open to the internet" in f["issue"] for f in findings)
        )

    # UDP tests

    def test_public_dns_udp_ipv4(self):
        rule = {
            "IpProtocol": "udp",
            "FromPort": 53,
            "ToPort": 53,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(findings, "DNS is open to the internet")

    def test_private_dns_udp_rule(self):
        rule = {
            "IpProtocol": "udp",
            "FromPort": 53,
            "ToPort": 53,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assertFalse(
            any("DNS is open to the internet" in f["issue"] for f in findings)
        )

    def test_public_custom_udp_port(self):
        rule = {
            "IpProtocol": "udp",
            "FromPort": 10000,
            "ToPort": 10000,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
        findings = self.run_scanner_with_rule(rule)
        self.assert_finding(
            findings,
            "Unrestricted custom UDP port range 10000-10000 "
            "is open to the internet",
        )

    # IMDSv2 tests

    def test_imdsv2_required_no_finding(self):
        findings = self.run_scanner_with_rule(http_tokens="required")
        self.assertFalse(any("IMDSv2" in f["issue"] for f in findings))

    def test_imdsv2_optional_finding(self):
        findings = self.run_scanner_with_rule(http_tokens="optional")
        self.assert_finding(
            findings,
            "EC2 instance does not require IMDSv2",
        )

    def test_imdsv2_missing_metadata_options(self):
        findings = self.run_scanner_with_rule(http_tokens=None)
        self.assert_finding(
            findings,
            "EC2 instance does not require IMDSv2",
        )

    # EBS encryption tests

    def test_unencrypted_ebs_volume_finding(self):
        mappings = [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"VolumeId": "vol-test123"},
            }
        ]
        findings = self.run_scanner_with_rule(
            block_device_mappings=mappings,
            volume_encrypted=False,
        )
        self.assert_finding(
            findings,
            "EBS volume vol-test123 is not encrypted",
        )

    def test_encrypted_ebs_volume_no_finding(self):
        mappings = [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"VolumeId": "vol-test123"},
            }
        ]
        findings = self.run_scanner_with_rule(
            block_device_mappings=mappings,
            volume_encrypted=True,
        )
        self.assertFalse(
            any("is not encrypted" in f["issue"] for f in findings)
        )

    # Public IP exposure tests

    def test_public_ipv4_address_finding(self):
        findings = self.run_scanner_with_rule(public_ip="203.0.113.10")
        self.assert_finding(
            findings,
            "EC2 instance has a public IPv4 address",
        )

    def test_no_public_ipv4_address_no_finding(self):
        findings = self.run_scanner_with_rule(public_ip=None)
        self.assertFalse(
            any("public IPv4 address" in f["issue"] for f in findings)
        )

    def test_public_ipv6_address_finding(self):
        findings = self.run_scanner_with_rule(
            ipv6_addresses=["2001:db8::10"]
        )
        self.assert_finding(
            findings,
            "EC2 instance has a public IPv6 address",
        )


if __name__ == "__main__":
    unittest.main()