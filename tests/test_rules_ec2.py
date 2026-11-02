from conftest import resource, verdict

from parapet.model import UNKNOWN
from parapet.rules import ec2


def rule(from_port, to_port, protocol="tcp", v4=("0.0.0.0/0",), v6=()):
    return {
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "cidr_blocks": list(v4),
        "ipv6_cidr_blocks": list(v6),
        "security_groups": [],
        "self": False,
    }


def group(*ingress, type_name="aws_security_group", egress=()):
    return resource(type_name, "sg", name="sg", ingress=list(ingress), egress=list(egress))


def test_port_span_handles_protocols():
    assert ec2.port_span(rule(0, 0, "-1")) == (0, 65535)
    assert ec2.port_span(rule(None, None, "-1")) == (0, 65535)
    assert ec2.port_span(rule(8, 0, "icmp")) is None
    assert ec2.port_span(rule(UNKNOWN, 22)) is None
    assert ec2.port_span(rule(443, 80)) == (80, 443)


def test_admin_ports_rule():
    assert verdict(ec2.AdminPortsOpen, group(rule(22, 22)))[1] == "ingress open on port 22 from 0.0.0.0/0"
    both = verdict(ec2.AdminPortsOpen, group(rule(3389, 3389, v4=(), v6=("::/0",)), rule(20, 25)))
    assert "port 22 from 0.0.0.0/0" in both[1] and "port 3389 from ::/0" in both[1]
    assert verdict(ec2.AdminPortsOpen, group(rule(22, 22, v4=("10.0.0.0/8",))))[0] is True
    assert verdict(ec2.AdminPortsOpen, group(rule(0, 0, "-1")))[0] is True
    custom = verdict(
        ec2.AdminPortsOpen,
        group(rule(2222, 2222)),
        settings={"admin_ports": [2222], "database_ports": [], "public_ports_allowed": []},
    )
    assert custom[0] is False


def test_all_traffic_and_database_rules():
    assert "every port from ::/0" in verdict(ec2.AllTrafficOpen, group(rule(0, 0, "-1", v4=(), v6=("::/0",))))[1]
    assert verdict(ec2.AllTrafficOpen, group(rule(0, 65535)))[0] is False
    assert verdict(ec2.AllTrafficOpen, group(rule(443, 443)))[0] is True
    assert "port 5432" in verdict(ec2.DatabasePortsOpen, group(rule(5432, 5432)))[1]
    assert verdict(ec2.DatabasePortsOpen, group(rule(3306, 3306, v4=("192.168.0.0/16",))))[0] is True


def test_unexpected_ports_rule_skips_already_flagged_rules():
    assert verdict(ec2.UnexpectedPortsOpen, group(rule(443, 443), rule(80, 80)))[0] is True
    assert "port 8080" in verdict(ec2.UnexpectedPortsOpen, group(rule(8080, 8080)))[1]
    assert "ports 8000-8100" in verdict(ec2.UnexpectedPortsOpen, group(rule(8000, 8100)))[1]
    assert verdict(ec2.UnexpectedPortsOpen, group(rule(22, 22), rule(0, 0, "-1"), rule(5432, 5432)))[0] is True


def test_default_security_group_rule():
    assert verdict(ec2.DefaultSecurityGroupInUse, group(type_name="aws_default_security_group"))[0] is True
    busy = group(rule(0, 0, "-1"), type_name="aws_default_security_group", egress=[rule(0, 0, "-1")])
    assert "1 ingress and 1 egress" in verdict(ec2.DefaultSecurityGroupInUse, busy)[1]
    assert (
        verdict(ec2.DefaultSecurityGroupInUse, resource("aws_default_security_group", "d", ingress=UNKNOWN, egress=[]))
        is None
    )


def test_vpc_and_ebs_rules():
    assert verdict(ec2.VpcFlowLogs, resource("aws_vpc", "v", flow_logs=[]))[0] is False
    assert verdict(ec2.VpcFlowLogs, resource("aws_vpc", "v", flow_logs=[{"traffic_type": "ALL"}]))[0] is True
    assert verdict(ec2.VpcFlowLogs, resource("aws_vpc", "v"))[0] is False
    assert (
        verdict(ec2.EbsDefaultEncryption, resource("aws_ebs_encryption_by_default", "us-east-1", enabled=False))[0]
        is False
    )
    assert (
        verdict(ec2.EbsDefaultEncryption, resource("aws_ebs_encryption_by_default", "us-east-1", enabled=True))[0]
        is True
    )
    assert verdict(ec2.EbsVolumeEncrypted, resource("aws_ebs_volume", "vol", encrypted=False))[0] is False
    assert verdict(ec2.EbsVolumeEncrypted, resource("aws_ebs_volume", "vol", encrypted=True))[0] is True
    assert verdict(ec2.EbsVolumeEncrypted, resource("aws_ebs_volume", "vol", encrypted=UNKNOWN)) is None


def test_instance_rules():
    optional = resource("aws_instance", "i", metadata_options=[{"http_tokens": "optional", "http_endpoint": "enabled"}])
    assert "IMDSv1" in verdict(ec2.InstanceImdsV2, optional)[1]
    required = resource("aws_instance", "i", metadata_options={"http_tokens": "required", "http_endpoint": "enabled"})
    assert verdict(ec2.InstanceImdsV2, required)[0] is True
    disabled = resource("aws_instance", "i", metadata_options={"http_tokens": "optional", "http_endpoint": "disabled"})
    assert verdict(ec2.InstanceImdsV2, disabled)[0] is True
    assert verdict(ec2.InstanceImdsV2, resource("aws_instance", "i", metadata_options=UNKNOWN)) is None
    assert verdict(ec2.InstanceImdsV2, resource("aws_instance", "i"))[0] is False
    assert verdict(ec2.InstancePublicIp, resource("aws_instance", "i", associate_public_ip_address=True))[0] is False
    assert verdict(ec2.InstancePublicIp, resource("aws_instance", "i", associate_public_ip_address=False))[0] is True
    assert verdict(ec2.InstancePublicIp, resource("aws_instance", "i", associate_public_ip_address=UNKNOWN)) is None
    assert verdict(ec2.InstancePublicIp, resource("aws_instance", "i")) is None
    plain = resource(
        "aws_instance", "i", root_block_device=[{"encrypted": False}], ebs_block_device=[{"encrypted": True}]
    )
    assert "1 block device" in verdict(ec2.InstanceVolumesEncrypted, plain)[1]
    assert (
        verdict(ec2.InstanceVolumesEncrypted, resource("aws_instance", "i", root_block_device=[{"encrypted": True}]))[0]
        is True
    )
    assert verdict(ec2.InstanceVolumesEncrypted, resource("aws_instance", "i")) is None
