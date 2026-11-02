from parapet.model import Severity, is_unknown
from parapet.rules.base import PASS, Rule, fail

ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"
ALL_PORTS = (0, 65535)
SECURITY_GROUP_TYPES = ("aws_security_group", "aws_default_security_group")


def public_sources(rule: dict) -> list:
    sources = []
    if ANY_IPV4 in (rule.get("cidr_blocks") or []):
        sources.append(ANY_IPV4)
    if ANY_IPV6 in (rule.get("ipv6_cidr_blocks") or []):
        sources.append(ANY_IPV6)
    return sources


def port_span(rule: dict):
    protocol = str(rule.get("protocol") or "").lower()
    if protocol in ("-1", "all"):
        return ALL_PORTS
    if protocol in ("icmp", "icmpv6", "1", "58"):
        return None
    start = rule.get("from_port")
    end = rule.get("to_port")
    if is_unknown(start) or is_unknown(end):
        return None
    if start is None or end is None:
        return ALL_PORTS
    start, end = int(start), int(end)
    return (min(start, end), max(start, end))


def span_text(span: tuple) -> str:
    if span == ALL_PORTS:
        return "all ports"
    if span[0] == span[1]:
        return f"port {span[0]}"
    return f"ports {span[0]}-{span[1]}"


def public_ingress(resource) -> list:
    entries = []
    ingress = resource.attrs.get("ingress")
    if not isinstance(ingress, list):
        return entries
    for rule in ingress:
        if not isinstance(rule, dict):
            continue
        sources = public_sources(rule)
        span = port_span(rule)
        if sources and span is not None:
            entries.append((span, sources))
    return entries


def ports_hit(entries: list, ports: list) -> dict:
    hits = {}
    for span, sources in entries:
        if span == ALL_PORTS:
            continue
        for port in ports:
            if span[0] <= port <= span[1]:
                hits.setdefault(port, set()).update(sources)
    return hits


def describe_hits(hits: dict) -> str:
    parts = []
    for port in sorted(hits):
        parts.append(f"port {port} from " + " and ".join(sorted(hits[port])))
    return ", ".join(parts)


class AdminPortsOpen(Rule):
    id = "EC2-001"
    title = "Security group allows remote administration from the internet"
    severity = Severity.HIGH
    resource_types = SECURITY_GROUP_TYPES
    cis = ("5.2", "5.3")
    security_hub = ("EC2.53", "EC2.54")
    remediation = "Remove 0.0.0.0/0 and ::/0 from SSH and RDP ingress rules; use a VPN, a bastion with a fixed source range, or Session Manager."

    def check(self, resource, inventory):
        hits = ports_hit(public_ingress(resource), self.settings["admin_ports"])
        if hits:
            return fail("ingress open on " + describe_hits(hits))
        return PASS


class AllTrafficOpen(Rule):
    id = "EC2-002"
    title = "Security group allows all traffic from the internet"
    severity = Severity.CRITICAL
    resource_types = SECURITY_GROUP_TYPES
    security_hub = ("EC2.18", "EC2.19")
    remediation = (
        "Replace the all-protocol or all-port ingress rule with rules for the exact ports and source ranges needed."
    )

    def check(self, resource, inventory):
        sources = set()
        for span, found in public_ingress(resource):
            if span == ALL_PORTS:
                sources.update(found)
        if sources:
            return fail("ingress allows every port from " + " and ".join(sorted(sources)))
        return PASS


class DatabasePortsOpen(Rule):
    id = "EC2-003"
    title = "Security group exposes a database port to the internet"
    severity = Severity.HIGH
    resource_types = SECURITY_GROUP_TYPES
    security_hub = ("EC2.19",)
    remediation = "Allow database ports only from application security groups or private CIDR ranges."

    def check(self, resource, inventory):
        hits = ports_hit(public_ingress(resource), self.settings["database_ports"])
        if hits:
            return fail("ingress open on " + describe_hits(hits))
        return PASS


class UnexpectedPortsOpen(Rule):
    id = "EC2-004"
    title = "Security group allows unrestricted ingress on an unexpected port"
    severity = Severity.MEDIUM
    resource_types = SECURITY_GROUP_TYPES
    security_hub = ("EC2.18",)
    remediation = "Limit internet facing ingress to the ports listed in public_ports_allowed, usually 80 and 443, and restrict everything else by source."

    def check(self, resource, inventory):
        allowed = set(self.settings["public_ports_allowed"])
        flagged = set(self.settings["admin_ports"]) | set(self.settings["database_ports"])
        unexpected = []
        for span, sources in public_ingress(resource):
            if span == ALL_PORTS:
                continue
            ports = range(span[0], span[1] + 1)
            if any(port in flagged for port in ports):
                continue
            if all(port in allowed for port in ports):
                continue
            unexpected.append(span_text(span) + " from " + " and ".join(sorted(sources)))
        if unexpected:
            return fail("ingress open on " + ", ".join(unexpected))
        return PASS


class DefaultSecurityGroupInUse(Rule):
    id = "EC2-005"
    title = "Default security group allows traffic"
    severity = Severity.MEDIUM
    resource_types = ("aws_default_security_group",)
    cis = ("5.4",)
    security_hub = ("EC2.2",)
    remediation = "Remove every ingress and egress rule from the default security group and attach purpose built groups to resources instead."

    def check(self, resource, inventory):
        ingress = resource.attrs.get("ingress")
        egress = resource.attrs.get("egress")
        if is_unknown(ingress) or is_unknown(egress):
            return None
        counts = (len(ingress or []), len(egress or []))
        if counts[0] or counts[1]:
            return fail(f"default security group has {counts[0]} ingress and {counts[1]} egress rule(s)")
        return PASS


class VpcFlowLogs(Rule):
    id = "EC2-006"
    title = "VPC has no flow logs"
    severity = Severity.MEDIUM
    resource_types = ("aws_vpc",)
    cis = ("3.7",)
    security_hub = ("EC2.6",)
    remediation = "Create a flow log for the VPC that captures ALL traffic to CloudWatch Logs or S3."

    def check(self, resource, inventory):
        logs = resource.attrs.get("flow_logs")
        if is_unknown(logs):
            return None
        if not logs:
            return fail("no flow log is attached to the VPC")
        return PASS


class EbsDefaultEncryption(Rule):
    id = "EC2-007"
    title = "EBS encryption by default is disabled"
    severity = Severity.MEDIUM
    resource_types = ("aws_ebs_encryption_by_default",)
    cis = ("2.2.1",)
    security_hub = ("EC2.7",)
    remediation = "Enable EBS encryption by default in every region so new volumes are encrypted automatically."

    def check(self, resource, inventory):
        enabled = resource.attrs.get("enabled")
        if is_unknown(enabled):
            return None
        if enabled is not True:
            return fail("new volumes in this region are not encrypted by default")
        return PASS


class EbsVolumeEncrypted(Rule):
    id = "EC2-008"
    title = "EBS volume is not encrypted"
    severity = Severity.MEDIUM
    resource_types = ("aws_ebs_volume",)
    security_hub = ("EC2.3",)
    remediation = "Create volumes with encryption enabled; existing volumes need a snapshot copied with encryption and a new volume from it."

    def check(self, resource, inventory):
        encrypted = resource.attrs.get("encrypted")
        if is_unknown(encrypted):
            return None
        if encrypted is not True:
            return fail("volume is not encrypted at rest")
        return PASS


class InstanceImdsV2(Rule):
    id = "EC2-009"
    title = "EC2 instance still allows IMDSv1"
    severity = Severity.HIGH
    resource_types = ("aws_instance",)
    cis = ("5.6",)
    security_hub = ("EC2.8",)
    remediation = "Set metadata_options http_tokens to required so the instance metadata service only answers IMDSv2 session requests."

    def check(self, resource, inventory):
        options = resource.attrs.get("metadata_options")
        if isinstance(options, list):
            options = options[0] if options else {}
        if is_unknown(options):
            return None
        options = options or {}
        if options.get("http_endpoint") == "disabled":
            return PASS
        tokens = options.get("http_tokens")
        if is_unknown(tokens):
            return None
        if tokens != "required":
            return fail("metadata service accepts IMDSv1 requests (http_tokens is " + str(tokens or "optional") + ")")
        return PASS


class InstancePublicIp(Rule):
    id = "EC2-010"
    title = "EC2 instance has a public IP address"
    severity = Severity.LOW
    resource_types = ("aws_instance",)
    security_hub = ("EC2.9",)
    remediation = (
        "Launch instances in private subnets behind a load balancer or NAT gateway instead of assigning public IPs."
    )

    def check(self, resource, inventory):
        public = resource.attrs.get("associate_public_ip_address")
        if public is None or is_unknown(public):
            return None
        if public:
            return fail("instance gets a public IPv4 address")
        return PASS


class InstanceVolumesEncrypted(Rule):
    id = "EC2-011"
    title = "EC2 instance block device is not encrypted"
    severity = Severity.MEDIUM
    resource_types = ("aws_instance",)
    sources = ("terraform",)
    security_hub = ("EC2.3",)
    remediation = (
        "Set encrypted = true on root_block_device and every ebs_block_device, or rely on EBS encryption by default."
    )

    def check(self, resource, inventory):
        devices = []
        for key in ("root_block_device", "ebs_block_device"):
            value = resource.attrs.get(key)
            if isinstance(value, list):
                devices.extend(d for d in value if isinstance(d, dict))
        if not devices:
            return None
        unencrypted = [d for d in devices if d.get("encrypted") is False]
        if unencrypted:
            return fail(f"{len(unencrypted)} block device(s) are configured without encryption")
        return PASS


RULES = [
    AdminPortsOpen,
    AllTrafficOpen,
    DatabasePortsOpen,
    UnexpectedPortsOpen,
    DefaultSecurityGroupInUse,
    VpcFlowLogs,
    EbsDefaultEncryption,
    EbsVolumeEncrypted,
    InstanceImdsV2,
    InstancePublicIp,
    InstanceVolumesEncrypted,
]
