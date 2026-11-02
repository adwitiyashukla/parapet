import json
from pathlib import Path

from parapet.model import UNKNOWN, Inventory, Resource, is_unknown
from parapet.sources import SourceError

GLOBAL_TYPES = {"aws_s3_account_public_access_block"}
SECURITY_GROUP_TYPES = ("aws_security_group", "aws_default_security_group")
NAME_ATTRIBUTES = {
    "aws_s3_bucket": "bucket",
    "aws_security_group": "name",
    "aws_iam_user": "name",
    "aws_iam_role": "name",
    "aws_iam_group": "name",
    "aws_iam_policy": "name",
    "aws_lambda_function": "function_name",
    "aws_lambda_function_url": "function_name",
    "aws_db_instance": "identifier",
    "aws_cloudtrail": "name",
    "aws_kms_key": "description",
}


def load_plan(path) -> Inventory:
    path = Path(path)
    if not path.is_file():
        raise SourceError(f"plan file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise SourceError(f"{path}: could not read plan json ({exc})") from None
    if not isinstance(data, dict) or "resource_changes" not in data:
        raise SourceError(f"{path}: not a terraform plan, produce one with: terraform show -json tfplan > plan.json")
    return build_inventory(data, str(path))


def build_inventory(data: dict, origin: str) -> Inventory:
    configuration = data.get("configuration") or {}
    provider_regions = _provider_regions(configuration)
    expressions, provider_keys = _collect_configuration(configuration.get("root_module") or {}, "")
    resources = {}
    for change in data.get("resource_changes") or []:
        if change.get("mode", "managed") != "managed":
            continue
        detail = change.get("change") or {}
        actions = detail.get("actions") or []
        if actions == ["delete"]:
            continue
        after = _merge_unknown(detail.get("after"), detail.get("after_unknown"))
        if not isinstance(after, dict):
            after = {}
        address = change["address"]
        rtype = change["type"]
        provider_key = provider_keys.get(_strip_index(address), "aws")
        region = _region_for(rtype, after, provider_regions.get(provider_key, provider_regions.get("aws", "default")))
        resources[address] = Resource(
            type=rtype,
            id=address,
            region=region,
            name=_display_name(rtype, after),
            address=address,
            attrs=after,
        )
    linker = _Linker(resources, expressions)
    for resource in list(resources.values()):
        if resource.type in SECURITY_GROUP_TYPES:
            for direction in ("ingress", "egress"):
                if not isinstance(resource.attrs.get(direction), list):
                    resource.attrs[direction] = []
        elif resource.type == "aws_s3_bucket":
            _normalize_bucket(resource)
    for resource in list(resources.values()):
        folder = FOLDERS.get(resource.type)
        if folder is not None and folder(resource, linker):
            linker.folded.add(resource.address)
    inventory = Inventory(source="terraform", origin=origin)
    for address, resource in resources.items():
        if address not in linker.folded:
            inventory.add(resource)
    inventory.regions = sorted({r.region for r in inventory.resources if r.region != "global"})
    return inventory


def _provider_regions(configuration: dict) -> dict:
    regions = {}
    for key, provider in (configuration.get("provider_config") or {}).items():
        if provider.get("name") != "aws":
            continue
        region = (provider.get("expressions") or {}).get("region", {}).get("constant_value")
        regions[key] = region if isinstance(region, str) else "default"
    return regions


def _collect_configuration(module: dict, prefix: str) -> tuple:
    expressions = {}
    provider_keys = {}
    for resource in module.get("resources") or []:
        if resource.get("mode", "managed") != "managed":
            continue
        address = prefix + resource["address"]
        expressions[address] = resource.get("expressions") or {}
        provider_keys[address] = resource.get("provider_config_key", "aws")
    for name, call in (module.get("module_calls") or {}).items():
        child_expressions, child_keys = _collect_configuration(call.get("module") or {}, f"{prefix}module.{name}.")
        expressions.update(child_expressions)
        provider_keys.update(child_keys)
    return expressions, provider_keys


def _merge_unknown(after, unknown):
    if unknown is True:
        return UNKNOWN
    if isinstance(unknown, dict):
        base = after if isinstance(after, dict) else {}
        merged = dict(base)
        for key, flag in unknown.items():
            merged[key] = _merge_unknown(base.get(key), flag)
        return merged
    if isinstance(unknown, list):
        base = after if isinstance(after, list) else []
        merged = list(base)
        for index, flag in enumerate(unknown):
            current = base[index] if index < len(base) else None
            value = _merge_unknown(current, flag)
            if index < len(merged):
                merged[index] = value
            else:
                merged.append(value)
        return merged
    return after


def _region_for(rtype: str, after: dict, fallback: str) -> str:
    region = after.get("region")
    if isinstance(region, str) and region:
        return region
    if rtype.startswith("aws_iam_") or rtype in GLOBAL_TYPES:
        return "global"
    return fallback


def _display_name(rtype: str, after: dict) -> str:
    key = NAME_ATTRIBUTES.get(rtype)
    if key is None:
        return ""
    value = after.get(key)
    return value if isinstance(value, str) else ""


def _strip_index(address: str) -> str:
    if address.endswith("]"):
        return address[: address.rfind("[")]
    return address


def _module_prefix(address: str) -> str:
    parts = address.split(".")
    index = 0
    while index + 1 < len(parts) and parts[index].startswith("module"):
        index += 2
    return ".".join(parts[:index]) + ("." if index else "")


class _Linker:
    def __init__(self, resources: dict, expressions: dict):
        self.resources = resources
        self.expressions = expressions
        self.folded = set()
        self.by_base = {}
        for address, resource in resources.items():
            self.by_base.setdefault(_strip_index(address), []).append(resource)

    def parents(self, child: Resource, attribute: str, parent_types: tuple, value_key: str = "") -> list:
        value = child.attrs.get(attribute)
        if value_key and isinstance(value, str):
            matches = [r for r in self.resources.values() if r.type in parent_types and r.attrs.get(value_key) == value]
            if matches:
                return matches
        found = []
        references = self.expressions.get(_strip_index(child.address), {}).get(attribute, {}).get("references", [])
        for reference in references:
            for candidate in self._candidates(reference, child.address):
                if candidate.type in parent_types and candidate not in found:
                    found.append(candidate)
        return found

    def _candidates(self, reference: str, child_address: str) -> list:
        full = _module_prefix(child_address) + reference
        parts = full.split(".")
        for end in range(len(parts), 1, -1):
            candidate = ".".join(parts[:end])
            if candidate in self.resources:
                return [self.resources[candidate]]
            if _strip_index(candidate) in self.by_base:
                return list(self.by_base[_strip_index(candidate)])
        return []


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _normalize_bucket(resource: Resource) -> None:
    attrs = resource.attrs
    legacy_versioning = _first(attrs.get("versioning"))
    if isinstance(legacy_versioning, dict):
        attrs["versioning"] = {
            "enabled": bool(legacy_versioning.get("enabled")),
            "mfa_delete": bool(legacy_versioning.get("mfa_delete")),
        }
    else:
        attrs["versioning"] = {"enabled": False, "mfa_delete": False}
    legacy_logging = _first(attrs.get("logging"))
    if isinstance(legacy_logging, dict):
        attrs["logging"] = {
            "target_bucket": legacy_logging.get("target_bucket"),
            "target_prefix": legacy_logging.get("target_prefix"),
        }
    else:
        attrs["logging"] = None
    legacy_encryption = _first(attrs.get("server_side_encryption_configuration"))
    attrs["encryption"] = None
    if isinstance(legacy_encryption, dict):
        rule = _first(legacy_encryption.get("rule"))
        if isinstance(rule, dict):
            default = _first(rule.get("apply_server_side_encryption_by_default")) or {}
            attrs["encryption"] = {
                "sse_algorithm": default.get("sse_algorithm"),
                "kms_key_id": default.get("kms_master_key_id"),
                "bucket_key_enabled": rule.get("bucket_key_enabled"),
            }
    if not isinstance(attrs.get("policy"), str):
        attrs["policy"] = None
    canned = attrs.get("acl")
    attrs["acl"] = {"canned": canned if isinstance(canned, str) else None, "grants": []}
    if not isinstance(attrs.get("public_access_block"), dict):
        attrs["public_access_block"] = None


def _bucket_folder(key: str, transform):
    def fold(child: Resource, linker: _Linker) -> bool:
        parents = linker.parents(child, "bucket", ("aws_s3_bucket",), "bucket")
        if not parents:
            return False
        value = transform(child, linker)
        for parent in parents:
            parent.attrs[key] = value
        return True

    return fold


def _public_access_block(child: Resource, linker: _Linker) -> dict:
    keys = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    return {key: child.attrs.get(key) for key in keys}


def _versioning(child: Resource, linker: _Linker) -> dict:
    block = _first(child.attrs.get("versioning_configuration")) or {}
    status = block.get("status")
    mfa = block.get("mfa_delete")
    return {
        "enabled": UNKNOWN if is_unknown(status) else status == "Enabled",
        "mfa_delete": UNKNOWN if is_unknown(mfa) else mfa == "Enabled",
    }


def _encryption(child: Resource, linker: _Linker):
    rule = _first(child.attrs.get("rule"))
    if not isinstance(rule, dict):
        return None
    default = _first(rule.get("apply_server_side_encryption_by_default")) or {}
    return {
        "sse_algorithm": default.get("sse_algorithm"),
        "kms_key_id": default.get("kms_master_key_id"),
        "bucket_key_enabled": rule.get("bucket_key_enabled"),
    }


def _logging(child: Resource, linker: _Linker) -> dict:
    target = child.attrs.get("target_bucket")
    if not isinstance(target, str):
        targets = linker.parents(child, "target_bucket", ("aws_s3_bucket",), "bucket")
        if targets:
            target = (
                targets[0].attrs.get("bucket")
                if isinstance(targets[0].attrs.get("bucket"), str)
                else targets[0].address
            )
    return {"target_bucket": target, "target_prefix": child.attrs.get("target_prefix")}


def _bucket_policy(child: Resource, linker: _Linker):
    return child.attrs.get("policy")


def _acl(child: Resource, linker: _Linker):
    grants = []
    policy = _first(child.attrs.get("access_control_policy"))
    if isinstance(policy, dict):
        for grant in policy.get("grant") or []:
            if not isinstance(grant, dict):
                continue
            grantee = _first(grant.get("grantee")) or {}
            grants.append(
                {"type": grantee.get("type"), "uri": grantee.get("uri"), "permission": grant.get("permission")}
            )
    return {"canned": child.attrs.get("acl"), "grants": grants}


def _security_group_rule(child: Resource, linker: _Linker) -> bool:
    direction = child.attrs.get("type")
    if direction not in ("ingress", "egress"):
        return False
    parents = linker.parents(child, "security_group_id", SECURITY_GROUP_TYPES)
    if not parents:
        return False
    rule = {
        "from_port": child.attrs.get("from_port"),
        "to_port": child.attrs.get("to_port"),
        "protocol": child.attrs.get("protocol"),
        "cidr_blocks": _string_list(child.attrs.get("cidr_blocks")),
        "ipv6_cidr_blocks": _string_list(child.attrs.get("ipv6_cidr_blocks")),
        "security_groups": [] if child.attrs.get("source_security_group_id") is None else ["referenced"],
        "self": bool(child.attrs.get("self")),
    }
    for parent in parents:
        parent.attrs[direction].append(rule)
    return True


def _vpc_security_group_rule(direction: str):
    def fold(child: Resource, linker: _Linker) -> bool:
        parents = linker.parents(child, "security_group_id", SECURITY_GROUP_TYPES)
        if not parents:
            return False
        ipv4 = child.attrs.get("cidr_ipv4")
        ipv6 = child.attrs.get("cidr_ipv6")
        rule = {
            "from_port": child.attrs.get("from_port"),
            "to_port": child.attrs.get("to_port"),
            "protocol": child.attrs.get("ip_protocol"),
            "cidr_blocks": [ipv4] if isinstance(ipv4, str) else [],
            "ipv6_cidr_blocks": [ipv6] if isinstance(ipv6, str) else [],
            "security_groups": [] if child.attrs.get("referenced_security_group_id") is None else ["referenced"],
            "self": False,
        }
        for parent in parents:
            parent.attrs[direction].append(rule)
        return True

    return fold


def _flow_log(child: Resource, linker: _Linker) -> bool:
    if child.attrs.get("vpc_id") is None:
        return False
    parents = linker.parents(child, "vpc_id", ("aws_vpc",))
    if not parents:
        return False
    entry = {
        "traffic_type": child.attrs.get("traffic_type"),
        "log_destination_type": child.attrs.get("log_destination_type"),
    }
    for parent in parents:
        parent.attrs.setdefault("flow_logs", []).append(entry)
    return True


def _inline_policy(attribute: str, parent_type: str):
    def fold(child: Resource, linker: _Linker) -> bool:
        parents = linker.parents(child, attribute, (parent_type,), "name")
        if not parents:
            return False
        entry = {"name": child.attrs.get("name"), "policy": child.attrs.get("policy")}
        for parent in parents:
            parent.attrs.setdefault("inline_policies", []).append(entry)
        return True

    return fold


def _policy_attachment(attribute: str, parent_type: str):
    def fold(child: Resource, linker: _Linker) -> bool:
        parents = linker.parents(child, attribute, (parent_type,), "name")
        if not parents:
            return False
        arn = child.attrs.get("policy_arn")
        if not isinstance(arn, str):
            policies = linker.parents(child, "policy_arn", ("aws_iam_policy",))
            arn = policies[0].address if policies else "unknown"
        for parent in parents:
            parent.attrs.setdefault("attached_policy_arns", []).append(arn)
        return True

    return fold


def _legacy_policy_attachment(child: Resource, linker: _Linker) -> bool:
    arn = child.attrs.get("policy_arn")
    if not isinstance(arn, str):
        policies = linker.parents(child, "policy_arn", ("aws_iam_policy",))
        arn = policies[0].address if policies else "unknown"
    attached = False
    for attribute, parent_type in (("users", "aws_iam_user"), ("groups", "aws_iam_group"), ("roles", "aws_iam_role")):
        names = child.attrs.get(attribute)
        if not isinstance(names, list):
            continue
        for parent in linker.resources.values():
            if parent.type == parent_type and parent.attrs.get("name") in names:
                parent.attrs.setdefault("attached_policy_arns", []).append(arn)
                attached = True
    return attached


def _lambda_permission(child: Resource, linker: _Linker) -> bool:
    parents = linker.parents(child, "function_name", ("aws_lambda_function",), "function_name")
    if not parents:
        return False
    principal = child.attrs.get("principal")
    statement = {
        "Sid": child.attrs.get("statement_id") or "",
        "Effect": "Allow",
        "Action": child.attrs.get("action") or "lambda:InvokeFunction",
        "Resource": "*",
    }
    if principal == "*":
        statement["Principal"] = "*"
    elif isinstance(principal, str) and principal.endswith(".amazonaws.com"):
        statement["Principal"] = {"Service": principal}
    else:
        statement["Principal"] = {"AWS": "unknown" if is_unknown(principal) else principal}
    condition = {}
    source_arn = child.attrs.get("source_arn")
    if source_arn is not None:
        condition.setdefault("ArnLike", {})["AWS:SourceArn"] = "unknown" if is_unknown(source_arn) else source_arn
    source_account = child.attrs.get("source_account")
    if source_account is not None:
        condition.setdefault("StringEquals", {})["AWS:SourceAccount"] = str(source_account)
    org_id = child.attrs.get("principal_org_id")
    if org_id is not None:
        condition.setdefault("StringEquals", {})["aws:PrincipalOrgID"] = str(org_id)
    if condition:
        statement["Condition"] = condition
    for parent in parents:
        policy = parent.attrs.get("policy")
        if not isinstance(policy, dict):
            policy = {"Version": "2012-10-17", "Statement": []}
            parent.attrs["policy"] = policy
        policy["Statement"].append(statement)
    return True


def _string_list(value) -> list:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


FOLDERS = {
    "aws_s3_bucket_public_access_block": _bucket_folder("public_access_block", _public_access_block),
    "aws_s3_bucket_versioning": _bucket_folder("versioning", _versioning),
    "aws_s3_bucket_server_side_encryption_configuration": _bucket_folder("encryption", _encryption),
    "aws_s3_bucket_logging": _bucket_folder("logging", _logging),
    "aws_s3_bucket_policy": _bucket_folder("policy", _bucket_policy),
    "aws_s3_bucket_acl": _bucket_folder("acl", _acl),
    "aws_security_group_rule": _security_group_rule,
    "aws_vpc_security_group_ingress_rule": _vpc_security_group_rule("ingress"),
    "aws_vpc_security_group_egress_rule": _vpc_security_group_rule("egress"),
    "aws_flow_log": _flow_log,
    "aws_iam_user_policy": _inline_policy("user", "aws_iam_user"),
    "aws_iam_role_policy": _inline_policy("role", "aws_iam_role"),
    "aws_iam_group_policy": _inline_policy("group", "aws_iam_group"),
    "aws_iam_user_policy_attachment": _policy_attachment("user", "aws_iam_user"),
    "aws_iam_role_policy_attachment": _policy_attachment("role", "aws_iam_role"),
    "aws_iam_group_policy_attachment": _policy_attachment("group", "aws_iam_group"),
    "aws_iam_policy_attachment": _legacy_policy_attachment,
    "aws_lambda_permission": _lambda_permission,
}
