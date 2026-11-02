import json

from parapet.model import UNKNOWN, is_unknown

RESTRICTING_CONDITION_KEYS = {
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principalisawsservice",
    "aws:userid",
    "aws:username",
    "aws:resourceaccount",
    "aws:resourceorgid",
    "s3:dataaccesspointaccount",
    "s3:dataaccesspointarn",
    "s3:accesspointnetworkorigin",
    "kms:calleraccount",
    "lambda:functionurlauthtype",
}


def load_policy(value):
    if is_unknown(value):
        return UNKNOWN
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            document = json.loads(value)
        except ValueError:
            return None
        return document if isinstance(document, dict) else None
    return None


def as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: dict) -> list:
    result = []
    for index, raw in enumerate(as_list(document.get("Statement"))):
        if not isinstance(raw, dict):
            continue
        result.append(
            {
                "label": str(raw.get("Sid") or f"statement {index + 1}"),
                "effect": raw.get("Effect", ""),
                "action": [str(a) for a in as_list(raw.get("Action"))],
                "has_not_action": "NotAction" in raw,
                "resource": [str(r) for r in as_list(raw.get("Resource"))],
                "has_not_resource": "NotResource" in raw,
                "principal": raw.get("Principal"),
                "condition": raw.get("Condition") if isinstance(raw.get("Condition"), dict) else {},
            }
        )
    return result


def is_public_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "aws"):
            if "*" in as_list(principal.get(key)):
                return True
    return False


def condition_restricts(condition: dict) -> bool:
    for pairs in condition.values():
        if not isinstance(pairs, dict):
            continue
        for key in pairs:
            if key.lower() in RESTRICTING_CONDITION_KEYS:
                return True
    return False


def allows_full_admin(document: dict) -> list:
    hits = []
    for statement in statements(document):
        if statement["effect"] != "Allow" or statement["condition"]:
            continue
        wildcard_action = statement["has_not_action"] or any(a in ("*", "*:*") for a in statement["action"])
        wildcard_resource = statement["has_not_resource"] or "*" in statement["resource"]
        if wildcard_action and wildcard_resource:
            hits.append(statement["label"])
    return hits


def service_wildcards(document: dict) -> list:
    found = set()
    for statement in statements(document):
        if statement["effect"] != "Allow":
            continue
        for action in statement["action"]:
            if action.endswith(":*") and action != "*:*":
                found.add(action)
    return sorted(found)


def public_statements(document: dict) -> list:
    hits = []
    for statement in statements(document):
        if statement["effect"] != "Allow" or not is_public_principal(statement["principal"]):
            continue
        if condition_restricts(statement["condition"]):
            continue
        hits.append(statement["label"])
    return hits


def denies_insecure_transport(document: dict) -> bool:
    for statement in statements(document):
        if statement["effect"] != "Deny" or not is_public_principal(statement["principal"]):
            continue
        for operator, pairs in statement["condition"].items():
            if not operator.lower().startswith("bool") or not isinstance(pairs, dict):
                continue
            for key, value in pairs.items():
                if key.lower() == "aws:securetransport" and str(value).lower() in ("false", "[false]"):
                    return True
                if (
                    key.lower() == "aws:securetransport"
                    and isinstance(value, list)
                    and any(str(v).lower() == "false" for v in value)
                ):
                    return True
    return False


def trust_allows_any_principal(document: dict) -> list:
    hits = []
    for statement in statements(document):
        if statement["effect"] != "Allow" or not is_public_principal(statement["principal"]):
            continue
        assume = any(a in ("*", "sts:*", "sts:AssumeRole") for a in statement["action"])
        if assume and not condition_restricts(statement["condition"]):
            hits.append(statement["label"])
    return hits
