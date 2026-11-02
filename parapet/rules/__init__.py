from parapet.rules import awsconfig, cloudtrail, ec2, iam, kms, lambda_, rds, s3

ALL_RULES = [
    *s3.RULES,
    *iam.RULES,
    *ec2.RULES,
    *cloudtrail.RULES,
    *kms.RULES,
    *rds.RULES,
    *lambda_.RULES,
    *awsconfig.RULES,
]


def build_rules(settings=None, disabled=(), now=None) -> list:
    rules = []
    for rule_class in ALL_RULES:
        if rule_class.id in disabled:
            continue
        rules.append(rule_class(settings, now))
    return rules


def rule_ids() -> list:
    return [rule.id for rule in ALL_RULES]
