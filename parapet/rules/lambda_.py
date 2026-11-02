from parapet.model import Severity, is_unknown
from parapet.rules import policy
from parapet.rules.base import PASS, Rule, fail


class PublicInvokePolicy(Rule):
    id = "LAMBDA-001"
    title = "Lambda function can be invoked by anyone"
    severity = Severity.CRITICAL
    resource_types = ("aws_lambda_function",)
    fsbp = ("Lambda.1",)
    remediation = (
        "Remove permissions with principal * or scope them with source_arn, source_account or principal_org_id."
    )

    def check(self, resource, inventory):
        document = policy.load_policy(resource.attrs.get("policy"))
        if is_unknown(document):
            return None
        if document is None:
            return PASS
        hits = policy.public_statements(document)
        if hits:
            return fail("resource policy allows any principal in " + ", ".join(hits))
        return PASS


class FunctionUrlWithoutAuth(Rule):
    id = "LAMBDA-002"
    title = "Lambda function URL has no authentication"
    severity = Severity.HIGH
    resource_types = ("aws_lambda_function_url",)
    remediation = "Set authorization_type to AWS_IAM, or put the function behind API Gateway with an authorizer."

    def check(self, resource, inventory):
        auth = resource.attrs.get("authorization_type")
        if is_unknown(auth):
            return None
        if auth == "NONE":
            return fail("function URL is reachable without any credentials")
        return PASS


class DeprecatedRuntime(Rule):
    id = "LAMBDA-003"
    title = "Lambda function uses a runtime that no longer receives updates"
    severity = Severity.MEDIUM
    resource_types = ("aws_lambda_function",)
    fsbp = ("Lambda.2",)
    remediation = "Move the function to a supported runtime version listed in the AWS Lambda runtime table."

    def check(self, resource, inventory):
        runtime = resource.attrs.get("runtime")
        if runtime is None or is_unknown(runtime):
            return None
        if runtime in self.settings["deprecated_lambda_runtimes"]:
            return fail(f"runtime {runtime} is deprecated")
        return PASS


RULES = [PublicInvokePolicy, FunctionUrlWithoutAuth, DeprecatedRuntime]
