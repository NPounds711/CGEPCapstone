package main

# AC.L2-3.1.5 — GAP-07
# No IAM role policy may grant a wildcard action (service:* or bare *).
# Wildcards violate least privilege and grant unintended access to PHI stores.

wildcard_in_policy(policy_str) {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    endswith(action, ":*")
}

wildcard_in_policy(policy_str) {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    stmt.Action == "*"
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] != "delete"
    policy_str := resource.change.after.policy
    policy_str != null
    wildcard_in_policy(policy_str)
    msg := sprintf("AC.L2-3.1.5 [GAP-07]: %v contains a wildcard action — use scoped least-privilege actions", [resource.address])
}
