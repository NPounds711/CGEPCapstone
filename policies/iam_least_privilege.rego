# ---
# title: IAM role policies must not contain wildcard actions
# description: Wildcard actions (service:* or bare *) in Lambda inline policies grant unintended access to PHI data stores and violate least privilege.
# custom:
#   framework: CMMC Level 2
#   control_id: AC.L2-3.1.5
#   severity: HIGH
#   remediation: Replace wildcard actions with the minimum required set, e.g. dynamodb:PutItem, dynamodb:GetItem, s3:PutObject.
package main

import rego.v1

wildcard_in_policy(policy_str) if {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    action := stmt.Action[_]
    endswith(action, ":*")
}

wildcard_in_policy(policy_str) if {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    stmt.Action == "*"
}

wildcard_in_policy(policy_str) if {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Allow"
    is_string(stmt.Action)
    endswith(stmt.Action, ":*")
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] != "delete"
    policy_str := resource.change.after.policy
    policy_str != null
    wildcard_in_policy(policy_str)
    msg := sprintf("AC.L2-3.1.5 [GAP-07]: %v contains a wildcard action — use scoped least-privilege actions", [resource.address])
}
