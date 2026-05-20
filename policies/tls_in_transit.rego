package main

# SC.L2-3.13.8 — GAP-03
# Every S3 bucket policy must contain a Deny statement that rejects
# requests where aws:SecureTransport is false.

has_tls_deny(policy_str) {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Deny"
    lower(stmt.Condition.Bool["aws:SecureTransport"]) == "false"
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_policy"
    resource.change.actions[_] != "delete"
    policy_str := resource.change.after.policy
    policy_str != null
    not has_tls_deny(policy_str)
    msg := sprintf("SC.L2-3.13.8 [GAP-03]: %v does not deny non-TLS requests — add Deny with aws:SecureTransport = false", [resource.address])
}
