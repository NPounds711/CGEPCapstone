# ---
# title: TLS enforcement required on S3 bucket policies
# description: Every S3 bucket policy must deny requests where aws:SecureTransport is false. PHI transmitted over HTTP is unencrypted.
# custom:
#   framework: CMMC Level 2
#   control_id: SC.L2-3.13.8
#   severity: HIGH
#   remediation: Add a Deny statement to the bucket policy with Condition Bool aws:SecureTransport = false.
package main

import rego.v1

has_tls_deny(policy_str) if {
    policy := json.unmarshal(policy_str)
    stmt := policy.Statement[_]
    stmt.Effect == "Deny"
    lower(stmt.Condition.Bool["aws:SecureTransport"]) == "false"
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_policy"
    resource.change.actions[_] != "delete"
    policy_str := resource.change.after.policy
    policy_str != null
    not has_tls_deny(policy_str)
    msg := sprintf("SC.L2-3.13.8 [GAP-03]: %v does not deny non-TLS requests — add Deny with aws:SecureTransport = false", [resource.address])
}
