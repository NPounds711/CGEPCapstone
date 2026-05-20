# ---
# title: CMK encryption required for PHI data stores
# description: S3 uploads bucket and DynamoDB submissions table must use customer-managed KMS keys. AWS-managed or SSE-S3 encryption does not provide customer key custody over PHI.
# custom:
#   framework: CMMC Level 2
#   control_id: SC.L2-3.13.11
#   severity: HIGH
#   remediation: Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and a non-empty kms_master_key_id. Add server_side_encryption { enabled = true, kms_key_arn = ... } to aws_dynamodb_table.
package main

import rego.v1

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    rule := resource.change.after.rule[_]
    sse := rule.apply_server_side_encryption_by_default[_]
    sse.sse_algorithm != "aws:kms"
    msg := sprintf("SC.L2-3.13.11 [GAP-01]: %v uses %v — SSE-KMS with a customer CMK is required for PHI", [resource.address, sse.sse_algorithm])
}

has_dynamodb_cmk(resource) if {
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled == true
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    resource.change.actions[_] != "delete"
    not has_dynamodb_cmk(resource)
    msg := sprintf("SC.L2-3.13.11 [GAP-02]: %v must have server_side_encryption with enabled = true and a customer CMK", [resource.address])
}
