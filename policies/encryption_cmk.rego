package main

# SC.L2-3.13.11 — GAP-01, GAP-02
# Every S3 SSE configuration must use aws:kms.
# Every DynamoDB table must have CMK server-side encryption enabled.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
    rule := resource.change.after.rule[_]
    sse := rule.apply_server_side_encryption_by_default[_]
    sse.sse_algorithm != "aws:kms"
    msg := sprintf("SC.L2-3.13.11 [GAP-01]: %v uses %v — SSE-KMS with a customer CMK is required for PHI", [resource.address, sse.sse_algorithm])
}

has_dynamodb_cmk(resource) {
    sse := resource.change.after.server_side_encryption[_]
    sse.enabled == true
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_dynamodb_table"
    resource.change.actions[_] != "delete"
    not has_dynamodb_cmk(resource)
    msg := sprintf("SC.L2-3.13.11 [GAP-02]: %v must have server_side_encryption with enabled = true and a customer CMK", [resource.address])
}
