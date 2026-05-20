# ---
# title: Lambda observability controls required
# description: Lambda functions must have a dead-letter queue for failed invocations and X-Ray active tracing for distributed trace visibility.
# custom:
#   framework: CMMC Level 2
#   control_id: SI.L2-3.14.6
#   severity: HIGH
#   remediation: Add dead_letter_config { target_arn = aws_sqs_queue.dlq.arn } and tracing_config { mode = "Active" } to aws_lambda_function.
package main

import rego.v1

has_dlq(resource) if {
    dlq := resource.change.after.dead_letter_config[_]
    dlq.target_arn != null
}

has_active_tracing(resource) if {
    tc := resource.change.after.tracing_config[_]
    tc.mode == "Active"
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_dlq(resource)
    msg := sprintf("SI.L2-3.14.6 [GAP-06]: %v has no dead_letter_config — failed invocations must be captured", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_active_tracing(resource)
    msg := sprintf("SI.L2-3.14.6 [GAP-06]: %v tracing_config.mode must be Active", [resource.address])
}
