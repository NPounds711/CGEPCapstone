package main

# SI.L2-3.14.6 — GAP-06
# Every Lambda function must have:
#   - dead_letter_config with a non-null target_arn (failed invocations preserved)
#   - tracing_config.mode = Active (X-Ray distributed tracing)

has_dlq(resource) {
    dlq := resource.change.after.dead_letter_config[_]
    dlq.target_arn != null
}

has_active_tracing(resource) {
    tc := resource.change.after.tracing_config[_]
    tc.mode == "Active"
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_dlq(resource)
    msg := sprintf("SI.L2-3.14.6 [GAP-06]: %v has no dead_letter_config — failed invocations must be captured", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_active_tracing(resource)
    msg := sprintf("SI.L2-3.14.6 [GAP-06]: %v tracing_config.mode must be Active", [resource.address])
}
