package main

# AU.L2-3.3.1 — GAP-08
# Every API Gateway v2 stage must have access_log_settings with a non-null
# destination ARN. Without access logging, API-layer audit events are lost.

has_access_logging(resource) {
    als := resource.change.after.access_log_settings[_]
    als.destination_arn != null
    als.destination_arn != ""
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_apigatewayv2_stage"
    resource.change.actions[_] != "delete"
    not has_access_logging(resource)
    msg := sprintf("AU.L2-3.3.1 [GAP-08]: %v has no access_log_settings — API access logs must ship to CloudWatch", [resource.address])
}
