# ---
# title: API Gateway stages must have access logging enabled
# description: API Gateway v2 stages without access_log_settings produce no audit trail of API-layer requests. PHI submission events are unrecorded.
# custom:
#   framework: CMMC Level 2
#   control_id: AU.L2-3.3.1
#   severity: HIGH
#   remediation: Add access_log_settings { destination_arn = aws_cloudwatch_log_group.apigw.arn } to aws_apigatewayv2_stage.
package main

import rego.v1

has_access_logging(resource) if {
    als := resource.change.after.access_log_settings[_]
    als.destination_arn != null
    als.destination_arn != ""
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_apigatewayv2_stage"
    resource.change.actions[_] != "delete"
    not has_access_logging(resource)
    msg := sprintf("AU.L2-3.3.1 [GAP-08]: %v has no access_log_settings — API access logs must ship to CloudWatch", [resource.address])
}
