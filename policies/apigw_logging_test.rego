package main

import rego.v1

test_deny_apigw_no_logging if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_apigatewayv2_stage.default",
        "type": "aws_apigatewayv2_stage",
        "change": {"actions": ["create"], "after": {"access_log_settings": []}}
    }]}
}

test_allow_apigw_with_logging if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_apigatewayv2_stage.default",
        "type": "aws_apigatewayv2_stage",
        "change": {"actions": ["create"], "after": {"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test"}]}}
    }]}
}
