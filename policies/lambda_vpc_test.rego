package main

import rego.v1

test_deny_lambda_no_vpc if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_lambda_function.intake",
        "type": "aws_lambda_function",
        "change": {"actions": ["create"], "after": {
            "vpc_config": [],
            "dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:dlq"}],
            "tracing_config": [{"mode": "Active"}]
        }}
    }]}
}

test_allow_lambda_with_vpc if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_lambda_function.intake",
        "type": "aws_lambda_function",
        "change": {"actions": ["create"], "after": {
            "vpc_config": [{"subnet_ids": ["subnet-123"], "security_group_ids": ["sg-123"]}],
            "dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:123456789012:dlq"}],
            "tracing_config": [{"mode": "Active"}]
        }}
    }]}
}
