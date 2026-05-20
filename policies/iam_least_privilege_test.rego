package main

import rego.v1

test_deny_iam_wildcard_service if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_iam_role_policy.lambda_inline",
        "type": "aws_iam_role_policy",
        "change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:*\"}]}"}}
    }]}
}

test_deny_iam_wildcard_bare if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_iam_role_policy.lambda_inline",
        "type": "aws_iam_role_policy",
        "change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}}
    }]}
}

test_allow_iam_scoped_actions if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_iam_role_policy.lambda_inline",
        "type": "aws_iam_role_policy",
        "change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"arn:aws:dynamodb:*\"}]}"}}
    }]}
}
