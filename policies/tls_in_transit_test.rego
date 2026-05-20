package main

import rego.v1

test_deny_bucket_policy_no_tls if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_s3_bucket_policy.uploads",
        "type": "aws_s3_bucket_policy",
        "change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::test/*\"}]}"}}
    }]}
}

test_allow_bucket_policy_with_tls if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_policy.uploads_tls",
        "type": "aws_s3_bucket_policy",
        "change": {"actions": ["create"], "after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::test\",\"arn:aws:s3:::test/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"}}
    }]}
}
