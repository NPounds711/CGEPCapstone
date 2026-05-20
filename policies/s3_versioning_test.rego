package main

import rego.v1

test_deny_versioning_suspended if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.uploads",
        "type": "aws_s3_bucket_versioning",
        "change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Suspended"}]}}
    }]}
}

test_allow_versioning_enabled if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_versioning.uploads",
        "type": "aws_s3_bucket_versioning",
        "change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Enabled"}]}}
    }]}
}
