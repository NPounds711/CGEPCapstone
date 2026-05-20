package main

import rego.v1

test_deny_s3_sse_aes256 if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"actions": ["create"], "after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256", "kms_master_key_id": ""}], "bucket_key_enabled": false}]}}
    }]}
}

test_deny_dynamodb_no_sse if {
    deny[_] with input as {"resource_changes": [{
        "address": "aws_dynamodb_table.intake",
        "type": "aws_dynamodb_table",
        "change": {"actions": ["create"], "after": {"server_side_encryption": []}}
    }]}
}

test_allow_s3_sse_kms if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
        "type": "aws_s3_bucket_server_side_encryption_configuration",
        "change": {"actions": ["create"], "after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/test"}], "bucket_key_enabled": true}]}}
    }]}
}

test_allow_dynamodb_cmk_sse if {
    count(deny) == 0 with input as {"resource_changes": [{
        "address": "aws_dynamodb_table.intake",
        "type": "aws_dynamodb_table",
        "change": {"actions": ["create"], "after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test"}]}}
    }]}
}
