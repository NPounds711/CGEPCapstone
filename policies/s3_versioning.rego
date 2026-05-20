# ---
# title: S3 versioning must be enabled
# description: Versioning must be Enabled on all S3 buckets that store PHI or audit evidence. Without versioning, object overwrites are unrecoverable.
# custom:
#   framework: CMMC Level 2
#   control_id: MP.L2-3.8.9
#   severity: MEDIUM
#   remediation: Add aws_s3_bucket_versioning with versioning_configuration { status = "Enabled" }.
package main

import rego.v1

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    resource.change.actions[_] != "delete"
    vc := resource.change.after.versioning_configuration[_]
    vc.status != "Enabled"
    msg := sprintf("MP.L2-3.8.9 [GAP-04]: %v versioning.status is %v — must be Enabled", [resource.address, vc.status])
}
