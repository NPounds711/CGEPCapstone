package main

# MP.L2-3.8.9 — GAP-04
# Every S3 bucket versioning resource must have status = Enabled.
# Versioning is required to recover from accidental overwrite of PHI objects.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    resource.change.actions[_] != "delete"
    vc := resource.change.after.versioning_configuration[_]
    vc.status != "Enabled"
    msg := sprintf("MP.L2-3.8.9 [GAP-04]: %v versioning.status is %v — must be Enabled", [resource.address, vc.status])
}
