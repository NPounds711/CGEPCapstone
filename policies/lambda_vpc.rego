# ---
# title: Lambda functions must run inside the VPC
# description: Lambda functions without vpc_config can reach the public internet directly, bypassing network segmentation controls on PHI traffic.
# custom:
#   framework: CMMC Level 2
#   control_id: SC.L2-3.13.1
#   severity: HIGH
#   remediation: Add vpc_config { subnet_ids = [...] security_group_ids = [...] } to aws_lambda_function using private subnets and an egress-only security group.
package main

import rego.v1

has_vpc_config(resource) if {
    resource.change.after.vpc_config[_]
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_vpc_config(resource)
    msg := sprintf("SC.L2-3.13.1 [GAP-05]: %v has no vpc_config — Lambda must run inside the VPC", [resource.address])
}
