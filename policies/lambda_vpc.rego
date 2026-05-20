package main

# SC.L2-3.13.1 — GAP-05
# Every Lambda function must have a vpc_config block with at least one subnet
# and one security group. A Lambda outside the VPC can reach the internet
# directly and bypasses network segmentation controls.

has_vpc_config(resource) {
    resource.change.after.vpc_config[_]
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    resource.change.actions[_] != "delete"
    not has_vpc_config(resource)
    msg := sprintf("SC.L2-3.13.1 [GAP-05]: %v has no vpc_config — Lambda must run inside the VPC", [resource.address])
}
