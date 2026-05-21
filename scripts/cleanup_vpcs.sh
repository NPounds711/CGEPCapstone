#!/usr/bin/env bash
# Deletes all orphaned acme-health-intake VPCs and their dependent resources
set -euo pipefail

PROFILE="sandbox"
REGION="us-east-1"

VPC_IDS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-vpcs \
  --filters "Name=tag:Project,Values=acme-health-intake" \
  --query "Vpcs[*].VpcId" --output text)

if [[ -z "$VPC_IDS" ]]; then
  echo "No project VPCs found."
  exit 0
fi

echo "Found VPCs to delete: $VPC_IDS"

delete_vpc() {
  local VPC_ID="$1"
  echo "--- Cleaning up $VPC_ID ---"

  # VPC endpoints — request deletion and wait for ENIs to clear
  ENDPOINTS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=vpc-endpoint-state,Values=available,pending" \
    --query "VpcEndpoints[*].VpcEndpointId" --output text)
  if [[ -n "$ENDPOINTS" ]]; then
    echo "  Deleting endpoints: $ENDPOINTS"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-vpc-endpoints \
      --vpc-endpoint-ids $ENDPOINTS > /dev/null
    echo "  Waiting for endpoints to fully delete..."
    aws --profile "$PROFILE" --region "$REGION" ec2 wait vpc-endpoint-deleted \
      --filters "Name=vpc-id,Values=$VPC_ID" 2>/dev/null || true
    sleep 10
  fi

  # Network interfaces — detach and delete any remaining ENIs
  ENIS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "NetworkInterfaces[*].NetworkInterfaceId" --output text)
  for ENI in $ENIS; do
    ATTACH_ID=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-network-interfaces \
      --network-interface-ids "$ENI" \
      --query "NetworkInterfaces[0].Attachment.AttachmentId" --output text 2>/dev/null || true)
    if [[ -n "$ATTACH_ID" && "$ATTACH_ID" != "None" && "$ATTACH_ID" != "null" ]]; then
      echo "  Detaching ENI: $ENI (attachment $ATTACH_ID)"
      aws --profile "$PROFILE" --region "$REGION" ec2 detach-network-interface \
        --attachment-id "$ATTACH_ID" --force 2>/dev/null || true
      sleep 3
    fi
    echo "  Deleting ENI: $ENI"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-network-interface \
      --network-interface-id "$ENI" 2>/dev/null || true
  done

  # Internet gateways
  IGWS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-internet-gateways \
    --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
    --query "InternetGateways[*].InternetGatewayId" --output text)
  for IGW in $IGWS; do
    echo "  Detaching and deleting IGW: $IGW"
    aws --profile "$PROFILE" --region "$REGION" ec2 detach-internet-gateway \
      --internet-gateway-id "$IGW" --vpc-id "$VPC_ID"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-internet-gateway \
      --internet-gateway-id "$IGW"
  done

  # Subnets — try once, wait, retry
  SUBNETS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[*].SubnetId" --output text)
  for SUBNET in $SUBNETS; do
    echo "  Deleting subnet: $SUBNET"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-subnet \
      --subnet-id "$SUBNET" 2>/dev/null || echo "  (will retry after wait)"
  done

  sleep 8

  SUBNETS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[*].SubnetId" --output text)
  for SUBNET in $SUBNETS; do
    echo "  Retry deleting subnet: $SUBNET"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-subnet --subnet-id "$SUBNET"
  done

  # Route tables (skip main)
  RTS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.main,Values=false" \
    --query "RouteTables[*].RouteTableId" --output text)
  for RT in $RTS; do
    echo "  Deleting route table: $RT"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-route-table --route-table-id "$RT"
  done

  # Security groups (skip default)
  SGS=$(aws --profile "$PROFILE" --region "$REGION" ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "SecurityGroups[?GroupName!='default'].GroupId" --output text)
  for SG in $SGS; do
    echo "  Deleting security group: $SG"
    aws --profile "$PROFILE" --region "$REGION" ec2 delete-security-group \
      --group-id "$SG" 2>/dev/null || true
  done

  # Delete VPC
  echo "  Deleting VPC: $VPC_ID"
  aws --profile "$PROFILE" --region "$REGION" ec2 delete-vpc --vpc-id "$VPC_ID"
  echo "  Done: $VPC_ID"
}

for VPC_ID in $VPC_IDS; do
  delete_vpc "$VPC_ID"
done

echo "All project VPCs deleted."
