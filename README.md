# CGE-P Capstone — Acme Health Patient Intake API

**Candidate:** Nicole Pounds  
**Primary Framework:** CMMC Level 2 (NIST SP 800-171 Rev 2)  
**Secondary Frameworks:** HIPAA Security Rule, SOC 2 Type II (residual coverage)

## Repository layout

```
CGEPCapstone/
├── WRITEUP.md                          # Framework justification and design decisions
├── GAPS.md                             # Named flaws in the starter workload
├── FRAMEWORKS.md                       # Framework mapping reference
├── terraform/
│   ├── main.tf                         # Original starter workload (do not modify)
│   ├── variables.tf
│   ├── outputs.tf
│   └── baseline/                       # GRC overlay: KMS, evidence vault, CloudTrail,
│                                       # SSE-KMS overrides, TLS policy, versioning,
│                                       # Lambda VPC/DLQ/X-Ray, API GW logging, IAM scoping
├── policies/                           # OPA/Rego policies (one per gap family)
├── scripts/                            # Helper scripts (sign, upload, verify)
├── oscal/
│   ├── component-definitions/          # OSCAL component-definition.json
│   └── profiles/                       # OSCAL profile selecting CMMC L2 controls
└── .github/workflows/                  # CI/CD pipeline: plan, conftest, apply, sign, vault
```

## Grader verification

### 1. Deploy the workload

```bash
cd terraform
terraform init
terraform plan -var="aws_region=us-east-1"
terraform apply -var="aws_region=us-east-1" -auto-approve
```

### 2. Run the OPA policy suite against a plan

```bash
terraform plan -out=tfplan -var="aws_region=us-east-1"
terraform show -json tfplan > tfplan.json
conftest test tfplan.json --policy policies/
```

All seven policies must pass with no violations.

### 3. Verify the OSCAL component

```bash
pip install compliance-trestle
trestle validate -f oscal/component-definitions/acme-health-intake/component-definition.json
```

Expected: `VALID`

### 4. Tear down

```bash
cd terraform
terraform destroy -var="aws_region=us-east-1" -auto-approve
```

## Framework justification

See [WRITEUP.md](WRITEUP.md) for a full explanation of why CMMC Level 2 was chosen as the primary framework, how each gap maps to a CMMC practice, and what residual HIPAA and SOC 2 coverage the architecture produces.

## Gap-to-control mapping

| Gap | Summary | CMMC Practice |
|-----|---------|---------------|
| GAP-01 | S3 SSE-S3 instead of CMK | SC.L2-3.13.11 |
| GAP-02 | DynamoDB AWS-owned key | SC.L2-3.13.11 |
| GAP-03 | No TLS enforcement on S3 | SC.L2-3.13.8 |
| GAP-04 | No S3 versioning | MP.L2-3.8.9 |
| GAP-05 | Lambda outside VPC | SC.L2-3.13.1 |
| GAP-06 | No DLQ, X-Ray, or concurrency limit | SI.L2-3.14.6 |
| GAP-07 | Wildcard IAM permissions | AC.L2-3.1.5 |
| GAP-08 | No API Gateway logging or throttling | AU.L2-3.3.1 |
