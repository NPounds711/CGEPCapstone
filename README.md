# CGE-P Capstone — Acme Health Patient Intake API

**Candidate:** Nicole Pounds  
**Primary Framework:** CMMC Level 2 (NIST SP 800-171 Rev 2)  
**Secondary Frameworks:** HIPAA Security Rule, SOC 2 Type II (residual coverage)

> This repository is forked from `GRCEngClub/cgep-app-starter`, an intentionally
> non-compliant workload designed to be governed. All code under `terraform/`
> (except the original `main.tf`, `variables.tf`, `outputs.tf`, and
> `lambda/handler.py`), `policies/`, `oscal/`, `.github/workflows/`, and the
> top-level `WRITEUP.md`, `WORKLOAD.md`, and `Makefile` is original capstone
> work.

## Repository layout

```
CGEPCapstone/
├── WRITEUP.md                          # Framework justification and design decisions
├── WORKLOAD.md                         # Workload narrative
├── GAPS.md                             # Named flaws in the starter workload
├── FRAMEWORKS.md                       # Framework mapping reference
├── LICENSE                             # MIT
├── Makefile                            # Grader-facing convenience targets
├── terraform/
│   ├── main.tf                         # Original starter workload (untouched)
│   ├── variables.tf                    # Original starter variables
│   ├── outputs.tf                      # Original starter outputs
│   ├── lambda/handler.py               # Original starter Lambda source
│   ├── kms.tf                          # GRC overlay: customer-managed KMS keys
│   ├── s3_baseline.tf                  # GRC overlay: SSE-KMS, TLS deny, versioning, vault
│   ├── cloudtrail.tf                   # GRC overlay: multi-region trail + log-file validation
│   ├── networking_baseline.tf          # GRC overlay: VPC, private subnets, security groups
│   ├── lambda_baseline.tf              # GRC overlay: VPC config, DLQ, X-Ray, IAM scoping
│   ├── apigw_baseline.tf               # GRC overlay: access logging, throttling
│   └── monitoring.tf                   # GRC overlay: CloudWatch metric filters + alarms
├── policies/                           # OPA/Rego policies (7 policies, 7 test files)
├── scripts/                            # Helper scripts
├── docs/
│   └── verification.md                 # Tier 0 static-analysis evidence
├── oscal/
│   ├── component-definitions/          # OSCAL component-definition.json (trestle VALID)
│   └── profiles/                       # OSCAL profile selecting CMMC L2 controls
├── test/                               # Smoke test against deployed API
└── .github/workflows/                  # CI: scan -> plan -> conftest -> apply -> sign -> vault
```

## Prerequisites

- Terraform `>= 1.6` (CI pins `1.6.6`)
- AWS CLI v2, with a profile named `sandbox` configured for the target account
- Python 3.10+ (for `compliance-trestle`)
- `conftest` (CI pins `0.51.0`) or `opa` for the policy suite
- Optional for Tier 0 static analysis: `checkov`, `tflint`, `gitleaks`, `semgrep`

## Static-analysis evidence

See [docs/verification.md](docs/verification.md) for the most recent local
results of `terraform fmt`, `terraform validate`, `checkov`, `tflint`,
`gitleaks`, `semgrep`, and `opa test` against this repository. The CI pipeline
re-runs the same scanners on every PR and push.

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
