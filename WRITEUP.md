# WRITEUP.md — Acme Health Patient Intake API GRC Capstone

**Primary Framework: CMMC Level 2 (NIST SP 800-171)**

The primary framework for this capstone is CMMC Level 2, implemented through its normative basis in NIST SP 800-171 Rev 2. Every OPA policy, every Terraform override, and every OSCAL control-implementation statement in this repo is anchored to a CMMC L2 practice ID. HIPAA Security Rule and SOC 2 Type II are treated as secondary beneficiaries — the architecture is designed so that satisfying CMMC's 110 practices produces substantial residual coverage of both, but neither is declared primary and neither drives any design decision that conflicts with CMMC.

> **OSCAL catalog note:** NIST does not publish an OSCAL catalog for SP 800-171 Rev 2. The OSCAL component in this repo uses the SP 800-171 Rev 3 catalog (`NIST_SP800-171_rev3_catalog.json`), which is the most current machine-readable version published by NIST. Practice IDs referenced in all implementation statements correspond to Rev 2 practices; the Rev 2-to-Rev 3 delta does not affect the eight gaps closed in this build.

---

## 1. Framework Choice: Why CMMC Level 2

### The business context

Acme Health has three compliance signals arriving simultaneously: a federal pilot that requires CMMC Level 2, an enterprise customer requiring SOC 2 Type II, and PHI on the wire that makes HIPAA Security Rule non-negotiable as a matter of law. With 30 days, one GRC engineer, and an instruction not to slow engineering down, pursuing all three independently is not feasible. The question is which framework, if used as the technical anchor, leaves the smallest residual gap across the other two.

### Why not HIPAA

HIPAA Security Rule is the legal floor, not the technical ceiling. Its 54 implementation specifications are written for healthcare administrators, not infrastructure engineers. It tells you what to protect (PHI confidentiality, integrity, availability) but not how to protect it. An organization can be fully HIPAA-compliant with a weak security posture because the rule allows flexibility in implementation. More critically, satisfying HIPAA does not close the technical gaps in this codebase. A HIPAA-anchored approach produces the right documentation and the right breach notification procedures, but it does not inherently produce the encryption key custody controls (GAP-01, GAP-02), the network segmentation (GAP-05), or the least-privilege IAM posture (GAP-07) that the starter is missing. Those require a technically prescriptive standard.

### Why not SOC 2

SOC 2 is principles-based. The Trust Services Criteria tell you the outcome you need to demonstrate — for example, CC6.1 requires logical access controls — but the criteria do not specify how those controls are implemented technically. A SOC 2 audit is a point-in-time or period attestation; it asks whether your controls were operating effectively during the audit window. That is the right end state, but it is not the right starting point for a 30-day sprint to make a non-compliant API defensible. Starting from SOC 2 criteria leaves too many implementation decisions undefined, which means the engineering team gets vague requirements and inconsistent policy enforcement.

### Why CMMC Level 2

CMMC Level 2 maps directly to all 110 practices in NIST SP 800-171 Rev 2. Each practice has a specific, testable requirement. Practice AC.L2-3.1.5 does not say "implement appropriate access controls" — it says "employ the principle of least privilege, including for specific security functions and privileged accounts." That specificity is what makes it automatable: I can write a Rego policy that detects `dynamodb:*` in an IAM policy and fails the plan with a message that cites AC.L2-3.1.5. I cannot do that with "CC6.3" alone without adding an interpretation layer.

The second reason is control coverage. Of the eight gaps in this starter, every single one maps to at least one CMMC L2 practice:

| Gap | Root Cause | CMMC Practice |
|---|---|---|
| GAP-01 | SSE-S3 instead of CMK on S3 | SC.L2-3.13.11 |
| GAP-02 | AWS-owned key on DynamoDB | SC.L2-3.13.11 |
| GAP-03 | No TLS-enforcement bucket policy | SC.L2-3.13.8 |
| GAP-04 | No S3 versioning | MP.L2-3.8.9 |
| GAP-05 | Lambda outside the VPC | SC.L2-3.13.1 |
| GAP-06 | No DLQ or X-Ray tracing | SI.L2-3.14.6 |
| GAP-07 | Wildcard IAM permissions | AC.L2-3.1.5 |
| GAP-08 | No API Gateway logging or throttling | AU.L2-3.3.1 |

HIPAA and SOC 2 map to the same eight gaps, but their control language is less precise. Building to CMMC L2 closes them in a way that is also defensible to a HIPAA auditor and a SOC 2 assessor — the reverse is not guaranteed.

The third reason is timeline alignment. CMMC Level 2 assessments are conducted by certified third-party assessment organizations (C3PAOs), but the framework's explicit, machine-readable control structure makes it the easiest of the three to express in OPA policies and OSCAL. HIPAA has no public OSCAL catalog maintained by HHS. SOC 2 criteria are expressed in attestation language, not machine-readable controls. NIST SP 800-171's OSCAL catalog is published and maintained by NIST. That matters when the deliverable includes a validated `component-definition.json`.

### Residual coverage of HIPAA and SOC 2

Anchoring to CMMC L2 is not a concession on HIPAA compliance — it is the fastest path to satisfying HIPAA's technical safeguards. The gaps this build closes (CMK custody, TLS enforcement, VPC isolation, least-privilege IAM, audit logging) satisfy HIPAA 164.312(a)(2)(iv), 164.312(e)(1), 164.312(a)(1), and 164.312(b) as a byproduct. The residual HIPAA gaps — Business Associate Agreements, breach notification procedures, minimum-necessary workforce policies — are organizational and legal, not technical. They are documented in the OSCAL component as policy-satisfied controls and flagged for the sprint backlog.

For SOC 2, the technical controls built here (encryption, access control, monitoring, availability via versioning) address CC6.1, CC6.3, CC6.6, CC6.7, CC7.2, A1.2, and A1.3. The assessor will still need to see vendor management, change management, and board-level risk documentation — those do not come from infrastructure code, and they are not claimed here.

---

## 2. Gap Remediation Strategy

Each gap is addressed in one or more of three layers. The choice of layer reflects whether the gap is best fixed in infrastructure (Terraform), enforced preventively (OPA/Conftest), or documented as a process control (OSCAL).

**GAP-01 and GAP-02 (Encryption key custody):** Both addressed in Terraform. A customer-managed KMS key with rotation enabled is provisioned and set as the SSE-KMS key for the S3 uploads bucket and the DynamoDB table. This is a Terraform fix because the gap is a resource attribute, not a policy decision — there is no safe version of "S3 encrypted with AWS-managed key" for PHI. The OPA policy `encryption_cmk.rego` blocks any future plan that introduces an SSE-S3 or AWS-owned-key configuration. Control: SC.L2-3.13.11.

**GAP-03 (TLS enforcement):** Addressed in Terraform via an `aws_s3_bucket_policy` that denies all requests where `aws:SecureTransport` is false. Also covered by `tls_in_transit.rego`. Control: SC.L2-3.13.8.

**GAP-04 (Versioning):** Addressed in Terraform via `aws_s3_bucket_versioning`. The evidence vault bucket also has Object Lock in GOVERNANCE mode (see design decision below). OPA policy `s3_versioning.rego` enforces this going forward. Control: MP.L2-3.8.9.

**GAP-05 (Lambda VPC isolation):** Addressed in Terraform by adding a `vpc_config` block to `aws_lambda_function.intake`, placing it in the private subnet of the VPC the starter already provisions. No new VPC is created. The policy `lambda_vpc.rego` fails any plan that removes or omits the VPC config. Control: SC.L2-3.13.1.

**GAP-06 (Observability):** Addressed in Terraform with a dead-letter queue backed by SQS and X-Ray active tracing. The OPA policy `lambda_observability.rego` checks for the DLQ and tracing config. Reserved concurrency was omitted — the sandbox account's total concurrency ceiling is too low to set a reservation without violating the AWS-enforced minimum of 10 unreserved executions; this is documented as a residual gap. Control: SI.L2-3.14.6.

**GAP-07 (Least-privilege IAM):** Addressed in Terraform by replacing the wildcard `dynamodb:*` and `s3:*` permissions with scoped action lists: `dynamodb:PutItem`, `dynamodb:GetItem`, `s3:PutObject`. The OPA policy `iam_least_privilege.rego` fails any plan where a Lambda inline policy contains `*` as an action on the workload resources. Control: AC.L2-3.1.5.

**GAP-08 (API Gateway logging/throttling):** Addressed in Terraform by enabling access logging on the API Gateway stage (writing to CloudWatch Logs) and adding default route throttling. The OPA policy `apigw_logging.rego` checks for the access log destination ARN. Control: AU.L2-3.3.1.

---

## 3. Design Decisions

**Object Lock mode: GOVERNANCE**

The evidence vault S3 bucket uses GOVERNANCE mode Object Lock with a 365-day retention period. COMPLIANCE mode was evaluated and rejected for this sandbox environment: COMPLIANCE mode prevented clean teardown of the vault bucket between test cycles because no principal — including root — can delete locked objects before the retention period expires. In a 30-day lab with repeated deploy-test-destroy cycles this creates orphaned buckets with objects locked until 2027. GOVERNANCE mode still provides meaningful immutability guarantees — objects cannot be deleted without the `s3:BypassGovernanceRetention` permission, which is not granted to the pipeline role — while remaining operationally manageable. In a production deployment with a dedicated evidence account, COMPLIANCE mode would be the correct choice.

**Single AWS account**

The evidence vault runs in the same AWS account as the workload. The cleaner architecture — a dedicated evidence account with cross-account S3 access — is acknowledged but deferred. A separate account eliminates the scenario where a compromised workload-account principal deletes evidence. In 30 days, with no existing account vending process, standing up a separate account introduces more operational risk (broken cross-account IAM, Terraform state split) than it mitigates. The Object Lock GOVERNANCE mode and the CloudTrail trail covering the evidence bucket provide compensating controls. This is a documented residual risk in the OSCAL component.

**Terraform state management: local state, documented choice**

The Terraform configuration uses local state rather than a remote backend. A remote backend (S3 + DynamoDB lock table) would be the correct choice for a team environment — it prevents concurrent applies and provides state history. For a single-engineer 30-day capstone with no collaborators, local state is acceptable. The tradeoff is that state is not preserved between GitHub Actions runs; each pipeline apply starts from empty state. This means the pipeline is idempotent but not incremental: a second push to main would attempt to create all resources again and fail on existing resource conflicts. The practical mitigation is that the pipeline is triggered once per submission cycle, not continuously. A production deployment would add an S3 backend block and the corresponding DynamoDB lock table.

**Continuous monitoring: CloudWatch metric filters and alarms**

Four CloudWatch metric filters are wired to the CloudTrail log group in `monitoring.tf`, each targeting a specific CMMC control scenario: root account usage (AU.L2-3.3.1, IA.L2-3.5.3), IAM policy changes (AC.L2-3.1.5), CloudTrail configuration changes (AU.L2-3.3.1), and KMS key deletion (SC.L2-3.13.11). Each filter has a paired CloudWatch alarm that routes to an SNS topic (`security-alerts`). This provides real-time drift detection against the four highest-risk event categories for this workload — any of these events firing in a live environment would indicate either an operational error or an active compromise.

**Pipeline apply gate: merge to main, no manual approval**

The pipeline applies on merge to main without a manual approval step post-merge. The policy gate (Conftest on the plan) is the approval mechanism. If the plan passes policy, apply runs automatically. This keeps the engineering team's deployment velocity intact — adding a manual approval gate would mean GRC is in the critical path for every deploy. The compensating control is that the policy suite must be comprehensive enough that a passing plan is genuinely safe to apply. The five Rego policies cover the eight gaps; a plan that passes all five is not guaranteed to be perfect, but it is guaranteed not to re-introduce the specific violations that the framework's most material controls prohibit. The multi-region CloudTrail trail covers the workload account and provides a detective compensating control for any violation that passes the gate — every API call that modifies a resource is logged, timestamped, and immutably stored, giving the security team a full audit trail to reconstruct any incident.

**Gaps closed in Terraform vs. policy only**

All eight gaps are addressed in Terraform. The OPA policies are additive — they prevent regression, not initial remediation. This is the right order of operations: fix the resource configuration first, then enforce that it stays fixed in CI. Using OPA as the sole remediation layer would mean the live infrastructure is still non-compliant until someone runs a plan that the gate catches. Terraform fixes the state; OPA guards the gate.

---

## 4. Control Coverage Summary

The OSCAL component implements the following CMMC L2 practice families: AC (Access Control), AU (Audit and Accountability), MP (Media Protection), SC (System and Communications Protection), and SI (System and Information Integrity). The OSCAL `source` field points to the NIST SP 800-171 Rev 3 OSCAL catalog published at `https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json`. Implementation statements reference Terraform resource addresses (e.g., `aws_kms_key.cmk`, `aws_s3_bucket.uploads`) and ARNs resolved at apply time.

---

## 5. Trade-offs Accepted

- **HIPAA breach notification is not automated.** The OSCAL component documents the control as policy-satisfied and points to an incident response runbook placeholder. In a production deployment this would be a 72-hour notification workflow wired to GuardDuty findings.
- **No WAF.** WAFv2 WebACL association with API Gateway v2 HTTP API stages fails in this sandbox — the stage ARN format used by HTTP APIs (empty account-ID field) is rejected by the WAFv2 `AssociateWebACL` API. The throttling controls on the API Gateway stage (burst 100, rate 50) provide a compensating control for volumetric abuse. WAF would be re-introduced using a Regional WAFv2 ACL in a production environment where the API Gateway is fronted by an ALB.
- **CloudWatch Logs, not a SIEM.** API Gateway and Lambda logs go to CloudWatch. A production compliance posture would ship logs to a SIEM (Splunk, Datadog Security) for correlation. That integration is out of scope for 30 days.
- **No encryption in transit validation for DynamoDB client.** The Lambda runtime uses the AWS SDK default, which uses TLS. There is no Rego policy enforcing an SDK configuration flag because the Terraform plan does not expose SDK transport settings. This is documented as a detective gap — CloudTrail data events would surface any unexpected plaintext call, but that has not been tested.

---

## 6. What Another Sprint Would Deliver

- Separate evidence-vault AWS account with cross-account S3 replication and SCPs preventing evidence deletion from the workload account.
- GuardDuty enabled with a Lambda-backed finding-to-ticket pipeline, closing SI.L2-3.14.7 (identify unauthorized use).
- AWS Config rules replacing the OPA policies for drift detection in the live account (not just at plan time).
- HIPAA BAA paperwork and breach notification runbook, closing the organizational controls left open in the OSCAL component.
- SOC 2 trust-services mapping document, translating the CMMC control evidence into the CC/A/PI criterion language an assessor expects.

---

## 7. What I Didn't Get To

- **GAP-06 DLQ alerting:** The DLQ is provisioned but there is no CloudWatch alarm on `NumberOfMessagesSent` to the DLQ. A failed Lambda invocation will land in the DLQ silently. This is a monitoring gap, not an infrastructure gap, and it is the highest-priority item for the next sprint.
- **OSCAL profile:** The OSCAL component references the full 800-171 catalog. A profile selecting only the controls this component implements would make the OSCAL more precise and reduce false-positive control claims. Trestle's `profile generate` command would do this in under an hour; it was cut for time.
- **Automated Cosign verification in the pipeline:** The pipeline signs the evidence bundle with Cosign (keyless, via GitHub OIDC) and uploads it to the vault. There is no downstream pipeline step that verifies the signature on the uploaded artifact before marking the run complete. Verification is currently a manual grader step. A production chain-of-custody system would verify on download, not just on upload.
