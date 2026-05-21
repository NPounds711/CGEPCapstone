# Local Verification Evidence

This document records the most recent Tier 0 static-analysis results against
this repository. The same checks run in CI (`.github/workflows/grc-gate.yml`)
on every pull request and push to `main`.

**Last run:** 2026-05-21
**Repository commit:** `git rev-parse HEAD` at time of run

## Tool versions

| Tool | Version |
|---|---|
| terraform | 1.15.2 (darwin_amd64) |
| checkov | latest pip release |
| conftest | 0.51.0 |
| opa | latest |
| gitleaks | latest (Homebrew) |
| trestle | compliance-trestle latest |

## Results

### `terraform fmt -check -recursive`

```
$ cd terraform && terraform fmt -check -recursive
$ echo $?
0
```

No diffs.

### `terraform validate`

```
$ cd terraform && terraform init -backend=false -input=false && terraform validate
Success! The configuration is valid.
```

### `checkov -d terraform/`

```
passed: 82  failed: 0
HIGH/CRITICAL failures: (none)
```

Full results stored as CI artifact `checkov-sarif` on every run.

### `opa test policies/`

```
PASS: 18/18
```

7 deny-by-default policies, each with at least one positive and one negative
test fixture. Every policy carries a `framework: CMMC Level 2` and a specific
`control_id` in its METADATA block.

### `gitleaks detect`

```
14 commits scanned.
scanned ~119031 bytes (119.03 KB) in 103ms
no leaks found
```

### `trestle validate` (OSCAL)

```
$ cd oscal && trestle validate -f component-definitions/acme-health-intake/component-definition.json
VALID: Model passed the Validator to confirm the model passes all registered validation tests.

$ cd oscal && trestle validate -f profiles/cmmc-l2-minimum/profile.json
VALID: Model passed the Validator to confirm the model passes all registered validation tests.
```

## Tools recommended for graders to re-run locally

```bash
# Terraform static analysis
cd terraform
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
cd ..
checkov -d terraform/ --quiet --compact

# Secret scan
gitleaks detect --no-banner

# Policy unit tests
opa test policies/

# OSCAL validation
cd oscal
trestle validate -f component-definitions/acme-health-intake/component-definition.json
trestle validate -f profiles/cmmc-l2-minimum/profile.json
```
