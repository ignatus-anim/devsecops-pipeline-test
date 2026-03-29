# DevSecOps Pipeline Test Repo

A minimal test repository for validating the Jenkins DevSecOps pipeline templates.

## What's in here

| File | Purpose |
|---|---|
| `Jenkinsfile` | Combined pre-commit + build pipeline for testing |
| `main.py` | Simple Flask app — gives Syft/Grype something to scan |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Container image definition |
| `terraform/main.tf` | Intentionally misconfigured IaC — should trigger Checkov HIGH/CRITICAL findings |
| `dummy-secrets.env` | Fake credentials — should trigger Gitleaks and block the pipeline |

## Expected behaviour

| Stage | Expected Result |
|---|---|
| Secret Detection | **FAIL** — `dummy-secrets.env` contains fake AWS keys, GitHub token, and Stripe key |
| SBOM Generation | Pass |
| SCA | Pass or Fail depending on Flask vulnerability state |
| License Compliance | Pass — Flask uses BSD-3-Clause |
| Container Image Build | Pass |
| Container Image Scanning | Pass or Fail depending on base image vulnerability state |
| IaC Scanning | **FAIL** — `terraform/main.tf` has open security groups and public S3 bucket |

## How to test

### Option A — Paste into Jenkins directly
1. Jenkins → New Item → Pipeline
2. Pipeline Definition → Pipeline script
3. Paste the contents of `Jenkinsfile`

### Option B — Point Jenkins at this repo (recommended)
1. Push this folder to a GitHub/GitLab repo
2. Jenkins → New Item → Pipeline
3. Pipeline Definition → Pipeline script from SCM
4. Set SCM to Git and provide the repo URL

## Prerequisites on the Jenkins agent

```bash
docker --version    # required for image build and scan
python3 --version   # required for Checkov and license check
pip --version       # required for Checkov install
curl --version      # required for tool downloads
```

## Removing the intentional failures

Once you have confirmed the gates are working:

- **Secret Detection** — delete `dummy-secrets.env`
- **IaC Scanning** — fix `terraform/main.tf` (enable versioning, block public access, restrict security group ingress)
