# StigKube

A CLI tool that scans Kubernetes clusters against the DISA Kubernetes STIG (Security Technical Implementation Guide) and generates deployment-aware Ansible remediation playbooks.

## Why This Exists

Getting a Kubernetes cluster through STIG compliance for an ATO (Authority to Operate) is painful:

1. **The STIG is 91 controls** spread across API server, kubelet, etcd, scheduler, controller-manager, and proxy components
2. **Existing tools are enterprise-priced** (GovWin, Anchore Enterprise) or require manual checking
3. **Remediation differs by deployment method** - fixing a kubeadm cluster is different from RKE2, K3s, or OpenShift
4. **Small contractors get stuck** - they need compliance but can't afford $15-30K/year tools

StigKube solves this by:
- Automatically scanning all 91 STIG controls
- Detecting your deployment method (kubeadm, Kubespray, RKE2, K3s, OpenShift)
- Generating Ansible remediation tailored to how your cluster was deployed
- Outputting results in formats auditors expect (text, JSON, XCCDF)

## Installation

```bash
go install github.com/aristonllc/stigkube/cmd/stigkube@latest
```

Or build from source:
```bash
git clone https://github.com/LcncRoot/ariston-stigkube.git
cd ariston-stigkube
go build -o stigkube ./cmd/stigkube/
```

## Quick Start

```bash
# 1. Install
go install github.com/aristonllc/stigkube/cmd/stigkube@latest

# 2. Ensure you have cluster access
kubectl get nodes

# 3. Run a scan
stigkube scan

# 4. Review findings and generate remediation
stigkube scan --remediate --output ./remediation/
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `stigkube scan` | Scan cluster against STIG controls |
| `stigkube remediate` | Generate Ansible remediation from scan results |
| `stigkube report` | Generate reports from saved scan results |
| `stigkube version` | Print version information |

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--kubeconfig` | Path to kubeconfig file | `~/.kube/config` |
| `--output`, `-o` | Output directory for reports and remediation | `./stigkube-output` |

### Scan Command

```bash
# Basic scan using default kubeconfig
stigkube scan

# Scan a specific cluster
stigkube scan --kubeconfig /path/to/kubeconfig

# Scan with JSON output
stigkube scan --json

# Scan with verbose output (shows each check as it runs)
stigkube scan --verbose

# Scan and immediately generate remediation playbook
stigkube scan --remediate

# Full example: scan, output JSON, generate remediation to specific directory
stigkube scan --json --remediate --output ./my-cluster-results/
```

#### Scan Flags

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON instead of text |
| `--remediate` | Generate Ansible remediation after scan |
| `--verbose`, `-v` | Show detailed output during scan |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no CAT I (high severity) failures |
| 1 | Scan completed with CAT I failures, or scan error |

Use exit codes in CI/CD pipelines to gate deployments on STIG compliance.

### Example Workflow

```bash
# 1. Initial assessment
stigkube scan --output ./baseline/

# 2. Review the findings
cat ./baseline/scan-results-*.json | jq '.summary'

# 3. Generate remediation
stigkube scan --remediate --output ./remediation/

# 4. Apply remediation (review first!)
cd ./remediation/
ansible-playbook -i inventory site.yml --check  # Dry run
ansible-playbook -i inventory site.yml          # Apply

# 5. Re-scan to verify
stigkube scan --output ./post-remediation/

# 6. Compare results
diff <(jq '.summary' ./baseline/scan-results-*.json) \
     <(jq '.summary' ./post-remediation/scan-results-*.json)
```

### CI/CD Integration

```yaml
# GitLab CI example
stig-scan:
  stage: security
  script:
    - stigkube scan --json --output ./stig-results/
  artifacts:
    paths:
      - stig-results/
  allow_failure: false  # Fails pipeline on CAT I findings
```

```yaml
# GitHub Actions example
- name: STIG Compliance Scan
  run: |
    stigkube scan --json --output ./stig-results/
  continue-on-error: false
```

## What It Checks

StigKube evaluates controls from the DISA Kubernetes STIG V1R11, including:

| Component | Example Controls |
|-----------|------------------|
| API Server | Anonymous auth disabled, RBAC enabled, audit logging, TLS 1.2+ |
| Kubelet | Authentication required, authorization mode, read-only port disabled |
| etcd | Client cert auth, peer cert auth, encryption at rest |
| Scheduler | Profiling disabled, secure binding |
| Controller Manager | Service account credentials, secure port |
| General | Namespace isolation, pod security standards, secrets management |

## Output

### Text Report (default)
```
============================================================
STIG COMPLIANCE SCAN RESULTS
============================================================

Cluster: my-cluster
Kubernetes Version: v1.28.4
Deployment Method: kubeadm
Nodes: 3

------------------------------------------------------------
SUMMARY
------------------------------------------------------------

Total Checks: 91
  Passed:       67
  Failed:       18
  Not Reviewed: 6

By Severity:
  CAT I (High) Failures:   2
  CAT II (Medium) Failures: 12
  CAT III (Low) Failures:  4
```

### JSON Output
Results are saved to `./stigkube-output/scan-results-<timestamp>.json` with full finding details.

## Deployment Method Detection

StigKube automatically detects how your cluster was deployed:

- **kubeadm** - Looks for kubeadm-config ConfigMap
- **Kubespray** - Checks for Kubespray annotations
- **RKE2** - Detects RKE2 version string and pods
- **K3s** - Identifies K3s kubelet version
- **OpenShift** - Checks for openshift.io API groups
- **EKS/AKS/GKE** - Detects managed service labels

This detection drives remediation generation - each deployment method has different config file locations and restart procedures.

## Roadmap

- [ ] Node-level checks via privileged scanner pod
- [ ] XCCDF report output for STIG Viewer
- [ ] Ansible role generation per deployment method
- [ ] CI/CD integration (exit code based on CAT I failures)
- [ ] Delta scanning (compare against baseline)

## License

MIT

## References

- [DISA Kubernetes STIG](https://public.cyber.mil/stigs/downloads/)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
