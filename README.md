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

## Usage

### Scan a cluster

```bash
# Use default kubeconfig (~/.kube/config)
stigkube scan

# Specify kubeconfig
stigkube scan --kubeconfig /path/to/config

# Output as JSON
stigkube scan --json --output ./results/
```

### Generate remediation

```bash
# Scan and generate Ansible remediation
stigkube scan --remediate --output ./stigkube-output/
```

### View version

```bash
stigkube version
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
