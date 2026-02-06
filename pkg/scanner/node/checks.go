package node

import (
	"strings"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// checkAPIServerConfig checks API server configuration against STIG requirements
func checkAPIServerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242376: Anonymous authentication must be disabled
	findings = append(findings, checkFlag(config, "V-242376", nodeName,
		"--anonymous-auth", "false", true,
		"Anonymous authentication should be disabled"))

	// V-242377: Insecure port must be disabled
	findings = append(findings, checkFlag(config, "V-242377", nodeName,
		"--insecure-port", "0", true,
		"Insecure port must be set to 0"))

	// V-242378: Kubelet HTTPS must be enabled
	findings = append(findings, checkFlag(config, "V-242378", nodeName,
		"--kubelet-https", "true", false,
		"Kubelet HTTPS should be enabled (default is true)"))

	// V-242379: Profiling must be disabled
	findings = append(findings, checkFlag(config, "V-242379", nodeName,
		"--profiling", "false", true,
		"Profiling should be disabled"))

	// V-242380: Audit logging must be enabled
	findings = append(findings, checkFlagExists(config, "V-242380", nodeName,
		"--audit-log-path",
		"Audit log path must be configured"))

	// V-242381: Audit policy must be set
	findings = append(findings, checkFlagExists(config, "V-242381", nodeName,
		"--audit-policy-file",
		"Audit policy file must be configured"))

	// V-242382: Audit log maxage must be set
	findings = append(findings, checkFlagExists(config, "V-242382", nodeName,
		"--audit-log-maxage",
		"Audit log max age must be configured"))

	// V-242384: Secure port must be enabled
	findings = append(findings, checkFlagNotValue(config, "V-242384", nodeName,
		"--secure-port", "0",
		"Secure port must not be disabled"))

	// V-242385: TLS min version must be 1.2+
	findings = append(findings, checkTLSVersion(config, "V-242385", nodeName,
		"--tls-min-version",
		"TLS minimum version must be VersionTLS12 or higher"))

	// V-242386: Strong crypto ciphers must be used
	findings = append(findings, checkFlagExists(config, "V-242386", nodeName,
		"--tls-cipher-suites",
		"TLS cipher suites should be explicitly configured"))

	// V-242388: Encryption provider must be configured
	findings = append(findings, checkFlagExists(config, "V-242388", nodeName,
		"--encryption-provider-config",
		"Encryption provider config must be set for secrets at rest"))

	// V-242400: AlwaysAdmit must not be enabled
	findings = append(findings, checkFlagNotContains(config, "V-242400", nodeName,
		"--enable-admission-plugins", "AlwaysAdmit",
		"AlwaysAdmit admission plugin must not be enabled"))

	// V-242401: AlwaysPullImages should be enabled
	findings = append(findings, checkFlagContains(config, "V-242401", nodeName,
		"--enable-admission-plugins", "AlwaysPullImages",
		"AlwaysPullImages admission plugin should be enabled"))

	// V-242402: ServiceAccount lookup must be enabled
	findings = append(findings, checkFlag(config, "V-242402", nodeName,
		"--service-account-lookup", "true", false,
		"Service account lookup should be enabled (default is true)"))

	// V-242403: Authorization mode must include RBAC
	findings = append(findings, checkFlagContains(config, "V-242403", nodeName,
		"--authorization-mode", "RBAC",
		"Authorization mode must include RBAC"))

	// V-242404: Authorization mode must not include AlwaysAllow
	findings = append(findings, checkFlagNotContains(config, "V-242404", nodeName,
		"--authorization-mode", "AlwaysAllow",
		"Authorization mode must not include AlwaysAllow"))

	return findings
}

// checkControllerManagerConfig checks controller-manager configuration
func checkControllerManagerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242390: Profiling must be disabled
	findings = append(findings, checkFlag(config, "V-242390", nodeName,
		"--profiling", "false", true,
		"Profiling should be disabled"))

	// V-242391: Use service account credentials must be enabled
	findings = append(findings, checkFlag(config, "V-242391", nodeName,
		"--use-service-account-credentials", "true", true,
		"Use service account credentials should be enabled"))

	// V-242392: Service account private key must be set
	findings = append(findings, checkFlagExists(config, "V-242392", nodeName,
		"--service-account-private-key-file",
		"Service account private key file must be configured"))

	// V-242393: Root CA file must be set
	findings = append(findings, checkFlagExists(config, "V-242393", nodeName,
		"--root-ca-file",
		"Root CA file must be configured"))

	// V-242394: TLS min version
	findings = append(findings, checkTLSVersion(config, "V-242394", nodeName,
		"--tls-min-version",
		"TLS minimum version must be VersionTLS12 or higher"))

	// V-242396: Bind address should be 127.0.0.1
	findings = append(findings, checkFlag(config, "V-242396", nodeName,
		"--bind-address", "127.0.0.1", true,
		"Bind address should be 127.0.0.1"))

	return findings
}

// checkSchedulerConfig checks scheduler configuration
func checkSchedulerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242398: Profiling must be disabled
	findings = append(findings, checkFlag(config, "V-242398", nodeName,
		"--profiling", "false", true,
		"Profiling should be disabled"))

	// V-242399: Bind address should be 127.0.0.1
	findings = append(findings, checkFlag(config, "V-242399", nodeName,
		"--bind-address", "127.0.0.1", true,
		"Bind address should be 127.0.0.1"))

	return findings
}

// checkEtcdConfig checks etcd configuration
func checkEtcdConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242405: etcd must use TLS for client connections
	findings = append(findings, checkFlagExists(config, "V-242405", nodeName,
		"--cert-file",
		"etcd must have cert-file configured for TLS"))

	// V-242406: etcd must use TLS for client connections (key)
	findings = append(findings, checkFlagExists(config, "V-242406", nodeName,
		"--key-file",
		"etcd must have key-file configured for TLS"))

	// V-242407: etcd must authenticate clients
	findings = append(findings, checkFlag(config, "V-242407", nodeName,
		"--client-cert-auth", "true", true,
		"etcd must require client certificate authentication"))

	// V-242408: etcd peer communication must use TLS
	findings = append(findings, checkFlagExists(config, "V-242408", nodeName,
		"--peer-cert-file",
		"etcd must have peer-cert-file configured"))

	// V-242409: etcd peer communication must use TLS (key)
	findings = append(findings, checkFlagExists(config, "V-242409", nodeName,
		"--peer-key-file",
		"etcd must have peer-key-file configured"))

	// V-242410: etcd peer communication must authenticate
	findings = append(findings, checkFlag(config, "V-242410", nodeName,
		"--peer-client-cert-auth", "true", true,
		"etcd must require peer client certificate authentication"))

	return findings
}

// checkKubeletConfig checks kubelet configuration
func checkKubeletConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242415: Anonymous auth must be disabled
	findings = append(findings, checkYAMLValue(config, "V-242415", nodeName,
		"authentication.anonymous.enabled", "false", true,
		"Kubelet anonymous authentication must be disabled"))

	// V-242416: Authorization mode must not be AlwaysAllow
	findings = append(findings, checkYAMLValueNot(config, "V-242416", nodeName,
		"authorization.mode", "AlwaysAllow",
		"Kubelet authorization mode must not be AlwaysAllow"))

	// V-242417: Client CA file must be set
	findings = append(findings, checkYAMLExists(config, "V-242417", nodeName,
		"authentication.x509.clientCAFile",
		"Kubelet must have client CA file configured"))

	// V-242418: Read-only port must be disabled
	findings = append(findings, checkYAMLValue(config, "V-242418", nodeName,
		"readOnlyPort", "0", true,
		"Kubelet read-only port must be disabled"))

	// V-242419: Streaming connection timeouts must be set
	findings = append(findings, checkYAMLExists(config, "V-242419", nodeName,
		"streamingConnectionIdleTimeout",
		"Kubelet streaming connection timeout should be configured"))

	// V-242420: Protect kernel defaults should be enabled
	findings = append(findings, checkYAMLValue(config, "V-242420", nodeName,
		"protectKernelDefaults", "true", true,
		"Kubelet should protect kernel defaults"))

	// V-242421: Make IPTABLES util chains should be true
	findings = append(findings, checkYAMLValue(config, "V-242421", nodeName,
		"makeIPTablesUtilChains", "true", false,
		"Kubelet should manage iptables util chains"))

	// V-242424: TLS cert and key must be set
	findings = append(findings, checkYAMLExists(config, "V-242424", nodeName,
		"tlsCertFile",
		"Kubelet TLS cert file must be configured"))

	findings = append(findings, checkYAMLExists(config, "V-242425", nodeName,
		"tlsPrivateKeyFile",
		"Kubelet TLS private key file must be configured"))

	return findings
}

// Helper functions for checking configurations

func checkFlag(config, vulnID, nodeName, flag, expected string, required bool, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + "=" + expected,
	}

	// Look for the flag in config
	value := extractFlagValue(config, flag)

	if value == "" {
		if required {
			finding.Status = models.StatusFail
			finding.Details = description
			finding.ActualValue = "not set"
		} else {
			// Assume default is acceptable
			finding.Status = models.StatusPass
			finding.Details = "Flag not set, using default (acceptable)"
			finding.ActualValue = "default"
		}
	} else if value == expected {
		finding.Status = models.StatusPass
		finding.Details = "Flag correctly configured"
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	}

	return finding
}

func checkFlagExists(config, vulnID, nodeName, flag, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + " must be set",
	}

	value := extractFlagValue(config, flag)
	if value == "" {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = "not set"
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Flag is configured"
		finding.ActualValue = value
	}

	return finding
}

func checkFlagNotValue(config, vulnID, nodeName, flag, forbidden, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + " must not be " + forbidden,
	}

	value := extractFlagValue(config, flag)
	if value == forbidden {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Flag has acceptable value"
		finding.ActualValue = value
	}

	return finding
}

func checkFlagContains(config, vulnID, nodeName, flag, required, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + " must contain " + required,
	}

	value := extractFlagValue(config, flag)
	if value == "" || !strings.Contains(value, required) {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Flag contains required value"
		finding.ActualValue = value
	}

	return finding
}

func checkFlagNotContains(config, vulnID, nodeName, flag, forbidden, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + " must not contain " + forbidden,
	}

	value := extractFlagValue(config, flag)
	if strings.Contains(value, forbidden) {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Flag does not contain forbidden value"
		finding.ActualValue = value
	}

	return finding
}

func checkTLSVersion(config, vulnID, nodeName, flag, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: flag + "=VersionTLS12 or VersionTLS13",
	}

	value := extractFlagValue(config, flag)
	if value == "" {
		// Default varies by version, mark as needing review
		finding.Status = models.StatusNotReviewed
		finding.Details = "TLS version not explicitly set, verify Kubernetes version defaults"
		finding.ActualValue = "not set (using default)"
	} else if value == "VersionTLS12" || value == "VersionTLS13" {
		finding.Status = models.StatusPass
		finding.Details = "TLS version meets minimum requirement"
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	}

	return finding
}

// YAML-based checks for kubelet config

func checkYAMLValue(config, vulnID, nodeName, path, expected string, required bool, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: path + ": " + expected,
	}

	value := extractYAMLValue(config, path)

	if value == "" {
		if required {
			finding.Status = models.StatusFail
			finding.Details = description
			finding.ActualValue = "not set"
		} else {
			finding.Status = models.StatusPass
			finding.Details = "Setting not configured, using default (acceptable)"
			finding.ActualValue = "default"
		}
	} else if value == expected {
		finding.Status = models.StatusPass
		finding.Details = "Setting correctly configured"
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	}

	return finding
}

func checkYAMLValueNot(config, vulnID, nodeName, path, forbidden, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: path + " must not be " + forbidden,
	}

	value := extractYAMLValue(config, path)
	if value == forbidden {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = value
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Setting has acceptable value"
		finding.ActualValue = value
	}

	return finding
}

func checkYAMLExists(config, vulnID, nodeName, path, description string) models.Finding {
	control := stig.GetControl(vulnID)
	if control == nil {
		return models.Finding{
			Status:   models.StatusError,
			Details:  "Control " + vulnID + " not found in STIG data",
			NodeName: nodeName,
		}
	}

	finding := models.Finding{
		Control:       *control,
		NodeName:      nodeName,
		ExpectedValue: path + " must be set",
	}

	value := extractYAMLValue(config, path)
	if value == "" {
		finding.Status = models.StatusFail
		finding.Details = description
		finding.ActualValue = "not set"
	} else {
		finding.Status = models.StatusPass
		finding.Details = "Setting is configured"
		finding.ActualValue = value
	}

	return finding
}

// extractFlagValue extracts the value of a command-line flag from config
func extractFlagValue(config, flag string) string {
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Handle --flag=value format
		if strings.HasPrefix(line, "- "+flag+"=") {
			return strings.TrimPrefix(line, "- "+flag+"=")
		}
		// Handle --flag value format (next line or same line)
		if strings.HasPrefix(line, "- "+flag) && !strings.Contains(line, "=") {
			// Value might be on same line after space
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return ""
}

// extractYAMLValue extracts a value from YAML config using dot notation path
func extractYAMLValue(config, path string) string {
	// Simple YAML parser for common patterns
	parts := strings.Split(path, ".")
	lines := strings.Split(config, "\n")

	currentIndent := 0
	pathIndex := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)

		// Check if we're at the right indentation level
		if pathIndex < len(parts) {
			key := parts[pathIndex]
			if strings.HasPrefix(trimmed, key+":") {
				if pathIndex == len(parts)-1 {
					// This is the final key, extract value
					value := strings.TrimPrefix(trimmed, key+":")
					value = strings.TrimSpace(value)
					return value
				}
				pathIndex++
				currentIndent = indent
			}
		}

		// Reset if we've gone back in indentation
		if indent <= currentIndent && pathIndex > 0 && !strings.HasPrefix(trimmed, parts[pathIndex-1]+":") {
			// We've moved out of the current path
			if pathIndex > 1 {
				pathIndex--
			}
		}
	}

	return ""
}
