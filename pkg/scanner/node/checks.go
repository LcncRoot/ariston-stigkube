package node

import (
	"strings"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// checkAPIServerConfig checks API server configuration against STIG requirements
func checkAPIServerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242390: API server anonymous authentication must be disabled
	findings = append(findings, checkFlag(config, "V-242390", nodeName,
		"--anonymous-auth", "false", true,
		"API server anonymous authentication must be disabled"))

	// V-242386: Insecure port must be disabled
	findings = append(findings, checkFlag(config, "V-242386", nodeName,
		"--insecure-port", "0", true,
		"API server insecure port must be set to 0"))

	// V-242378: API Server TLS min version must be 1.2+
	findings = append(findings, checkTLSVersion(config, "V-242378", nodeName,
		"--tls-min-version",
		"API server TLS minimum version must be VersionTLS12 or higher"))

	// V-242389: Secure port must be enabled
	findings = append(findings, checkFlagNotValue(config, "V-242389", nodeName,
		"--secure-port", "0",
		"API server secure port must not be disabled"))

	// V-242402: Audit log path must be set
	findings = append(findings, checkFlagExists(config, "V-242402", nodeName,
		"--audit-log-path",
		"API server audit log path must be configured"))

	// V-242403: Audit policy must be set
	findings = append(findings, checkFlagExists(config, "V-242403", nodeName,
		"--audit-policy-file",
		"API server audit policy file must be configured"))

	// V-242382: Authorization mode must include Node,RBAC
	findings = append(findings, checkFlagContains(config, "V-242382", nodeName,
		"--authorization-mode", "RBAC",
		"API server authorization mode must include RBAC"))

	// V-242418: Strong crypto ciphers must be used
	findings = append(findings, checkFlagExists(config, "V-242418", nodeName,
		"--tls-cipher-suites",
		"API server TLS cipher suites should be explicitly configured"))

	// V-242400: Alpha APIs must be disabled (check enable-admission-plugins doesn't have AlwaysAdmit)
	findings = append(findings, checkFlagNotContains(config, "V-242400", nodeName,
		"--enable-admission-plugins", "AlwaysAdmit",
		"AlwaysAdmit admission plugin must not be enabled"))

	// V-242419: SSL CA must be set
	findings = append(findings, checkFlagExists(config, "V-242419", nodeName,
		"--client-ca-file",
		"API server client CA file must be configured"))

	return findings
}

// checkControllerManagerConfig checks controller-manager configuration
func checkControllerManagerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242409: Profiling must be disabled
	findings = append(findings, checkFlag(config, "V-242409", nodeName,
		"--profiling", "false", true,
		"Controller Manager profiling must be disabled"))

	// V-242381: Use service account credentials must be enabled
	findings = append(findings, checkFlag(config, "V-242381", nodeName,
		"--use-service-account-credentials", "true", true,
		"Controller Manager must use service account credentials"))

	// V-242421: Root CA file must be set
	findings = append(findings, checkFlagExists(config, "V-242421", nodeName,
		"--root-ca-file",
		"Controller Manager root CA file must be configured"))

	// V-242385: Bind address should be 127.0.0.1 (secure binding)
	findings = append(findings, checkFlag(config, "V-242385", nodeName,
		"--bind-address", "127.0.0.1", true,
		"Controller Manager bind address should be 127.0.0.1"))

	// V-242376: TLS min version
	findings = append(findings, checkTLSVersion(config, "V-242376", nodeName,
		"--tls-min-version",
		"Controller Manager TLS minimum version must be VersionTLS12 or higher"))

	return findings
}

// checkSchedulerConfig checks scheduler configuration
func checkSchedulerConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242411: Profiling must be disabled (part of PPS enforcement)
	findings = append(findings, checkFlag(config, "V-242411", nodeName,
		"--profiling", "false", true,
		"Scheduler profiling must be disabled"))

	// V-242384: Bind address should be 127.0.0.1 (secure binding)
	findings = append(findings, checkFlag(config, "V-242384", nodeName,
		"--bind-address", "127.0.0.1", true,
		"Scheduler bind address should be 127.0.0.1"))

	// V-242377: TLS min version
	findings = append(findings, checkTLSVersion(config, "V-242377", nodeName,
		"--tls-min-version",
		"Scheduler TLS minimum version must be VersionTLS12 or higher"))

	return findings
}

// checkEtcdConfig checks etcd configuration
func checkEtcdConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242428: etcd must have cert-file for TLS
	findings = append(findings, checkFlagExists(config, "V-242428", nodeName,
		"--cert-file",
		"etcd must have cert-file configured for TLS"))

	// V-242427: etcd must have key-file for TLS
	findings = append(findings, checkFlagExists(config, "V-242427", nodeName,
		"--key-file",
		"etcd must have key-file configured for TLS"))

	// V-242423: etcd must require client certificate authentication
	findings = append(findings, checkFlag(config, "V-242423", nodeName,
		"--client-cert-auth", "true", true,
		"etcd must require client certificate authentication"))

	// V-242432: etcd peer communication must use TLS (peer-cert-file)
	findings = append(findings, checkFlagExists(config, "V-242432", nodeName,
		"--peer-cert-file",
		"etcd must have peer-cert-file configured"))

	// V-242433: etcd peer communication must use TLS (peer-key-file)
	findings = append(findings, checkFlagExists(config, "V-242433", nodeName,
		"--peer-key-file",
		"etcd must have peer-key-file configured"))

	// V-242426: etcd peer authentication
	findings = append(findings, checkFlag(config, "V-242426", nodeName,
		"--peer-client-cert-auth", "true", true,
		"etcd must require peer client certificate authentication"))

	return findings
}

// checkKubeletConfig checks kubelet configuration
func checkKubeletConfig(config string, nodeName string) []models.Finding {
	var findings []models.Finding

	// V-242391: Kubelet anonymous auth must be disabled
	findings = append(findings, checkYAMLValue(config, "V-242391", nodeName,
		"authentication.anonymous.enabled", "false", true,
		"Kubelet anonymous authentication must be disabled"))

	// V-242392: Kubelet authorization mode must not be AlwaysAllow
	findings = append(findings, checkYAMLValueNot(config, "V-242392", nodeName,
		"authorization.mode", "AlwaysAllow",
		"Kubelet authorization mode must not be AlwaysAllow"))

	// V-242420: Kubelet client CA file must be set
	findings = append(findings, checkYAMLExists(config, "V-242420", nodeName,
		"authentication.x509.clientCAFile",
		"Kubelet must have client CA file configured"))

	// V-242387: Kubelet read-only port must be disabled
	findings = append(findings, checkYAMLValue(config, "V-242387", nodeName,
		"readOnlyPort", "0", true,
		"Kubelet read-only port must be disabled"))

	// V-242434: Kubelet protect kernel defaults should be enabled
	findings = append(findings, checkYAMLValue(config, "V-242434", nodeName,
		"protectKernelDefaults", "true", true,
		"Kubelet should protect kernel defaults"))

	// V-242424: Kubelet TLS private key must be set
	findings = append(findings, checkYAMLExists(config, "V-242424", nodeName,
		"tlsPrivateKeyFile",
		"Kubelet TLS private key file must be configured"))

	// V-242425: Kubelet TLS cert must be set
	findings = append(findings, checkYAMLExists(config, "V-242425", nodeName,
		"tlsCertFile",
		"Kubelet TLS cert file must be configured"))

	// V-245541: Kubelet streaming connection timeout must be set
	findings = append(findings, checkYAMLExists(config, "V-245541", nodeName,
		"streamingConnectionIdleTimeout",
		"Kubelet streaming connection timeout should be configured"))

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
					// Strip inline comments (# ...)
					value = stripYAMLComment(value)
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

// stripYAMLComment removes inline comments from YAML values
// Handles: "value # comment" -> "value"
// Preserves: "value#without-space" (not a comment)
// Preserves: "'value # with hash'" (quoted strings)
func stripYAMLComment(value string) string {
	// Empty value
	if value == "" {
		return value
	}

	// Check if value is quoted (single or double)
	if (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) ||
		(strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) {
		return value
	}

	// Find comment marker (# preceded by space)
	// Note: In YAML, # only starts a comment if preceded by whitespace
	for i := 0; i < len(value); i++ {
		if value[i] == '#' && i > 0 && (value[i-1] == ' ' || value[i-1] == '\t') {
			return strings.TrimSpace(value[:i])
		}
	}

	return value
}
