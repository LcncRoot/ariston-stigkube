package apiserver

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// Check performs API server STIG compliance checks
func Check(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	var findings []models.Finding

	// V-242376: Anonymous authentication must be disabled
	findings = append(findings, checkAnonymousAuth(ctx, client))

	// V-242378: RBAC must be enabled
	findings = append(findings, checkRBACEnabled(ctx, client))

	// V-242380: Audit logging must be enabled
	findings = append(findings, checkAuditLogging(ctx, client))

	// V-242381: Audit policy must be configured
	findings = append(findings, checkAuditPolicy(ctx, client))

	// V-242384: Secure port must be used
	findings = append(findings, checkSecurePort(ctx, client))

	// V-242385: API server must use TLS 1.2+
	findings = append(findings, checkTLSVersion(ctx, client))

	// V-242402: Service account lookup must be enabled
	findings = append(findings, checkServiceAccountLookup(ctx, client))

	return findings, nil
}

func checkAnonymousAuth(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242376")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242376 not found in STIG data",
		}
	}

	finding := models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "Anonymous authentication check requires access to API server configuration files on the master node",
	}

	// This check requires node access to read kube-apiserver manifest or process args
	// For now, mark as not_reviewed - will be implemented with node scanner
	return finding
}

func checkRBACEnabled(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242378")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242378 not found in STIG data",
		}
	}

	// Check if RBAC API is available by trying to list roles
	_, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return models.Finding{
			Control: *control,
			Status:  models.StatusFail,
			Details: "RBAC API not available or not enabled",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusPass,
		Details: "RBAC authorization mode is enabled (RBAC API available)",
	}
}

func checkAuditLogging(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242380")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242380 not found in STIG data",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "Audit logging check requires access to API server configuration files on the master node",
	}
}

func checkAuditPolicy(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242381")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242381 not found in STIG data",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "Audit policy check requires access to audit policy file on the master node",
	}
}

func checkSecurePort(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242384")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242384 not found in STIG data",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "Secure port check requires access to API server configuration on the master node",
	}
}

func checkTLSVersion(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242385")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242385 not found in STIG data",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "TLS version check requires access to API server configuration on the master node",
	}
}

func checkServiceAccountLookup(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242402")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242402 not found in STIG data",
		}
	}

	return models.Finding{
		Control: *control,
		Status:  models.StatusNotReviewed,
		Details: "Service account lookup check requires access to API server configuration on the master node",
	}
}
