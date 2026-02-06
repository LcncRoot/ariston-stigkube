package apiserver

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// Check performs API server STIG compliance checks that can be done via the K8s API
// Note: Most API server config checks require node access and are in pkg/scanner/node/
func Check(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	var findings []models.Finding

	// V-242382: RBAC must be enabled - can check via API
	findings = append(findings, checkRBACEnabled(ctx, client))

	return findings, nil
}

func checkRBACEnabled(ctx context.Context, client *kubernetes.Clientset) models.Finding {
	control := stig.GetControl("V-242382")
	if control == nil {
		return models.Finding{
			Status:  models.StatusError,
			Details: "Control V-242382 not found in STIG data",
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
