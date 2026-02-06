package general

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// Check performs general/cluster-level STIG compliance checks
func Check(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	var findings []models.Finding

	// V-242383: Namespace isolation must be enforced
	namespaceFindings, err := checkNamespaceIsolation(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("namespace isolation check failed: %w", err)
	}
	findings = append(findings, namespaceFindings...)

	// V-242395: Secrets must not contain sensitive data in environment variables
	secretFindings, err := checkSecretsInEnv(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("secrets in env check failed: %w", err)
	}
	findings = append(findings, secretFindings...)

	// V-242397: Default namespace must not be used for workloads
	defaultNsFindings, err := checkDefaultNamespace(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("default namespace check failed: %w", err)
	}
	findings = append(findings, defaultNsFindings...)

	// V-242414: Pod Security must be enforced
	pssFindings, err := checkPodSecurity(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("pod security check failed: %w", err)
	}
	findings = append(findings, pssFindings...)

	return findings, nil
}

func checkNamespaceIsolation(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	control := stig.GetControl("V-242383")
	if control == nil {
		return []models.Finding{{
			Status:  models.StatusError,
			Details: "Control V-242383 not found in STIG data",
		}}, nil
	}

	// Check for NetworkPolicies in non-system namespaces
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []models.Finding
	namespacesWithoutNetPol := []string{}

	var checkErrors []string
	for _, ns := range namespaces.Items {
		// Skip system namespaces
		if isSystemNamespace(ns.Name) {
			continue
		}

		// Check if namespace has any NetworkPolicies
		netpols, err := client.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			// Record error but continue checking other namespaces
			checkErrors = append(checkErrors, fmt.Sprintf("%s: %v", ns.Name, err))
			continue
		}

		if len(netpols.Items) == 0 {
			namespacesWithoutNetPol = append(namespacesWithoutNetPol, ns.Name)
		}
	}

	// Report any errors that occurred during checking
	if len(checkErrors) > 0 {
		findings = append(findings, models.Finding{
			Control: *control,
			Status:  models.StatusError,
			Details: fmt.Sprintf("Failed to check NetworkPolicies in some namespaces: %v", checkErrors),
		})
	}

	if len(namespacesWithoutNetPol) > 0 {
		findings = append(findings, models.Finding{
			Control:       *control,
			Status:        models.StatusFail,
			Details:       fmt.Sprintf("Namespaces without NetworkPolicies: %v", namespacesWithoutNetPol),
			ExpectedValue: "All namespaces should have NetworkPolicies defined",
			ActualValue:   fmt.Sprintf("%d namespaces without NetworkPolicies", len(namespacesWithoutNetPol)),
		})
	} else {
		findings = append(findings, models.Finding{
			Control: *control,
			Status:  models.StatusPass,
			Details: "All non-system namespaces have NetworkPolicies defined",
		})
	}

	return findings, nil
}

func checkSecretsInEnv(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	control := stig.GetControl("V-242395")
	if control == nil {
		return []models.Finding{{
			Status:  models.StatusError,
			Details: "Control V-242395 not found in STIG data",
		}}, nil
	}

	// List pods with pagination to avoid OOM on large clusters
	podsWithSecretsInEnv := []string{}
	continueToken := ""

	for {
		pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			Limit:    500,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}

		for _, pod := range pods.Items {
			if isSystemNamespace(pod.Namespace) {
				continue
			}

			for _, container := range pod.Spec.Containers {
				for _, env := range container.Env {
					if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
						podsWithSecretsInEnv = append(podsWithSecretsInEnv,
							fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
				}
			}
		}

		// Check if there are more pages
		if pods.Continue == "" {
			break
		}
		continueToken = pods.Continue
	}

	var findings []models.Finding
	if len(podsWithSecretsInEnv) > 0 {
		findings = append(findings, models.Finding{
			Control:       *control,
			Status:        models.StatusFail,
			Details:       fmt.Sprintf("Pods using secrets in environment variables: %v", podsWithSecretsInEnv),
			ExpectedValue: "Secrets should be mounted as volumes, not environment variables",
			ActualValue:   fmt.Sprintf("%d pods with secrets in env vars", len(podsWithSecretsInEnv)),
		})
	} else {
		findings = append(findings, models.Finding{
			Control: *control,
			Status:  models.StatusPass,
			Details: "No pods found using secrets in environment variables",
		})
	}

	return findings, nil
}

func checkDefaultNamespace(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	control := stig.GetControl("V-242397")
	if control == nil {
		return []models.Finding{{
			Status:  models.StatusError,
			Details: "Control V-242397 not found in STIG data",
		}}, nil
	}

	// Check for pods in default namespace
	pods, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Filter out system pods
	userPods := []string{}
	for _, pod := range pods.Items {
		// Skip kubernetes service account pods
		if pod.Spec.ServiceAccountName != "default" {
			continue
		}
		userPods = append(userPods, pod.Name)
	}

	var findings []models.Finding
	if len(userPods) > 0 {
		findings = append(findings, models.Finding{
			Control:       *control,
			Status:        models.StatusFail,
			Details:       fmt.Sprintf("User workloads in default namespace: %v", userPods),
			ExpectedValue: "No user workloads in default namespace",
			ActualValue:   fmt.Sprintf("%d pods in default namespace", len(userPods)),
		})
	} else {
		findings = append(findings, models.Finding{
			Control: *control,
			Status:  models.StatusPass,
			Details: "No user workloads found in default namespace",
		})
	}

	return findings, nil
}

func checkPodSecurity(ctx context.Context, client *kubernetes.Clientset) ([]models.Finding, error) {
	control := stig.GetControl("V-242414")
	if control == nil {
		return []models.Finding{{
			Status:  models.StatusError,
			Details: "Control V-242414 not found in STIG data",
		}}, nil
	}

	// Check namespaces for Pod Security labels
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespacesWithoutPSS := []string{}

	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) {
			continue
		}

		// Check for Pod Security Standards labels
		labels := ns.Labels
		hasPSS := false
		for key := range labels {
			if key == "pod-security.kubernetes.io/enforce" ||
				key == "pod-security.kubernetes.io/audit" ||
				key == "pod-security.kubernetes.io/warn" {
				hasPSS = true
				break
			}
		}

		if !hasPSS {
			namespacesWithoutPSS = append(namespacesWithoutPSS, ns.Name)
		}
	}

	var findings []models.Finding
	if len(namespacesWithoutPSS) > 0 {
		findings = append(findings, models.Finding{
			Control:       *control,
			Status:        models.StatusFail,
			Details:       fmt.Sprintf("Namespaces without Pod Security Standards: %v", namespacesWithoutPSS),
			ExpectedValue: "All namespaces should have Pod Security Standards labels",
			ActualValue:   fmt.Sprintf("%d namespaces without PSS labels", len(namespacesWithoutPSS)),
		})
	} else {
		findings = append(findings, models.Finding{
			Control: *control,
			Status:  models.StatusPass,
			Details: "All non-system namespaces have Pod Security Standards labels",
		})
	}

	return findings, nil
}

func isSystemNamespace(name string) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
		"default":         true,
	}
	return systemNamespaces[name]
}
