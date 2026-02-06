package detector

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Deployment method constants
const (
	MethodKubeadm   = "kubeadm"
	MethodKubespray = "kubespray"
	MethodRKE2      = "rke2"
	MethodK3s       = "k3s"
	MethodOpenShift = "openshift"
	MethodEKS       = "eks"
	MethodAKS       = "aks"
	MethodGKE       = "gke"
	MethodUnknown   = "unknown"
)

// Detect determines the deployment method of the Kubernetes cluster
func Detect(client *kubernetes.Clientset) (string, error) {
	ctx := context.Background()

	// Check for OpenShift
	if isOpenShift(ctx, client) {
		return MethodOpenShift, nil
	}

	// Check for managed Kubernetes services
	if method := detectManagedService(ctx, client); method != MethodUnknown {
		return method, nil
	}

	// Check for K3s
	if isK3s(ctx, client) {
		return MethodK3s, nil
	}

	// Check for RKE2
	if isRKE2(ctx, client) {
		return MethodRKE2, nil
	}

	// Check for Kubespray
	if isKubespray(ctx, client) {
		return MethodKubespray, nil
	}

	// Check for kubeadm (default for self-managed clusters)
	if isKubeadm(ctx, client) {
		return MethodKubeadm, nil
	}

	return MethodUnknown, nil
}

func isOpenShift(ctx context.Context, client *kubernetes.Clientset) bool {
	// Check for OpenShift-specific API groups
	groups, err := client.Discovery().ServerGroups()
	if err != nil {
		return false
	}

	for _, group := range groups.Groups {
		if strings.Contains(group.Name, "openshift.io") {
			return true
		}
	}

	return false
}

func detectManagedService(ctx context.Context, client *kubernetes.Clientset) string {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		return MethodUnknown
	}

	node := nodes.Items[0]

	// Check node labels and provider ID for cloud provider indicators
	providerID := node.Spec.ProviderID

	if strings.HasPrefix(providerID, "aws://") {
		// Check for EKS-specific labels
		if _, ok := node.Labels["eks.amazonaws.com/nodegroup"]; ok {
			return MethodEKS
		}
		// Could be self-managed on AWS
		return MethodUnknown
	}

	if strings.HasPrefix(providerID, "azure://") {
		if _, ok := node.Labels["kubernetes.azure.com/agentpool"]; ok {
			return MethodAKS
		}
		return MethodUnknown
	}

	if strings.HasPrefix(providerID, "gce://") {
		if _, ok := node.Labels["cloud.google.com/gke-nodepool"]; ok {
			return MethodGKE
		}
		return MethodUnknown
	}

	return MethodUnknown
}

func isK3s(ctx context.Context, client *kubernetes.Clientset) bool {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		return false
	}

	// K3s nodes have specific labels or container runtime indicators
	node := nodes.Items[0]

	// Check for k3s in kubelet version
	if strings.Contains(node.Status.NodeInfo.KubeletVersion, "k3s") {
		return true
	}

	// Check for k3s label
	if _, ok := node.Labels["node.kubernetes.io/instance-type"]; ok {
		if strings.Contains(node.Labels["node.kubernetes.io/instance-type"], "k3s") {
			return true
		}
	}

	return false
}

func isRKE2(ctx context.Context, client *kubernetes.Clientset) bool {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		return false
	}

	node := nodes.Items[0]

	// RKE2 has specific kubelet version indicator
	if strings.Contains(node.Status.NodeInfo.KubeletVersion, "rke2") {
		return true
	}

	// Check for rke2 specific pods in kube-system
	pods, err := client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "rke2-") {
			return true
		}
	}

	return false
}

func isKubespray(ctx context.Context, client *kubernetes.Clientset) bool {
	// Kubespray typically leaves specific annotations or configmaps
	cms, err := client.CoreV1().ConfigMaps("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return false
	}

	for _, cm := range cms.Items {
		if strings.Contains(cm.Name, "kubespray") {
			return true
		}
		// Check annotations
		for key := range cm.Annotations {
			if strings.Contains(key, "kubespray") {
				return true
			}
		}
	}

	return false
}

func isKubeadm(ctx context.Context, client *kubernetes.Clientset) bool {
	// kubeadm creates specific configmaps
	_, err := client.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", metav1.GetOptions{})
	if err == nil {
		return true
	}

	// Also check for kubelet-config
	_, err = client.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubelet-config", metav1.GetOptions{})
	return err == nil
}
