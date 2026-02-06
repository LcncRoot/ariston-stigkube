package node

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aristonllc/stigkube/pkg/models"
)

const (
	scannerNamespace = "stigkube-scanner"
	scannerImage     = "busybox:1.36"
	scannerTimeout   = 60 * time.Second
)

// Scanner performs node-level STIG checks by deploying privileged pods
type Scanner struct {
	client *kubernetes.Clientset
}

// New creates a new node scanner
func New(client *kubernetes.Clientset) *Scanner {
	return &Scanner{client: client}
}

// ScanAllNodes scans all nodes in the cluster for STIG compliance
func (s *Scanner) ScanAllNodes(ctx context.Context) ([]models.Finding, error) {
	var allFindings []models.Finding

	// Create scanner namespace if it doesn't exist
	if err := s.ensureNamespace(ctx); err != nil {
		return nil, fmt.Errorf("failed to create scanner namespace: %w", err)
	}

	// Get all nodes
	nodes, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes.Items {
		// Only scan control plane nodes for API server/etcd/scheduler/controller-manager
		if isControlPlane(node) {
			findings, err := s.scanControlPlaneNode(ctx, node.Name)
			if err != nil {
				fmt.Printf("    Warning: failed to scan control plane node %s: %v\n", node.Name, err)
				continue
			}
			allFindings = append(allFindings, findings...)
		}

		// Scan all nodes for kubelet config
		findings, err := s.scanKubeletConfig(ctx, node.Name)
		if err != nil {
			fmt.Printf("    Warning: failed to scan kubelet on node %s: %v\n", node.Name, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Cleanup scanner namespace
	s.cleanupNamespace(ctx)

	return allFindings, nil
}

func (s *Scanner) ensureNamespace(ctx context.Context) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: scannerNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "stigkube-scanner",
				"app.kubernetes.io/managed-by": "stigkube",
			},
		},
	}

	_, err := s.client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return err
	}
	return nil
}

func (s *Scanner) cleanupNamespace(ctx context.Context) {
	// Delete namespace and all resources in it
	_ = s.client.CoreV1().Namespaces().Delete(ctx, scannerNamespace, metav1.DeleteOptions{})
}

func (s *Scanner) scanControlPlaneNode(ctx context.Context, nodeName string) ([]models.Finding, error) {
	var findings []models.Finding

	// Read API server manifest
	apiServerConfig, err := s.readFileFromNode(ctx, nodeName, "/etc/kubernetes/manifests/kube-apiserver.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read API server config: %w", err)
	}

	findings = append(findings, checkAPIServerConfig(apiServerConfig, nodeName)...)

	// Read controller-manager manifest
	cmConfig, err := s.readFileFromNode(ctx, nodeName, "/etc/kubernetes/manifests/kube-controller-manager.yaml")
	if err == nil {
		findings = append(findings, checkControllerManagerConfig(cmConfig, nodeName)...)
	}

	// Read scheduler manifest
	schedulerConfig, err := s.readFileFromNode(ctx, nodeName, "/etc/kubernetes/manifests/kube-scheduler.yaml")
	if err == nil {
		findings = append(findings, checkSchedulerConfig(schedulerConfig, nodeName)...)
	}

	// Read etcd manifest
	etcdConfig, err := s.readFileFromNode(ctx, nodeName, "/etc/kubernetes/manifests/etcd.yaml")
	if err == nil {
		findings = append(findings, checkEtcdConfig(etcdConfig, nodeName)...)
	}

	return findings, nil
}

func (s *Scanner) scanKubeletConfig(ctx context.Context, nodeName string) ([]models.Finding, error) {
	var findings []models.Finding

	// Try to read kubelet config from common locations
	kubeletConfig, err := s.readFileFromNode(ctx, nodeName, "/var/lib/kubelet/config.yaml")
	if err != nil {
		// Try alternative location
		kubeletConfig, err = s.readFileFromNode(ctx, nodeName, "/etc/kubernetes/kubelet.conf")
		if err != nil {
			return nil, fmt.Errorf("failed to read kubelet config: %w", err)
		}
	}

	findings = append(findings, checkKubeletConfig(kubeletConfig, nodeName)...)
	return findings, nil
}

func (s *Scanner) readFileFromNode(ctx context.Context, nodeName, filePath string) (string, error) {
	podName := fmt.Sprintf("stigkube-reader-%s", strings.ReplaceAll(nodeName, ".", "-"))

	// Create a privileged pod to read the file
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: scannerNamespace,
		},
		Spec: corev1.PodSpec{
			NodeName:      nodeName,
			RestartPolicy: corev1.RestartPolicyNever,
			HostPID:       true,
			HostNetwork:   true,
			Containers: []corev1.Container{
				{
					Name:    "reader",
					Image:   scannerImage,
					Command: []string{"cat", filePath},
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	// Update command to read from host mount
	pod.Spec.Containers[0].Command = []string{"cat", "/host" + filePath}

	// Create the pod
	_, err := s.client.CoreV1().Pods(scannerNamespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create scanner pod: %w", err)
	}

	// Wait for pod to complete
	defer func() {
		_ = s.client.CoreV1().Pods(scannerNamespace).Delete(ctx, podName, metav1.DeleteOptions{})
	}()

	// Poll for completion
	timeout := time.After(scannerTimeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("timeout waiting for scanner pod")
		case <-ticker.C:
			p, err := s.client.CoreV1().Pods(scannerNamespace).Get(ctx, podName, metav1.GetOptions{})
			if err != nil {
				continue
			}

			if p.Status.Phase == corev1.PodSucceeded {
				// Get logs (file content)
				logs, err := s.getPodLogs(ctx, podName)
				if err != nil {
					return "", fmt.Errorf("failed to get pod logs: %w", err)
				}
				return logs, nil
			}

			if p.Status.Phase == corev1.PodFailed {
				return "", fmt.Errorf("scanner pod failed")
			}
		}
	}
}

func (s *Scanner) getPodLogs(ctx context.Context, podName string) (string, error) {
	req := s.client.CoreV1().Pods(scannerNamespace).GetLogs(podName, &corev1.PodLogOptions{})
	logs, err := req.Do(ctx).Raw()
	if err != nil {
		return "", err
	}
	return string(logs), nil
}

func isControlPlane(node corev1.Node) bool {
	// Check for control-plane label (modern) or master label (legacy)
	if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
		return true
	}
	if _, ok := node.Labels["node-role.kubernetes.io/master"]; ok {
		return true
	}
	return false
}

func boolPtr(b bool) *bool {
	return &b
}
