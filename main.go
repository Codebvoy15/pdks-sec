package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type ClusterMeta struct {
	Name    string `json:"name"`
	Context string `json:"context"`
}

type StreamResults struct {
	Nodes []NodeModel `json:"nodes"`
	Pods  []PodModel  `json:"pods"`
	Error string      `json:"error,omitempty"`
}

type NodeModel struct {
	Name        string   `json:"name"`
	Kernel      string   `json:"kernel"`
	PatchStatus string   `json:"patchStatus"`
	AlgifState  string   `json:"algifState"`
	Capacity    string   `json:"capacity"`
	Provider    string   `json:"provider"`
	RiskScore   int      `json:"riskScore"`
	RiskLevel   string   `json:"riskLevel"`
	Failures    []string `json:"failures"`
}

type PodModel struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	Status       string   `json:"status"`
	IsPrivileged bool     `json:"isPrivileged"`
	HostNetwork  bool     `json:"hostNetwork"`
	RiskScore    int      `json:"riskScore"`
	RiskLevel    string   `json:"riskLevel"`
	Violations   []string `json:"violations"`
	Image        string   `json:"image"`
}

func main() {
	// Added prefix router structure to avoid generic proxy collisions
	http.HandleFunc("/pdks/api/contexts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err := clientcmd.LoadFromFile(kubeconfigPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var availableClusters []ClusterMeta
		for ctxName := range config.Contexts {
			tokens := strings.Split(ctxName, "/")
			availableClusters = append(availableClusters, ClusterMeta{
				Name:    tokens[len(tokens)-1],
				Context: ctxName,
			})
		}
		json.NewEncoder(w).Encode(availableClusters)
	})

	http.HandleFunc("/pdks/api/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		targetCtx := r.URL.Query().Get("context")
		if targetCtx == "" {
			http.Error(w, "Query parameter 'context' required", http.StatusBadRequest)
			return
		}

		results := queryTargetClusterMetrics(targetCtx)
		json.NewEncoder(w).Encode(results)
	})

	http.HandleFunc("/pdks/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})

	// Root redirect parameter to automatically map into /pdks/
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/pdks/", http.StatusMovedPermanently)
	})

	log.Println("🛡️  PDKS Corporate-Hardened Control Plane running on: http://localhost:8080/pdks/")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func queryTargetClusterMetrics(targetCtx string) StreamResults {
	var out StreamResults
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: targetCtx},
	).ClientConfig()

	if err != nil {
		out.Error = fmt.Sprintf("IAM Client Config Context Failure: %v", err)
		return out
	}

	clientConfig.Timeout = 8 * time.Second
	clientset, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		out.Error = fmt.Sprintf("Cluster Authentication Refused: %v", err)
		return out
	}

	rawNodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		out.Error = fmt.Sprintf("Kubectl node API query timeout: %v", err)
		return out
	}

	clusterIsVulnerable := false
	for _, node := range rawNodes.Items {
		kVer := node.Status.NodeInfo.KernelVersion
		isVulnerable := true
		if strings.Contains(kVer, "6.1.") {
			var revision int
			_, formatError := fmt.Sscanf(kVer, "6.1.%d", &revision)
			if formatError == nil && revision >= 141 {
				isVulnerable = false
			}
		}

		patchState := "UNPATCHED"
		algifState := "LOADED"
		nodeWeightScore := 15
		var nodeFaults []string

		if !isVulnerable {
			patchState = "PATCHED"
			algifState = "BLOCKED"
		} else {
			nodeWeightScore += 50
			nodeFaults = append(nodeFaults, "Kernel Vulnerable (<6.1.141)")
			clusterIsVulnerable = true
		}

		if algifState == "LOADED" {
			nodeWeightScore += 15
			nodeFaults = append(nodeFaults, "algif_aead module active")
		}

		capacityType := "ON_DEMAND"
		if node.Labels["eks.amazonaws.com/capacityType"] == "SPOT" || node.Labels["karpenter.sh/capacity-type"] == "spot" {
			capacityType = "SPOT"
		}

		providerType := "MANAGED"
		if _, hasKarpenter := node.Labels["karpenter.sh/nodepool"]; hasKarpenter {
			providerType = "KARPENTER"
		}

		nodeRiskLevel := "LOW"
		if nodeWeightScore >= 65 {
			nodeRiskLevel = "CRITICAL"
		} else if nodeWeightScore >= 40 {
			nodeRiskLevel = "HIGH"
		}

		out.Nodes = append(out.Nodes, NodeModel{
			Name:        node.Name,
			Kernel:      kVer,
			PatchStatus: patchState,
			AlgifState:  algifState,
			Capacity:    capacityType,
			Provider:    providerType,
			RiskScore:   nodeWeightScore,
			RiskLevel:   nodeRiskLevel,
			Failures:    nodeFaults,
		})
	}

	rawPods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		for _, pod := range rawPods.Items {
			if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
				continue
			}

			privilegedContextActive := false
			networkHostSpaceActive := pod.Spec.HostNetwork
			var complianceFaults []string
			podRiskScore := 10

			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					privilegedContextActive = true
				}
			}

			if privilegedContextActive {
				podRiskScore += 45
				complianceFaults = append(complianceFaults, "Privileged securityContext active")
			}
			if networkHostSpaceActive {
				podRiskScore += 25
				complianceFaults = append(complianceFaults, "hostNetwork space escape path")
			}
			if clusterIsVulnerable && pod.Namespace != "kube-system" {
				podRiskScore += 15
				complianceFaults = append(complianceFaults, "Co-allocated on exposed unpatched host instance")
			}

			podRiskLevel := "LOW"
			if podRiskScore >= 60 {
				podRiskLevel = "CRITICAL"
			} else if podRiskScore >= 35 {
				podRiskLevel = "HIGH"
			}

			primaryImage := "unknown"
			if len(pod.Spec.Containers) > 0 {
				primaryImage = pod.Spec.Containers[0].Image
			}

			out.Pods = append(out.Pods, PodModel{
				Name:         pod.Name,
				Namespace:    pod.Namespace,
				Status:       string(pod.Status.Phase),
				IsPrivileged: privilegedContextActive,
				HostNetwork:  networkHostSpaceActive,
				RiskScore:    podRiskScore,
				RiskLevel:    podRiskLevel,
				Violations:   complianceFaults,
				Image:        primaryImage,
			})
		}
	}

	return out
}
