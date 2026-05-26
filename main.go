package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type OperationalPayload struct {
	Metrics   MetricsMetrics  `json:"metrics"`
	Clusters  []ClusterModel  `json:"clusters"`
	Nodes     []NodeModel     `json:"nodes"`
	Pods      []PodModel      `json:"pods"`
	ScanState ScanMetadata    `json:"scanState"`
}

type MetricsMetrics struct {
	TotalClusters  int `json:"totalClusters"`
	ActiveContexts int `json:"activeContexts"`
	Unreachable    int `json:"unreachable"`
	TotalNodes     int `json:"totalNodes"`
	ExposedNodes   int `json:"exposedNodes"`
	CriticalRisk   int `json:"criticalRisk"`
	HighRisk       int `json:"highRisk"`
	AggregateRisk  int `json:"aggregateRisk"`
}

type ClusterModel struct {
	Name         string `json:"name"`
	Context      string `json:"context"`
	Region       string `json:"region"`
	NodeCount    int    `json:"nodeCount"`
	ExposedCount int    `json:"exposedCount"`
	Status       string `json:"status"`
	ErrorDetail  string `json:"errorDetail,omitempty"`
}

type NodeModel struct {
	Name        string   `json:"name"`
	Cluster     string   `json:"cluster"`
	Context     string   `json:"context"`
	Kernel      string   `json:"kernel"`
	PatchStatus string   `json:"patchStatus"`
	AlgifState  string   `json:"algifState"`
	Capacity    string   `json:"capacity"`
	Provider    string   `json:"provider"`
	NodePool    string   `json:"nodePool"`
	Zone        string   `json:"zone"`
	RiskScore   int      `json:"riskScore"`
	RiskLevel   string   `json:"riskLevel"`
	Failures    []string `json:"failures"`
}

type PodModel struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	Cluster      string   `json:"cluster"`
	NodeName     string   `json:"nodeName"`
	Status       string   `json:"status"`
	IsPrivileged bool     `json:"isPrivileged"`
	HostNetwork  bool     `json:"hostNetwork"`
	RiskScore    int      `json:"riskScore"`
	RiskLevel    string   `json:"riskLevel"`
	Violations   []string `json:"violations"`
	Image        string   `json:"image"`
}

type ScanMetadata struct {
	LastScannedAt  string `json:"lastScannedAt"`
	ScanInProgress bool   `json:"scanInProgress"`
}

var (
	stateLock  sync.RWMutex
	stateCache OperationalPayload
)

func main() {
	go backgroundOrchestrationEngine()

	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		stateLock.RLock()
		defer stateLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stateCache)
	})

	http.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		go runFleetDiscoveryScan()
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"SCAN_INITIALIZED"}`))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "dashboard.html")
	})

	log.Println("🛡️  PDKS Security Control Plane Engine bound to: http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func backgroundOrchestrationEngine() {
	runFleetDiscoveryScan()
	ticker := time.NewTicker(45 * time.Second)
	for range ticker.C {
		runFleetDiscoveryScan()
	}
}

func runFleetDiscoveryScan() {
	stateLock.Lock()
	stateCache.ScanState.ScanInProgress = true
	stateLock.Unlock()

	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")
	poConfig, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		log.Printf("[ERROR] Kubeconfig processing error context: %v", err)
		return
	}

	var (
		nodesAccumulator    []NodeModel
		podsAccumulator     []PodModel
		clustersAccumulator []ClusterModel
		wg                  sync.WaitGroup
		mutationLock        sync.Mutex
		unreachableContexts int
	)

	workerPoolThrottle := make(chan struct{}, 20)

	for contextName := range poConfig.Contexts {
		wg.Add(1)
		workerPoolThrottle <- struct{}{}

		go func(targetCtx string) {
			defer wg.Done()
			defer func() { <-workerPoolThrottle }()

			ctxTokens := strings.Split(targetCtx, "/")
			clusterShortName := ctxTokens[len(ctxTokens)-1]

			clusterReport := ClusterModel{
				Context: targetCtx,
				Name:    clusterShortName,
				Status:  "HEALTHY",
				Region:  "us-east-1",
			}

			if strings.Contains(targetCtx, "us-west-2") {
				clusterReport.Region = "us-west-2"
			} else if strings.Contains(targetCtx, "eu-west-1") {
				clusterReport.Region = "eu-west-1"
			}

			clientConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
				&clientcmd.ConfigOverrides{CurrentContext: targetCtx},
			).ClientConfig()

			var clientset *kubernetes.Clientset
			if err == nil {
				clientConfig.Timeout = 6 * time.Second
				clientset, err = kubernetes.NewForConfig(clientConfig)
			}

			if err != nil {
				clusterReport.Status = "UNREACHABLE"
				clusterReport.ErrorDetail = err.Error()
				mutationLock.Lock()
				unreachableContexts++
				clustersAccumulator = append(clustersAccumulator, clusterReport)
				mutationLock.Unlock()
				return
			}

			rawNodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				clusterReport.Status = "UNREACHABLE"
				clusterReport.ErrorDetail = err.Error()
				mutationLock.Lock()
				unreachableContexts++
				clustersAccumulator = append(clustersAccumulator, clusterReport)
				mutationLock.Unlock()
				return
			}

			clusterReport.NodeCount = len(rawNodes.Items)
			var nodeMetricsExposed int
			var localNodes []NodeModel
			clusterHasExploitVulnerability := false

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
					nodeMetricsExposed++
					clusterHasExploitVulnerability = true
				}

				if algifState == "LOADED" {
					nodeWeightScore += 15
					nodeFaults = append(nodeFaults, "algif_aead module active")
				}

				capacityType := "ON_DEMAND"
				if node.Labels["eks.amazonaws.com/capacityType"] == "SPOT" || node.Labels["karpenter.sh/capacity-type"] == "spot" {
					capacityType = "SPOT"
					nodeWeightScore += 5
				}

				providerType := "MANAGED"
				nodepoolName, hasKarpenter := node.Labels["karpenter.sh/nodepool"]
				if hasKarpenter {
					providerType = "KARPENTER"
				}

				nodeRiskLevel := "LOW"
				if nodeWeightScore >= 65 {
					nodeRiskLevel = "CRITICAL"
				} else if nodeWeightScore >= 40 {
					nodeRiskLevel = "HIGH"
				}

				localNodes = append(localNodes, NodeModel{
					Name:        node.Name,
					Cluster:     clusterShortName,
					Context:     targetCtx,
					Kernel:      kVer,
					PatchStatus: patchState,
					AlgifState:  algifState,
					Capacity:    capacityType,
					Provider:    providerType,
					NodePool:    nodepoolName,
					Zone:        node.Labels["topology.kubernetes.io/zone"],
					RiskScore:   nodeWeightScore,
					RiskLevel:   nodeRiskLevel,
					Failures:    nodeFaults,
				})
			}

			clusterReport.ExposedCount = nodeMetricsExposed

			rawPods, err := clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
			var localPods []PodModel
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
						complianceFaults = append(complianceFaults, "hostNetwork configuration space escape")
					}
					if clusterHasExploitVulnerability && pod.Namespace != "kube-system" {
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

					localPods = append(localPods, PodModel{
						Name:         pod.Name,
						Namespace:    pod.Namespace,
						Cluster:      clusterShortName,
						NodeName:     pod.Spec.NodeName,
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

			mutationLock.Lock()
			nodesAccumulator = append(nodesAccumulator, localNodes...)
			podsAccumulator = append(podsAccumulator, localPods...)
			clustersAccumulator = append(clustersAccumulator, clusterReport)
			mutationLock.Unlock()

		}(contextName)
	}

	wg.Wait()

	var totalNodesCounter, exposedNodesCounter, criticalNodesCounter, highNodesCounter int
	for _, n := range nodesAccumulator {
		totalNodesCounter++
		if n.PatchStatus == "UNPATCHED" {
			exposedNodesCounter++
		}
		if n.RiskLevel == "CRITICAL" {
			criticalNodesCounter++
		} else if n.RiskLevel == "HIGH" {
			highNodesCounter++
		}
	}

	aggregateRiskFactor := 12
	if totalNodesCounter > 0 {
		aggregateRiskFactor = (criticalNodesCounter*95 + highNodesCounter*60) / totalNodesCounter
		if aggregateRiskFactor == 0 && exposedNodesCounter > 0 {
			aggregateRiskFactor = 25
		}
	}

	stateLock.Lock()
	stateCache = OperationalPayload{
		Metrics: MetricsMetrics{
			TotalClusters:  len(poConfig.Contexts),
			ActiveContexts: len(clustersAccumulator) - unreachableContexts,
			Unreachable:    unreachableContexts,
			TotalNodes:     totalNodesCounter,
			ExposedNodes:   exposedNodesCounter,
			CriticalRisk:   criticalNodesCounter,
			HighRisk:       highNodesCounter,
			AggregateRisk:  aggregateRiskFactor,
		},
		Clusters:  clustersAccumulator,
		Nodes:     nodesAccumulator,
		Pods:      podsAccumulator,
		ScanState: ScanMetadata{
			LastScannedAt:  time.Now().Format(time.RFC3339),
			ScanInProgress: false,
		},
	}
	stateLock.Unlock()
}
