package report

import "fmt"

const (
	KUBERNETES string = "kubernetes"
	MEMORY     string = "memory"
)

var SupportedTypes = [2]string{KUBERNETES, MEMORY}

// PolicyReportStore caches the latest version of `PolicyReports` and `ClusterPolicyReports`.
// It also provides functions to read, delete and save these resources,
// only updating them if there is indeed a change in data.
//
//go:generate mockery --name=PolicyReportStore
type PolicyReportStore interface {
	// GetPolicyReport returns the Policy Report defined inside a given namespace.
	// An empty PolicyReport is returned when nothing is found
	GetPolicyReport(namespace string) (PolicyReport, error)

	// GetClusterPolicyReport gets the ClusterPolicyReport
	GetClusterPolicyReport(name string) (ClusterPolicyReport, error)

	// SavePolicyReport instantiates the passed namespaced PolicyReport if it doesn't exist, or
	// updates it if one is found
	SavePolicyReport(report *PolicyReport) error

	// SaveClusterPolicyReport instantiates the ClusterPolicyReport if it doesn't exist, or
	// updates it one is found
	SaveClusterPolicyReport(report *ClusterPolicyReport) error
}

func NewPolicyReportStoreFromType(storeType string) (PolicyReportStore, error) { //nolint:ireturn
	switch storeType {
	case KUBERNETES:
		return NewKubernetesPolicyReportStore()
	case MEMORY:
		return NewMemoryPolicyReportStore(), nil
	default:
		return nil, fmt.Errorf("invalid policyReport store type: %s", storeType)
	}
}
