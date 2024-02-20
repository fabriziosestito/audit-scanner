package policies

import (
	"context"
	"fmt"
	"net/url"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Fetcher fetches Kubewarden policies from the Kubernetes cluster, and filters policies that are auditable.
type Fetcher struct {
	// client knows about policies.kubewarden.io GVK
	client client.Client
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to fetch the policy server resources
	kubewardenNamespace string
	// FQDN of the policy server to query. If not empty, Fetcher will query on
	// port 3000. Useful for out-of-cluster debugging
	policyServerURL string
}

type Policies struct {
	// PoliciesByGVRAndObjectSelector represents a map of policies by GVR and ObjectSelector
	PoliciesByGVRAndObjectSelector map[schema.GroupVersionResource]map[string][]*Policy
	// PolicyNum represents the number of policies
	PolicyNum int
	// SkippedNum represents the number of skipped policies
	SkippedNum int
}

// Policy represents a policy and the URL of the policy server where it is running
type Policy struct {
	policiesv1.Policy
	PolicyServer *url.URL
}

// NewFetcher returns a Fetcher. It will try to use in-cluster config, which will work just if audit-scanner is deployed
// inside a Pod. If in-cluster fails, it will try to fetch the kube config from the home dir. It will return an error
// if both attempts fail.
func NewFetcher(client client.Client, kubewardenNamespace string, policyServerURL string) (*Fetcher, error) {
	if policyServerURL != "" {
		log.Info().Msg(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}

	return &Fetcher{
		client:              client,
		kubewardenNamespace: kubewardenNamespace,
		policyServerURL:     policyServerURL,
	}, nil
}

// GetPoliciesForANamespace gets all auditable policies for a given namespace, and the number
// of skipped policies
func (f *Fetcher) GetPoliciesForANamespace(ctx context.Context, namespace string) (*Policies, error) {
	namespacePolicies, err := f.findNamespacesForAllClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't fetch ClusterAdmissionPolicies: %w", err)
	}
	admissionPolicies, err := f.getAdmissionPolicies(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("can't fetch AdmissionPolicies: %w", err)
	}
	for _, policy := range admissionPolicies {
		policy := policy
		namespacePolicies[namespace] = append(namespacePolicies[namespace], &policy)
	}

	filteredPolicies := filterAuditablePolicies(namespacePolicies[namespace])
	skippedNum := len(namespacePolicies[namespace]) - len(filteredPolicies)

	groupedPolicies, err := f.groupPoliciesByGVRAndObjectSelector(ctx, filteredPolicies, true)
	if err != nil {
		return nil, err
	}

	policies := &Policies{
		PoliciesByGVRAndObjectSelector: groupedPolicies,
		PolicyNum:                      len(filteredPolicies),
		SkippedNum:                     skippedNum,
	}

	return policies, nil
}

func (f *Fetcher) getClusterAdmissionPolicies(ctx context.Context) ([]policiesv1.ClusterAdmissionPolicy, error) {
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err := f.client.List(ctx, policies)
	if err != nil {
		return []policiesv1.ClusterAdmissionPolicy{}, err
	}
	return policies.Items, nil
}

// GetClusterAdmissionPolicies gets all auditable ClusterAdmissionPolicy policies,
// and the number of skipped policies
func (f *Fetcher) GetClusterAdmissionPolicies(ctx context.Context) (*Policies, error) {
	clusterAdmissionPolicies, err := f.getClusterAdmissionPolicies(ctx)
	if err != nil {
		return nil, err
	}
	policies := []policiesv1.Policy{}
	for _, policy := range clusterAdmissionPolicies {
		policy := policy
		policies = append(policies, &policy)
	}
	filteredPolicies := filterAuditablePolicies(policies)
	skippedNum := len(policies) - len(filteredPolicies)

	groupedPolicies, err := f.groupPoliciesByGVRAndObjectSelector(ctx, filteredPolicies, false)
	if err != nil {
		return nil, err
	}

	result := &Policies{
		PoliciesByGVRAndObjectSelector: groupedPolicies,
		PolicyNum:                      len(filteredPolicies),
		SkippedNum:                     skippedNum,
	}

	return result, nil
}

// initializes map with an entry for all namespaces with an empty policies array as value
func (f *Fetcher) initNamespacePoliciesMap(ctx context.Context) (map[string][]policiesv1.Policy, error) {
	namespacePolicies := make(map[string][]policiesv1.Policy)
	namespaceList := &v1.NamespaceList{}
	err := f.client.List(ctx, namespaceList, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	for _, namespace := range namespaceList.Items {
		namespacePolicies[namespace.Name] = []policiesv1.Policy{}
	}

	return namespacePolicies, nil
}

// returns a map with an entry per each namespace. Key is the namespace name, and value is an array of ClusterAdmissionPolicies
// that will evaluate resources within this namespace.
func (f *Fetcher) findNamespacesForAllClusterAdmissionPolicies(ctx context.Context) (map[string][]policiesv1.Policy, error) {
	namespacePolicies, err := f.initNamespacePoliciesMap(ctx)
	if err != nil {
		return nil, err
	}
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err = f.client.List(ctx, policies, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list ClusterAdmissionPolicies: %w", err)
	}

	for _, policy := range policies.Items {
		policy := policy
		namespaces, err := f.findNamespacesForClusterAdmissionPolicy(ctx, policy)
		if err != nil {
			return nil, fmt.Errorf("can't find namespaces for ClusterAdmissionPolicy %s: %w", policy.Name, err)
		}
		for _, namespace := range namespaces {
			namespacePolicies[namespace.Name] = append(namespacePolicies[namespace.Name], &policy)
		}
	}

	return namespacePolicies, nil
}

// finds all namespaces where this ClusterAdmissionPolicy will evaluate resources. It uses the namespaceSelector field to filter the namespaces.
func (f *Fetcher) findNamespacesForClusterAdmissionPolicy(ctx context.Context, policy policiesv1.ClusterAdmissionPolicy) ([]v1.Namespace, error) {
	namespaceList := &v1.NamespaceList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetUpdatedNamespaceSelector(f.kubewardenNamespace))
	if err != nil {
		return nil, err
	}
	opts := client.ListOptions{
		LabelSelector: labelSelector,
	}
	err = f.client.List(ctx, namespaceList, &opts)
	if err != nil {
		return nil, err
	}

	return namespaceList.Items, nil
}

func (f *Fetcher) getAdmissionPolicies(ctx context.Context, namespace string) ([]policiesv1.AdmissionPolicy, error) {
	policies := &policiesv1.AdmissionPolicyList{}
	err := f.client.List(ctx, policies, &client.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	return policies.Items, nil
}

func (f *Fetcher) groupPoliciesByGVRAndObjectSelector(ctx context.Context, policies []policiesv1.Policy, namespaced bool) (map[schema.GroupVersionResource]map[string][]*Policy, error) {
	resources := make(map[schema.GroupVersionResource]map[string][]*Policy)
	for _, policy := range policies {
		url, err := f.getPolicyServerURLRunningPolicy(ctx, policy)
		if err != nil {
			return nil, err
		}

		for _, rules := range policy.GetRules() {
			for _, resource := range rules.Resources {
				for _, version := range rules.APIVersions {
					for _, group := range rules.APIGroups {
						gvr := schema.GroupVersionResource{
							Group:    group,
							Version:  version,
							Resource: resource,
						}
						isNamespaced, err := f.isNamespacedResource(gvr)
						if err != nil {
							return nil, err
						}
						if namespaced && !isNamespaced {
							// continue if resource is clusterwide
							continue
						}
						if !namespaced && isNamespaced {
							// continue if resource is namespaced
							continue
						}

						labelSelector := metav1.FormatLabelSelector(policy.GetObjectSelector())

						policy := Policy{
							Policy:       policy,
							PolicyServer: url,
						}

						if _, ok := resources[gvr]; !ok {
							resources[gvr] = map[string][]*Policy{
								labelSelector: {&policy},
							}
							continue
						}

						if _, ok := resources[gvr][labelSelector]; !ok {
							resources[gvr][labelSelector] = []*Policy{&policy}
						} else {
							resources[gvr][labelSelector] = append(resources[gvr][labelSelector], &policy)
						}
					}
				}
			}
		}
	}

	return resources, nil
}

// Method to check if the given resource is namespaced or not.
func (f *Fetcher) isNamespacedResource(gvr schema.GroupVersionResource) (bool, error) {
	gvk, err := f.client.RESTMapper().KindFor(gvr)
	if err != nil {
		return false, err
	}

	mapping, err := f.client.RESTMapper().RESTMapping(gvk.GroupKind(), gvr.Version)
	if err != nil {
		return false, err
	}

	return mapping.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

func (f *Fetcher) getPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error) {
	policyServer, err := f.getPolicyServerByName(ctx, policy.GetPolicyServer())
	if err != nil {
		return nil, err
	}
	service, err := f.getServiceByAppLabel(ctx, policyServer.AppLabel(), f.kubewardenNamespace)
	if err != nil {
		return nil, err
	}
	if len(service.Spec.Ports) < 1 {
		return nil, fmt.Errorf("policy server service does not have a port")
	}
	var urlStr string
	if f.policyServerURL != "" {
		url, err := url.Parse(f.policyServerURL)
		if err != nil {
			log.Fatal().Msg("incorrect URL for policy-server")
		}
		urlStr = fmt.Sprintf("%s/audit/%s", url, policy.GetUniqueName())
	} else {
		urlStr = fmt.Sprintf("https://%s.%s.svc:%d/audit/%s", service.Name, f.kubewardenNamespace, service.Spec.Ports[0].Port, policy.GetUniqueName())
	}
	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return url, nil
}

func (f *Fetcher) getPolicyServerByName(ctx context.Context, policyServerName string) (*policiesv1.PolicyServer, error) {
	var policyServer policiesv1.PolicyServer

	err := f.client.Get(ctx, client.ObjectKey{Name: policyServerName}, &policyServer)
	if err != nil {
		return nil, err
	}

	return &policyServer, nil
}

func (f *Fetcher) getServiceByAppLabel(ctx context.Context, appLabel string, namespace string) (*v1.Service, error) {
	serviceList := v1.ServiceList{}
	err := f.client.List(ctx, &serviceList, &client.ListOptions{Namespace: namespace}, &client.MatchingLabels{"app": appLabel})
	if err != nil {
		return nil, err
	}

	if len(serviceList.Items) != 1 {
		return nil, fmt.Errorf("could not find a single service for the given policy server app label")
	}

	return &serviceList.Items[0], nil
}
