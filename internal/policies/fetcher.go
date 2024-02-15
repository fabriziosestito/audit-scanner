package policies

import (
	"context"
	"fmt"
	"net/url"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	errorsApi "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const policyServerResource = "policyservers"

// Fetcher fetches Kubewarden policies from the Kubernetes cluster, and filters policies that are auditable.
type Fetcher struct {
	// client knows about policies.kubewarden.io GVK
	client client.Client

	clientset kubernetes.Interface
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to fetch the policy server resources
	kubewardenNamespace string
	// list of skipped namespaces from audit, by name. It includes kubewardenNamespace
	skippedNs []string
	// filter cribes the passed policies and returns only those that should be audited
	filter func(policies []policiesv1.Policy) []policiesv1.Policy
	// FQDN of the policy server to query. If not empty, Fetcher will query on
	// port 3000. Useful for out-of-cluster debugging
	policyServerURL string
}

// NewFetcher returns a Fetcher. It will try to use in-cluster config, which will work just if audit-scanner is deployed
// inside a Pod. If in-cluster fails, it will try to fetch the kube config from the home dir. It will return an error
// if both attempts fail.
func NewFetcher(kubewardenNamespace string, skippedNs []string, policyServerURL string) (*Fetcher, error) {
	client, err := newClient()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		return nil, err
	}

	skippedNs = append(skippedNs, kubewardenNamespace)

	if policyServerURL != "" {
		log.Info().Msg(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}

	return &Fetcher{
		client:              client,
		clientset:           clientset,
		kubewardenNamespace: kubewardenNamespace,
		skippedNs:           skippedNs,
		filter:              filterAuditablePolicies,
		policyServerURL:     policyServerURL,
	}, nil
}

// GetPoliciesForANamespace gets all auditable policies for a given namespace, and the number
// of skipped policies
func (f *Fetcher) GetPoliciesForANamespace(namespace string) (FetchedPolicies, int, error) {
	namespacePolicies, err := f.findNamespacesForAllClusterAdmissionPolicies()
	if err != nil {
		return nil, 0, fmt.Errorf("can't fetch ClusterAdmissionPolicies: %w", err)
	}
	admissionPolicies, err := f.getAdmissionPolicies(namespace)
	if err != nil {
		return nil, 0, fmt.Errorf("can't fetch AdmissionPolicies: %w", err)
	}
	for _, policy := range admissionPolicies {
		policy := policy
		namespacePolicies[namespace] = append(namespacePolicies[namespace], &policy)
	}

	filteredPolicies := f.filter(namespacePolicies[namespace])
	skippedNum := len(namespacePolicies[namespace]) - len(filteredPolicies)

	fetchedPolicies := f.groupPoliciesByGVRAndObjectSelector(filteredPolicies, true)

	return fetchedPolicies, skippedNum, nil
}

func (f *Fetcher) getClusterAdmissionPolicies() ([]policiesv1.ClusterAdmissionPolicy, error) {
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err := f.client.List(context.Background(), policies)
	if err != nil {
		return []policiesv1.ClusterAdmissionPolicy{}, err
	}
	return policies.Items, nil
}

// GetClusterAdmissionPolicies gets all auditable ClusterAdmissionPolicy policies,
// and the number of skipped policies
func (f *Fetcher) GetClusterAdmissionPolicies() (FetchedPolicies, int, error) {
	clusterAdmissionPolicies, err := f.getClusterAdmissionPolicies()
	if err != nil {
		return nil, 0, err
	}
	policies := []policiesv1.Policy{}
	for _, policy := range clusterAdmissionPolicies {
		policy := policy
		policies = append(policies, &policy)
	}
	filteredPolicies := f.filter(policies)
	skippedNum := len(policies) - len(filteredPolicies)

	fetchedPolicies := f.groupPoliciesByGVRAndObjectSelector(filteredPolicies, false)
	return fetchedPolicies, skippedNum, nil
}

func (f *Fetcher) GetNamespace(nsName string) (*v1.Namespace, error) {
	namespace := &v1.Namespace{}
	err := f.client.Get(context.Background(),
		client.ObjectKey{
			Name: nsName,
		},
		namespace)
	if err != nil && errorsApi.IsNotFound(err) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("can't get namespace %s: %w", nsName, err)
	}
	return namespace, nil
}

// GetAuditedNamespaces gets all namespaces besides the ones in fetcher.skippedNs
// This function cannot be tested with fake.client, as fake.client doesn't
// support fields.OneTermNotEqualSelector()
func (f *Fetcher) GetAuditedNamespaces() (*v1.NamespaceList, error) {
	skipNsFields := fields.Everything()
	for _, nsName := range f.skippedNs {
		skipNsFields = fields.AndSelectors(skipNsFields, fields.OneTermNotEqualSelector("metadata.name", nsName))
		log.Debug().Str("ns", nsName).Msg("skipping ns")
	}

	namespaceList := &v1.NamespaceList{}
	err := f.client.List(context.Background(), namespaceList, &client.ListOptions{FieldSelector: skipNsFields})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	return namespaceList, nil
}

// initializes map with an entry for all namespaces with an empty policies array as value
func (f *Fetcher) initNamespacePoliciesMap() (map[string][]policiesv1.Policy, error) {
	namespacePolicies := make(map[string][]policiesv1.Policy)
	namespaceList := &v1.NamespaceList{}
	err := f.client.List(context.Background(), namespaceList, &client.ListOptions{})
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
func (f *Fetcher) findNamespacesForAllClusterAdmissionPolicies() (map[string][]policiesv1.Policy, error) {
	namespacePolicies, err := f.initNamespacePoliciesMap()
	if err != nil {
		return nil, err
	}
	policies := &policiesv1.ClusterAdmissionPolicyList{}
	err = f.client.List(context.Background(), policies, &client.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't list ClusterAdmissionPolicies: %w", err)
	}

	for _, policy := range policies.Items {
		policy := policy
		namespaces, err := f.findNamespacesForClusterAdmissionPolicy(policy)
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
func (f *Fetcher) findNamespacesForClusterAdmissionPolicy(policy policiesv1.ClusterAdmissionPolicy) ([]v1.Namespace, error) {
	namespaceList := &v1.NamespaceList{}
	labelSelector, err := metav1.LabelSelectorAsSelector(policy.GetUpdatedNamespaceSelector(f.kubewardenNamespace))
	if err != nil {
		return nil, err
	}
	opts := client.ListOptions{
		LabelSelector: labelSelector,
	}
	err = f.client.List(context.Background(), namespaceList, &opts)
	if err != nil {
		return nil, err
	}

	return namespaceList.Items, nil
}

func (f *Fetcher) getAdmissionPolicies(namespace string) ([]policiesv1.AdmissionPolicy, error) {
	policies := &policiesv1.AdmissionPolicyList{}
	err := f.client.List(context.Background(), policies, &client.ListOptions{Namespace: namespace})
	if err != nil {
		return nil, err
	}

	return policies.Items, nil
}

func newClient() (client.Client, error) { //nolint:ireturn
	config := ctrl.GetConfigOrDie()
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion},
		&policiesv1.ClusterAdmissionPolicy{},
		&policiesv1.AdmissionPolicy{},
		&policiesv1.ClusterAdmissionPolicyList{},
		&policiesv1.AdmissionPolicyList{},
		&policiesv1.PolicyServer{},
	)
	metav1.AddToGroupVersion(
		customScheme, schema.GroupVersion{Group: constants.KubewardenPoliciesGroup, Version: constants.KubewardenPoliciesVersion},
	)

	return client.New(config, client.Options{Scheme: customScheme})
}

type ObjectFilter struct {
	LabelSelector *metav1.LabelSelector
}

type PolicyWithPolicyServer struct {
	Policy       policiesv1.Policy
	PolicyServer *url.URL
}

type FetchedPolicies map[schema.GroupVersionResource]map[ObjectFilter][]PolicyWithPolicyServer

func (f *Fetcher) groupPoliciesByGVRAndObjectSelector(policies []policiesv1.Policy, namespaced bool) FetchedPolicies {
	resources := make(FetchedPolicies)
	for _, policy := range policies {
		url, err := f.GetPolicyServerURLRunningPolicy(context.Background(), policy)
		if err != nil {
			panic(err)
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
							panic(err)
						}
						if namespaced && !isNamespaced {
							// continue if resource is clusterwide
							continue
						}

						if !namespaced && isNamespaced {
							// continue if resource is namespaced
							continue
						}

						filter := ObjectFilter{
							LabelSelector: policy.GetObjectSelector(),
						}

						p := PolicyWithPolicyServer{
							Policy:       policy,
							PolicyServer: url,
						}

						if _, ok := resources[gvr]; !ok {
							resources[gvr] = map[ObjectFilter][]PolicyWithPolicyServer{
								filter: {p},
							}
							continue
						}

						if _, ok := resources[gvr][filter]; !ok {
							resources[gvr][filter] = []PolicyWithPolicyServer{p}
						} else {
							resources[gvr][filter] = append(resources[gvr][filter], p)
						}
					}
				}
			}
		}
	}

	return resources
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

func (f *Fetcher) GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error) {
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
	labelSelector := fmt.Sprintf("app=%s", appLabel)
	services, err := f.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}

	if len(services.Items) != 1 {
		return nil, fmt.Errorf("could not find a single service for the given policy server app label")
	}

	return &services.Items[0], nil
}
