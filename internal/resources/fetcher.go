package resources

import (
	"context"
	"fmt"
	"net/url"

	"github.com/gookit/goutil/dump"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	pageSize             = 100
	policyServerResource = "policyservers"
)

// Fetcher fetches all auditable resources.
// Uses a dynamic client to get all resources from the rules defined in a policy
type Fetcher struct {
	// dynamicClient is used to fetch resource data
	dynamicClient dynamic.Interface
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to fetch the policy server resources
	kubewardenNamespace string
	// FQDN of the policy server to query. If not empty, Fetcher will query on
	// port 3000. Useful for out-of-cluster debugging
	policyServerURL string
	// clientset is used to call the discovery API and see if a resource is
	// namespaced or not
	clientset kubernetes.Interface
}

// NewFetcher returns a new fetcher with a dynamic client
func NewFetcher(kubewardenNamespace string, policyServerURL string) (*Fetcher, error) {
	config := ctrl.GetConfigOrDie()
	dynamicClient := dynamic.NewForConfigOrDie(config)
	clientset := kubernetes.NewForConfigOrDie(config)
	if policyServerURL != "" {
		log.Info().Msg(fmt.Sprintf("querying PolicyServers at %s for debugging purposes. Don't forget to start `kubectl port-forward` if needed", policyServerURL))
	}
	return &Fetcher{dynamicClient, kubewardenNamespace, policyServerURL, clientset}, nil
}

func (f *Fetcher) GetResources(gvr schema.GroupVersionResource, nsName string, labelSelector *metav1.LabelSelector) (*pager.ListPager, error) {
	page := 0

	listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		var resources *unstructured.UnstructuredList
		page++

		resources, err := f.listResources(ctx, gvr, nsName, labelSelector, opts)
		if apimachineryerrors.IsNotFound(err) {
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", gvr.String()).
					Str("ns", nsName),
				).Msg("API resource not found")
		}
		if apimachineryerrors.IsForbidden(err) {
			// ServiceAccount lacks permissions, GVK may not exist, or policies may be misconfigured
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", gvr.String()).
					Str("ns", nsName),
				).Msg("API resource forbidden, unknown GVK or ServiceAccount lacks permissions")
		}
		if err != nil {
			return nil, err
		}

		dump.P(page, gvr.String(), len(resources.Items))

		return resources, nil
	})

	listPager.PageSize = pageSize

	return listPager, nil
}

func (f *Fetcher) listResources(ctx context.Context,
	gvr schema.GroupVersionResource,
	nsName string,
	labelSelector *metav1.LabelSelector,
	opts metav1.ListOptions,
) (
	*unstructured.UnstructuredList, error,
) {
	resourceID := schema.GroupVersionResource{
		Group:    gvr.Group,
		Version:  gvr.Version,
		Resource: gvr.Resource,
	}

	var list *unstructured.UnstructuredList
	var err error

	if labelSelector != nil {
		labelSelector := metav1.FormatLabelSelector(labelSelector)
		opts = metav1.ListOptions{LabelSelector: labelSelector}
	}

	list, err = f.dynamicClient.Resource(resourceID).Namespace(nsName).List(ctx, opts)

	if err != nil {
		return nil, err
	}

	return list, nil
}

// Method to check if the given resource is namespaced or not.
func (f *Fetcher) IsNamespacedResource(gvr schema.GroupVersionResource) (bool, error) {
	discoveryClient := f.clientset.Discovery()

	apiResourceList, err := discoveryClient.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		return false, err
	}
	for _, apiResource := range apiResourceList.APIResources {
		if apiResource.Name == gvr.Resource {
			return apiResource.Namespaced, nil
		}
	}
	return false, apimachineryerrors.NewNotFound(gvr.GroupResource(), gvr.Resource)
}

func (f *Fetcher) GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error) {
	policyServer, err := getPolicyServerByName(ctx, policy.GetPolicyServer(), &f.dynamicClient)
	if err != nil {
		return nil, err
	}
	service, err := getServiceByAppLabel(ctx, policyServer.AppLabel(), f.kubewardenNamespace, &f.dynamicClient)
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

func getPolicyServerByName(ctx context.Context, policyServerName string, dynamicClient *dynamic.Interface) (*policiesv1.PolicyServer, error) {
	resourceID := schema.GroupVersionResource{
		Group:    policiesv1.GroupVersion.Group,
		Version:  policiesv1.GroupVersion.Version,
		Resource: policyServerResource,
	}
	resourceObj, err := (*dynamicClient).Resource(resourceID).Get(ctx, policyServerName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var policyServer policiesv1.PolicyServer
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(resourceObj.UnstructuredContent(), &policyServer)
	if err != nil {
		return nil, err
	}
	return &policyServer, nil
}

func getServiceByAppLabel(ctx context.Context, appLabel string, namespace string, dynamicClient *dynamic.Interface) (*v1.Service, error) {
	resourceID := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "services",
	}
	labelSelector := fmt.Sprintf("app=%s", appLabel)
	list, err := (*dynamicClient).Resource(resourceID).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, err
	}
	if len(list.Items) != 1 {
		return nil, fmt.Errorf("could not find a single service for the given policy server app label")
	}
	var service v1.Service
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[0].UnstructuredContent(), &service)
	if err != nil {
		return nil, err
	}
	return &service, nil
}
