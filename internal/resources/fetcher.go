package resources

import (
	"context"
	"fmt"

	"github.com/gookit/goutil/dump"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
)

const pageSize = 100

// type ResourceFetcher interface {
// 	GetResources(gvr schema.GroupVersionResource, nsName string, labelSelector *metav1.LabelSelector) (*pager.ListPager, error)
// 	// GetNamespace gets a given namespace
// 	GetNamespace(namespace string) (*v1.Namespace, error)
// 	// GetAuditedNamespaces gets all namespaces, minus those in the skipped ns list
// 	GetAuditedNamespaces() (*v1.NamespaceList, error)
// }

// Fetcher fetches all auditable resources.
// Uses a dynamic client to get all resources from the rules defined in a policy
type Fetcher struct {
	// dynamicClient is used to fetch resource lists
	dynamicClient dynamic.Interface
	// client is used to fetch namespaces
	clientset kubernetes.Interface
	// list of skipped namespaces from audit, by name. It includes kubewardenNamespace
	skippedNs []string
}

// NewFetcher returns a new resource fetcher
func NewFetcher(dynamicClient dynamic.Interface, clientset kubernetes.Interface, kubewardenNamespace string, skippedNs []string) (*Fetcher, error) {
	skippedNs = append(skippedNs, kubewardenNamespace)

	return &Fetcher{
		dynamicClient,
		clientset,
		skippedNs,
	}, nil
}

func (f *Fetcher) GetResources(gvr schema.GroupVersionResource, nsName string, labelSelector string) (*pager.ListPager, error) {
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
	labelSelector string,
	opts metav1.ListOptions,
) (
	*unstructured.UnstructuredList, error,
) {
	resourceID := schema.GroupVersionResource{
		Group:    gvr.Group,
		Version:  gvr.Version,
		Resource: gvr.Resource,
	}

	opts.LabelSelector = labelSelector

	return f.dynamicClient.Resource(resourceID).Namespace(nsName).List(ctx, opts)
}

// GetAuditedNamespaces gets all namespaces besides the ones in fetcher.skippedNs
func (f *Fetcher) GetAuditedNamespaces(ctx context.Context) (*v1.NamespaceList, error) {
	// This function cannot be tested with fake client, as filtering is done server-side
	skipNsFields := fields.Everything()
	for _, nsName := range f.skippedNs {
		skipNsFields = fields.AndSelectors(skipNsFields, fields.OneTermNotEqualSelector("metadata.name", nsName))
		log.Debug().Str("ns", nsName).Msg("skipping ns")
	}

	namespaceList, err := f.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{FieldSelector: skipNsFields.String()})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	return namespaceList, nil
}

func (f *Fetcher) GetNamespace(ctx context.Context, nsName string) (*v1.Namespace, error) {
	return f.clientset.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
}
