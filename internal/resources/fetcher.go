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
	"k8s.io/client-go/tools/pager"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	// dynamicClient is used to fetch resource data
	dynamicClient dynamic.Interface
	// client knows about policies.kubewarden.io GVK
	client client.Client
	// list of skipped namespaces from audit, by name. It includes kubewardenNamespace
	skippedNs []string
}

// NewFetcher returns a new resource fetcher
func NewFetcher(dynamicClient dynamic.Interface, client client.Client, kubewardenNamespace string, skippedNs []string) (*Fetcher, error) {
	skippedNs = append(skippedNs, kubewardenNamespace)

	return &Fetcher{
		dynamicClient,
		client,
		skippedNs,
	}, nil
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
		opts.LabelSelector = labelSelector
	}

	list, err = f.dynamicClient.Resource(resourceID).Namespace(nsName).List(ctx, opts)

	if err != nil {
		return nil, err
	}

	return list, nil
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

func (f *Fetcher) GetNamespace(nsName string) (*v1.Namespace, error) {
	namespace := &v1.Namespace{}
	err := f.client.Get(context.Background(),
		client.ObjectKey{
			Name: nsName,
		},
		namespace)
	if err != nil {
		return nil, err
	}

	return namespace, nil
}
