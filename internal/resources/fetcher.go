package resources

import (
	"context"

	"github.com/gookit/goutil/dump"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/pager"
	ctrl "sigs.k8s.io/controller-runtime"
)

const pageSize = 100

// Fetcher fetches all auditable resources.
// Uses a dynamic client to get all resources from the rules defined in a policy
type Fetcher struct {
	// dynamicClient is used to fetch resource data
	dynamicClient dynamic.Interface
	// Namespace where the Kubewarden components (e.g. policy server) are installed
	// This is the namespace used to fetch the policy server resources
	kubewardenNamespace string
}

// NewFetcher returns a new fetcher with a dynamic client
func NewFetcher(kubewardenNamespace string) (*Fetcher, error) {
	config := ctrl.GetConfigOrDie()
	dynamicClient := dynamic.NewForConfigOrDie(config)

	return &Fetcher{dynamicClient, kubewardenNamespace}, nil
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
