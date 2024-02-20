package resources

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestGetResources(t *testing.T) {
	var pods []runtime.Object
	for i := 0; i < 15; i++ {
		pods = append(pods, &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", i), Namespace: "default"}})
	}

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme, pods...)
	fakeClient := fake.NewSimpleClientset()

	fetcher, err := NewFetcher(dynamicClient, fakeClient, "kubewarden", nil)
	if err != nil {
		t.Errorf("Error creating fetcher: %s", err)
	}

	pager, err := fetcher.GetResources(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}, "default", "")
	require.NoError(t, err)

	list, _, err := pager.List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)

	unstructuredList, ok := list.(*unstructured.UnstructuredList)
	require.True(t, ok, "expected unstructured list")

	assert.Len(t, unstructuredList.Items, 15)
	assert.Equal(t, "PodList", unstructuredList.GetObjectKind().GroupVersionKind().Kind)
}
