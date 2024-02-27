package report

import (
	"context"
	"testing"

	"github.com/gookit/goutil/dump"
	testutils "github.com/kubewarden/audit-scanner/internal/testutils"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestCreateOrPatchPolicyReport(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pod",
			Namespace:       "namespace",
			UID:             "123",
			ResourceVersion: "123",
		},
	}
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	obj := unstructured.Unstructured{}
	obj.SetUnstructuredContent(unstructuredObj)
	require.NoError(t, err)

	policyReport := NewPolicyReport(obj)

	dump.P(policyReport)

	fakeClient := testutils.NewFakeClient()
	store := NewPolicyReportStore(fakeClient)

	err = store.CreateOrPatchPolicyReport(context.TODO(), &policyReport)
	require.NoError(t, err)

	expectedPolicyReport := &wgpolicy.PolicyReport{}
	err = fakeClient.Get(context.TODO(), client.ObjectKey{Name: string(pod.GetUID()), Namespace: "namespace"}, expectedPolicyReport)
	require.NoError(t, err)

	dump.P(expectedPolicyReport)

	pod.ObjectMeta.ResourceVersion = "124"
	unstructuredObj, err = runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	obj = unstructured.Unstructured{}
	obj.SetUnstructuredContent(unstructuredObj)
	require.NoError(t, err)

	policyReport = NewPolicyReport(obj)
	err = store.CreateOrPatchPolicyReport(context.TODO(), &policyReport)
	require.NoError(t, err)

	expectedPolicyReport = &wgpolicy.PolicyReport{}
	err = fakeClient.Get(context.TODO(), client.ObjectKey{Name: string(pod.GetUID()), Namespace: "namespace"}, expectedPolicyReport)
	require.NoError(t, err)

	dump.P(expectedPolicyReport)
}
