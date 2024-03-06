package report

import (
	"testing"
	"time"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestNewPolicyReport(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetNamespace("namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Pod")
	resource.SetName("test-pod")
	resource.SetResourceVersion("12345")

	policyReport := NewPolicyReport(resource)

	assert.Equal(t, "uid", policyReport.ObjectMeta.Name)
	assert.Equal(t, "namespace", policyReport.ObjectMeta.Namespace)
	assert.Equal(t, "kubewarden", policyReport.ObjectMeta.Labels["app.kubernetes.io/managed-by"])

	assert.Equal(t, "v1", policyReport.ObjectMeta.OwnerReferences[0].APIVersion)
	assert.Equal(t, "Pod", policyReport.ObjectMeta.OwnerReferences[0].Kind)
	assert.Equal(t, "test-pod", policyReport.ObjectMeta.OwnerReferences[0].Name)
	assert.Equal(t, types.UID("uid"), policyReport.ObjectMeta.OwnerReferences[0].UID)

	assert.Equal(t, "v1", policyReport.Scope.APIVersion)
	assert.Equal(t, "Pod", policyReport.Scope.Kind)
	assert.Equal(t, "test-pod", policyReport.Scope.Name)
	assert.Equal(t, types.UID("uid"), policyReport.Scope.UID)
	assert.Equal(t, "12345", policyReport.Scope.ResourceVersion)

	assert.Empty(t, policyReport.Results)
}

func TestAddResultToPolicyReport(t *testing.T) {
	policy := &policiesv1.AdmissionPolicy{}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: true,
			Result:  &metav1.Status{Message: "The request was allowed"},
		},
	}

	policyReport := NewPolicyReport(unstructured.Unstructured{})
	result := NewPolicyReportResult(policy, admissionReview, false, metav1.Timestamp{Seconds: time.Now().Unix()})
	AddResultToPolicyReport(policyReport, result)

	assert.Len(t, policyReport.Results, 1)
	assert.Equal(t, 1, policyReport.Summary.Pass)
	assert.Equal(t, 0, policyReport.Summary.Fail)
	assert.Equal(t, 0, policyReport.Summary.Warn)
	assert.Equal(t, 0, policyReport.Summary.Error)
}

//nolint:dupl
func TestFindPolicyReportResultByResourceAndPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyReport   *wgpolicy.PolicyReport
		policy         policiesv1.Policy
		resource       unstructured.Unstructured
		expectedResult *wgpolicy.PolicyReportResult
	}{
		{
			name: "result found",
			policyReport: &wgpolicy.PolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "456",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: &wgpolicy.PolicyReportResult{
				Properties: map[string]string{
					"policy-uid":              "policy-uid",
					"policy-resource-version": "456",
				},
				Result: statusPass,
			},
		},
		{
			name: "result not found, resource has a different resourceVersion",
			policyReport: &wgpolicy.PolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "456",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "789",
					},
				},
			},
			expectedResult: nil,
		},
		{
			name: "result not found, policy has a different resourceVersion",
			policyReport: &wgpolicy.PolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "789",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: nil,
		},
		{
			name: "result not found, policy was never audited",
			policyReport: &wgpolicy.PolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "other-policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "789",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := FindPolicyReportResultByResourceAndPolicy(test.policyReport, test.policy, test.resource)
			assert.Equal(t, test.expectedResult, result)
		})
	}
}

func TestNewClusterPolicyReport(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetName("test-namespace")
	resource.SetAPIVersion("v1")
	resource.SetKind("Namespace")
	resource.SetResourceVersion("12345")

	clusterPolicyReport := NewClusterPolicyReport(resource)

	assert.Equal(t, "uid", clusterPolicyReport.ObjectMeta.Name)
	assert.Equal(t, "kubewarden", clusterPolicyReport.ObjectMeta.Labels[labelAppManagedBy])

	assert.Equal(t, "v1", clusterPolicyReport.ObjectMeta.OwnerReferences[0].APIVersion)
	assert.Equal(t, "Namespace", clusterPolicyReport.ObjectMeta.OwnerReferences[0].Kind)
	assert.Equal(t, "test-namespace", clusterPolicyReport.ObjectMeta.OwnerReferences[0].Name)
	assert.Equal(t, types.UID("uid"), clusterPolicyReport.ObjectMeta.OwnerReferences[0].UID)

	assert.Equal(t, "v1", clusterPolicyReport.Scope.APIVersion)
	assert.Equal(t, "Namespace", clusterPolicyReport.Scope.Kind)
	assert.Equal(t, "test-namespace", clusterPolicyReport.Scope.Name)
	assert.Equal(t, types.UID("uid"), clusterPolicyReport.Scope.UID)
	assert.Equal(t, "12345", clusterPolicyReport.Scope.ResourceVersion)

	assert.Empty(t, clusterPolicyReport.Results)
}

func TestAddResultToClusterPolicyReport(t *testing.T) {
	policy := &policiesv1.AdmissionPolicy{}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: "The request was rejected"},
		},
	}

	clusterPolicyReport := NewClusterPolicyReport(unstructured.Unstructured{})
	result := NewPolicyReportResult(policy, admissionReview, false, metav1.Timestamp{Seconds: time.Now().Unix()})
	AddResultToClusterPolicyReport(clusterPolicyReport, result)

	assert.Len(t, clusterPolicyReport.Results, 1)
	assert.Equal(t, 0, clusterPolicyReport.Summary.Pass)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Fail)
	assert.Equal(t, 0, clusterPolicyReport.Summary.Warn)
	assert.Equal(t, 0, clusterPolicyReport.Summary.Error)
}

//nolint:dupl
func TestFindClusterPolicyReportResultByResourceAndPolicy(t *testing.T) {
	tests := []struct {
		name                string
		clusterPolicyReport *wgpolicy.ClusterPolicyReport
		policy              policiesv1.Policy
		resource            unstructured.Unstructured
		expectedResult      *wgpolicy.PolicyReportResult
	}{
		{
			name: "result found",
			clusterPolicyReport: &wgpolicy.ClusterPolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "456",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: &wgpolicy.PolicyReportResult{
				Properties: map[string]string{
					"policy-uid":              "policy-uid",
					"policy-resource-version": "456",
				},
				Result: statusPass,
			},
		},
		{
			name: "result not found, resource has a different resourceVersion",
			clusterPolicyReport: &wgpolicy.ClusterPolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "456",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "789",
					},
				},
			},
			expectedResult: nil,
		},
		{
			name: "result not found, policy has a different resourceVersion",
			clusterPolicyReport: &wgpolicy.ClusterPolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "789",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: nil,
		},
		{
			name: "result not found, policy was never audited",
			clusterPolicyReport: &wgpolicy.ClusterPolicyReport{
				Scope: &corev1.ObjectReference{
					UID:             "resource-uid",
					ResourceVersion: "123",
				},
				Results: []*wgpolicy.PolicyReportResult{
					{
						Properties: map[string]string{
							"policy-uid":              "other-policy-uid",
							"policy-resource-version": "456",
						},
						Result: statusPass,
					},
				},
			},
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "789",
				},
			},
			resource: unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid":             "resource-uid",
						"resourceVersion": "123",
					},
				},
			},
			expectedResult: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := FindClusterPolicyReportResultByResourceAndPolicy(test.clusterPolicyReport, test.policy, test.resource)
			assert.Equal(t, test.expectedResult, result)
		})
	}
}

func TestNewPolicyReportResult(t *testing.T) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}

	tests := []struct {
		name           string
		policy         policiesv1.Policy
		amissionReview *admissionv1.AdmissionReview
		errored        bool
		expectedResult *wgpolicy.PolicyReportResult
	}{
		{
			name: "Validating policy, allowed response",
			policy: &policiesv1.ClusterAdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityLow,
					},
				},
				Spec: policiesv1.ClusterAdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: false,
					},
				},
			},
			amissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: true,
					Result:  nil,
				},
			},
			errored: false,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "clusterwide-policy-name",
				Severity:        severityLow,
				Result:          statusPass,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					typeValidating:                valueTypeTrue,
				},
			},
		},
		{
			name: "Mutating policy, rejected response",
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Namespace:       "policy-namespace",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityCritical,
					},
				},
				Spec: policiesv1.AdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: true,
					},
				},
			},
			amissionReview: &admissionv1.AdmissionReview{
				Response: &admissionv1.AdmissionResponse{
					Allowed: false,
					Result:  &metav1.Status{Message: "The request was rejected"},
				},
			},
			errored: false,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "namespaced-policy-namespace-policy-name",
				Severity:        severityCritical,
				Result:          statusFail,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "The request was rejected",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					typeMutating:                  valueTypeTrue,
				},
			},
		},
		{
			name: "Validating policy in monitor mode, response error",
			policy: &policiesv1.AdmissionPolicy{
				ObjectMeta: metav1.ObjectMeta{
					UID:             "policy-uid",
					ResourceVersion: "1",
					Name:            "policy-name",
					Namespace:       "policy-namespace",
					Annotations: map[string]string{
						policiesv1.AnnotationSeverity: severityInfo,
					},
				},
				Spec: policiesv1.AdmissionPolicySpec{
					PolicySpec: policiesv1.PolicySpec{
						Mutating: false,
						Mode:     policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor),
					},
				},
			},
			amissionReview: nil,
			errored:        true,
			expectedResult: &wgpolicy.PolicyReportResult{
				Source:          policyReportSource,
				Policy:          "namespaced-policy-namespace-policy-name",
				Severity:        severityInfo,
				Result:          statusError,
				Timestamp:       now,
				Scored:          true,
				SubjectSelector: &metav1.LabelSelector{},
				Description:     "",
				Properties: map[string]string{
					propertyPolicyUID:             "policy-uid",
					propertyPolicyResourceVersion: "1",
					typeValidating:                valueTypeTrue,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewPolicyReportResult(test.policy, test.amissionReview, test.errored, now)
			assert.Equal(t, test.expectedResult, result)
		})
	}
}
