package report

import (
	"time"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// NewPolicyReport creates a new PolicyReport from a given resource.
func NewPolicyReport(runUID string, resource unstructured.Unstructured) *wgpolicy.PolicyReport {
	return &wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(resource.GetUID()),
			Namespace: resource.GetNamespace(),
			Labels: map[string]string{
				labelAppManagedBy:                 labelApp,
				labelPolicyReportVersion:          labelPolicyReportVersionValue,
				constants.AuditScannerRunUIDLabel: runUID,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: resource.GetAPIVersion(),
					Kind:       resource.GetKind(),
					Name:       resource.GetName(),
					UID:        resource.GetUID(),
				},
			},
		},
		Scope: &corev1.ObjectReference{
			APIVersion:      resource.GetAPIVersion(),
			Kind:            resource.GetKind(),
			Namespace:       resource.GetNamespace(),
			Name:            resource.GetName(),
			UID:             resource.GetUID(),
			ResourceVersion: resource.GetResourceVersion(),
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
	}
}

// AddResultToPolicyReport adds a result to a PolicyReport and updates the summary.
func AddResultToPolicyReport(
	policyReport *wgpolicy.PolicyReport,
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) *wgpolicy.PolicyReportResult {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		policyReport.Summary.Fail++
	case statusError:
		policyReport.Summary.Error++
	case statusPass:
		policyReport.Summary.Pass++
	}
	policyReport.Results = append(policyReport.Results, result)

	return result
}

// NewClusterPolicyReport creates a new ClusterPolicyReport from a given resource.
func NewClusterPolicyReport(runUID string, resource unstructured.Unstructured) *wgpolicy.ClusterPolicyReport {
	return &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(resource.GetUID()),
			Labels: map[string]string{
				labelAppManagedBy:                 labelApp,
				labelPolicyReportVersion:          labelPolicyReportVersionValue,
				constants.AuditScannerRunUIDLabel: runUID,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: resource.GetAPIVersion(),
					Kind:       resource.GetKind(),
					Name:       resource.GetName(),
					UID:        resource.GetUID(),
				},
			},
		},
		Scope: &corev1.ObjectReference{
			APIVersion:      resource.GetAPIVersion(),
			Kind:            resource.GetKind(),
			Name:            resource.GetName(),
			UID:             resource.GetUID(),
			ResourceVersion: resource.GetResourceVersion(),
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
	}
}

// AddResultToClusterPolicyReport adds a result to a ClusterPolicyReport and updates the summary.
func AddResultToClusterPolicyReport(
	policyReport *wgpolicy.ClusterPolicyReport,
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) *wgpolicy.PolicyReportResult {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		policyReport.Summary.Fail++
	case statusError:
		policyReport.Summary.Error++
	case statusPass:
		policyReport.Summary.Pass++
	}
	policyReport.Results = append(policyReport.Results, result)

	return result
}

func newPolicyReportResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool, timestamp metav1.Timestamp) *wgpolicy.PolicyReportResult {
	var category string
	if c, present := policy.GetCategory(); present {
		category = c
	}

	var message string
	// We need to check if Result is not nil because this field is
	// optional. If the policy returns "allowed" to the admissionReview,
	// the Result field is not checked by Kubernetes.
	// https://pkg.go.dev/k8s.io/api@v0.29.2/admission/v1#AdmissionResponse
	if admissionReview != nil &&
		admissionReview.Response != nil &&
		admissionReview.Response.Result != nil {
		// Mesage contains the human-readable error message if Response.Result.Code == 500
		// or the reason why the policy returned a failure
		message = admissionReview.Response.Result.Message
	}

	return &wgpolicy.PolicyReportResult{
		Source:          policyReportSource,
		Policy:          policy.GetUniqueName(),
		Category:        category,
		Severity:        computePolicyResultSeverity(policy),           // either info for monitor or empty
		Timestamp:       timestamp,                                     // time the result was computed
		Result:          computePolicyResult(errored, admissionReview), // pass, fail, error
		Scored:          true,
		SubjectSelector: &metav1.LabelSelector{},
		// This field is marshalled to `message`
		Description: message,
		Properties:  computeProperties(policy),
	}
}

func computePolicyResult(errored bool, admissionReview *admissionv1.AdmissionReview) wgpolicy.PolicyResult {
	if errored {
		return statusError
	}
	if admissionReview.Response.Allowed {
		return statusPass
	}

	return statusFail
}

func computePolicyResultSeverity(policy policiesv1.Policy) wgpolicy.PolicyResultSeverity {
	var severity wgpolicy.PolicyResultSeverity

	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		return severityInfo
	}

	if s, present := policy.GetSeverity(); present {
		return wgpolicy.PolicyResultSeverity(s)
	}

	return severity
}

func computeProperties(policy policiesv1.Policy) map[string]string {
	properties := map[string]string{}
	if policy.IsMutating() {
		properties[typeMutating] = valueTypeTrue
	} else {
		properties[typeValidating] = valueTypeTrue
	}
	if policy.IsContextAware() {
		properties[typeContextAware] = valueTypeTrue
	}
	// The policy resource version and the policy UID are used to check if the
	// same result can be reused in the next scan
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	properties[propertyPolicyResourceVersion] = policy.GetResourceVersion()
	properties[propertyPolicyUID] = string(policy.GetUID())
	properties[propertyPolicyName] = policy.GetName()
	if policy.GetNamespace() != "" {
		properties[propertyPolicyNamespace] = policy.GetNamespace()
	}

	return properties
}
