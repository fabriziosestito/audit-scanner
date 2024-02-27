package report

import (
	"time"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func NewPolicyReport(resource unstructured.Unstructured) wgpolicy.PolicyReport {
	return wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(resource.GetUID()),
			Namespace: resource.GetNamespace(),
			Labels: map[string]string{
				LabelAppManagedBy: LabelApp,
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
		Scope: &v1.ObjectReference{
			Kind:            resource.GetKind(),
			Namespace:       resource.GetNamespace(),
			Name:            resource.GetName(),
			UID:             resource.GetUID(),
			APIVersion:      resource.GetAPIVersion(),
			ResourceVersion: resource.GetResourceVersion(),
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
		Results: []*wgpolicy.PolicyReportResult{},
	}
}

func AddResultToPolicyReport(
	policyReport *wgpolicy.PolicyReport,
	policy policiesv1.Policy,
	amissionResponse *admissionv1.AdmissionResponse, responseErr error,
) *wgpolicy.PolicyReportResult {
	result := newPolicyReportResult(policy, amissionResponse, responseErr)
	switch result.Result {
	case StatusFail:
		policyReport.Summary.Fail++
	case StatusError:
		policyReport.Summary.Error++
	case StatusPass:
		policyReport.Summary.Pass++
	}
	policyReport.Results = append(policyReport.Results, result)

	return result
}

func NewClusterPolicyReport(resource unstructured.Unstructured) wgpolicy.ClusterPolicyReport {
	return wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(resource.GetUID()),
			Labels: map[string]string{
				LabelAppManagedBy: LabelApp,
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
		Scope: &v1.ObjectReference{
			Kind:            resource.GetKind(),
			Name:            resource.GetName(),
			UID:             resource.GetUID(),
			APIVersion:      resource.GetAPIVersion(),
			ResourceVersion: resource.GetResourceVersion(),
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
		Results: []*wgpolicy.PolicyReportResult{},
	}
}

func AddResultToClusterPolicyReport(
	policyReport *wgpolicy.ClusterPolicyReport,
	policy policiesv1.Policy,
	amissionResponse *admissionv1.AdmissionResponse, responseErr error,
) *wgpolicy.PolicyReportResult {
	result := newPolicyReportResult(policy, amissionResponse, responseErr)
	switch result.Result {
	case StatusFail:
		policyReport.Summary.Fail++
	case StatusError:
		policyReport.Summary.Error++
	case StatusPass:
		policyReport.Summary.Pass++
	}
	policyReport.Results = append(policyReport.Results, result)

	return result
}

func newPolicyReportResult(policy policiesv1.Policy, amissionResponse *admissionv1.AdmissionResponse, responseErr error) *wgpolicy.PolicyReportResult {
	severity := computePolicyResultSeverity(policy)
	scored := false
	if severity != "" {
		scored = true
	}

	var category string
	if c, present := policy.GetCategory(); present {
		category = c
	}

	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	return &wgpolicy.PolicyReportResult{
		Source:          PolicyReportSource,
		Policy:          policy.GetUniqueName(),
		Category:        category,
		Severity:        severity,                                                   // either info for monitor or empty
		Timestamp:       now,                                                        // time the result was computed
		Result:          computePolicyResult(responseErr, amissionResponse.Allowed), // pass, fail, error
		Scored:          scored,
		SubjectSelector: &metav1.LabelSelector{},
		Description:     amissionResponse.Result.Message, // output message of the policy
		Properties:      computeProperties(policy),
	}
}

func computePolicyResult(responseErr error, allowed bool) wgpolicy.PolicyResult {
	if responseErr != nil {
		return StatusError
	}
	if allowed {
		return StatusPass
	}

	return StatusFail
}

func computePolicyResultSeverity(policy policiesv1.Policy) wgpolicy.PolicyResultSeverity {
	var severity wgpolicy.PolicyResultSeverity

	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		return SeverityInfo
	}

	if s, present := policy.GetSeverity(); present {
		switch s {
		case SeverityCritical:
			severity = SeverityCritical
		case SeverityHigh:
			severity = SeverityHigh
		case SeverityMedium:
			severity = SeverityMedium
		case SeverityLow:
			severity = SeverityLow
		}
	}

	return severity
}

func computeProperties(policy policiesv1.Policy) map[string]string {
	properties := map[string]string{}
	if policy.IsMutating() {
		properties[TypeMutating] = ValueTypeTrue
	} else {
		properties[TypeValidating] = ValueTypeTrue
	}
	if policy.IsContextAware() {
		properties[TypeContextAware] = ValueTypeTrue
	}
	// The policy resource version and the policy UID are used to check if the
	// same result can be reused in the next scan
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	properties[PropertyPolicyResourceVersion] = policy.GetResourceVersion()
	properties[PropertyPolicyUID] = string(policy.GetUID())

	return properties
}
