package report

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

type PolicyReportStore struct {
	client client.Client
}

func NewPolicyReportStore(client client.Client) *PolicyReportStore {
	return &PolicyReportStore{
		client: client,
	}
}

func (s *PolicyReportStore) CreateOrPatchPolicyReport(ctx context.Context, policyReport *wgpolicy.PolicyReport) error {
	oldPolicyReport := &wgpolicy.PolicyReport{ObjectMeta: metav1.ObjectMeta{
		Name:      policyReport.GetName(),
		Namespace: policyReport.GetNamespace(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldPolicyReport, func() error {
		oldPolicyReport.ObjectMeta.Labels = policyReport.ObjectMeta.Labels
		oldPolicyReport.ObjectMeta.OwnerReferences = policyReport.ObjectMeta.OwnerReferences
		oldPolicyReport.Scope = policyReport.Scope
		oldPolicyReport.Summary = policyReport.Summary
		oldPolicyReport.Results = policyReport.Results

		return nil
	})
	if err != nil {
		return err
	}

	log.Debug().Dict("dict", zerolog.Dict()).
		Str("report name", policyReport.GetName()).
		Str("report version", policyReport.GetResourceVersion()).
		Str("resource name", policyReport.Scope.Name).
		Str("resource namespace", policyReport.Scope.Namespace).
		Str("resource version", policyReport.Scope.ResourceVersion).
		Msgf("PolicyReport %s", operation)

	return nil
}

func (s *PolicyReportStore) CreateOrPatchClusterPolicyReport(ctx context.Context, clusterPolicyReport *wgpolicy.ClusterPolicyReport) error {
	oldClusterPolicyReport := &wgpolicy.ClusterPolicyReport{ObjectMeta: metav1.ObjectMeta{
		Name: clusterPolicyReport.GetName(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldClusterPolicyReport, func() error {
		oldClusterPolicyReport.ObjectMeta.Labels = clusterPolicyReport.ObjectMeta.Labels
		oldClusterPolicyReport.ObjectMeta.OwnerReferences = clusterPolicyReport.ObjectMeta.OwnerReferences
		oldClusterPolicyReport.Scope = clusterPolicyReport.Scope
		oldClusterPolicyReport.Summary = clusterPolicyReport.Summary
		oldClusterPolicyReport.Results = clusterPolicyReport.Results

		return nil
	})
	if err != nil {
		return err
	}

	log.Debug().Dict("dict", zerolog.Dict()).
		Str("report name", clusterPolicyReport.GetName()).
		Str("report version", clusterPolicyReport.GetResourceVersion()).
		Str("resource name", clusterPolicyReport.Scope.Name).
		Str("resource namespace", clusterPolicyReport.Scope.Namespace).
		Str("resource version", clusterPolicyReport.Scope.ResourceVersion).
		Msgf("ClusterPolicyReport %s", operation)

	return nil
}
