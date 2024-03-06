package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admissionv1 "k8s.io/api/admission/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesClient    *policies.Client
	k8sClient         *k8s.Client
	policyReportStore *report.PolicyReportStore
	// http client used to make requests against the Policy Server
	httpClient   http.Client
	outputScan   bool
	disableStore bool
}

// NewScanner creates a new scanner
// If insecureClient is false, it will read the caCertFile and add it to the in-app
// cert trust store. This gets used by the httpClient when connection to
// PolicyServers endpoints.
func NewScanner(
	policiesClient *policies.Client,
	k8sClient *k8s.Client,
	policyReportStore *report.PolicyReportStore,
	outputScan bool,
	disableStore bool,
	insecureClient bool,
	caCertFile string,
) (*Scanner, error) {
	// Get the SystemCertPool to build an in-app cert pool from it
	// Continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caCertFile != "" {
		certs, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q with CA cert: %w", caCertFile, err)
		}
		// Append our cert to the in-app cert pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("failed to append cert to in-app RootCAs trust store")
		}
		log.Debug().Str("ca-cert-file", caCertFile).
			Msg("appended cert file to in-app RootCAs trust store")
	}

	httpClient := *http.DefaultClient
	httpClient.Timeout = 10 * time.Second
	httpClient.Transport = http.DefaultTransport
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("failed to build httpClient: failed http.Transport type assertion")
	}
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs, // our augmented in-app cert pool
		MinVersion: tls.VersionTLS12,
	}

	if insecureClient {
		transport.TLSClientConfig.InsecureSkipVerify = true
		log.Warn().Msg("connecting to PolicyServers endpoints without validating TLS connection")
	}

	return &Scanner{
		policiesClient:    policiesClient,
		k8sClient:         k8sClient,
		policyReportStore: policyReportStore,
		httpClient:        httpClient,
		outputScan:        outputScan,
		disableStore:      disableStore,
	}, nil
}

// ScanNamespace scans resources for a given namespace.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanNamespace(ctx context.Context, nsName string) error {
	log.Info().Str("namespace", nsName).Msg("namespace scan started")

	_, err := s.k8sClient.GetNamespace(ctx, nsName)
	if err != nil {
		return err
	}
	policies, err := s.policiesClient.GetPoliciesForANamespace(ctx, nsName)
	if err != nil {
		return err
	}

	log.Info().
		Str("namespace", nsName).
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", policies.PolicyNum).
			Int("policies skipped", policies.SkippedNum),
		).Msg("policy count")

	for gvr, policies := range policies.PoliciesByGVR {
		pager, err := s.k8sClient.GetResources(gvr, nsName)
		if err != nil {
			return err
		}

		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return fmt.Errorf("failed to convert runtime.Object to *unstructured.Unstructured")
			}
			s.auditResource(ctx, policies, *resource)

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// ScanAllNamespaces scans resources for all namespaces, except the ones in the skipped list.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces(ctx context.Context) error {
	log.Info().Msg("all-namespaces scan started")
	nsList, err := s.k8sClient.GetAuditedNamespaces(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error scanning all namespaces")
	}

	for _, ns := range nsList.Items {
		if e := s.ScanNamespace(ctx, ns.Name); e != nil {
			log.Error().Err(e).Str("ns", ns.Name).Msg("error scanning namespace")
			err = errors.Join(err, e)
		}
	}
	log.Info().Msg("all-namespaces scan finished")
	return err
}

// ScanClusterWideResources scans all cluster wide resources.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanClusterWideResources(ctx context.Context) error {
	log.Info().Msg("clusterwide resources scan started")

	policies, err := s.policiesClient.GetClusterWidePolicies(ctx)
	if err != nil {
		return err
	}

	log.Info().
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", policies.PolicyNum).
			Int("policies skipped", policies.SkippedNum),
		).Msg("cluster admission policies count")

	for gvr, policies := range policies.PoliciesByGVR {
		pager, err := s.k8sClient.GetResources(gvr, "")
		if err != nil {
			return err
		}

		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return fmt.Errorf("failed to convert runtime.Object to *unstructured.Unstructured")
			}

			s.auditClusterResource(ctx, policies, *resource)

			return nil
		})
		if err != nil {
			return err
		}
	}

	log.Info().Msg("clusterwide resources scan finished")

	return nil
}

//nolint:funlen
func (s *Scanner) auditResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured) {
	policyReport := report.NewPolicyReport(resource)
	oldPolicyReport, err := s.policyReportStore.GetPolicyReport(ctx, string(resource.GetUID()), resource.GetNamespace())
	if err != nil && !apimachineryerrors.IsNotFound(err) {
		log.Error().Err(err).Msg("error obtaining PolicyReport")
	}

	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		matches, err := policyMatches(policy, resource)
		if err != nil {
			log.Error().Err(err).Msg("error matching policy to resource")
		}

		if !matches {
			continue
		}

		// If the resource has been audited before, and the policy has not changed, we can skip the audit and use the previous result
		if oldPolicyReport != nil {
			oldResult := report.FindPolicyReportResultByResourceAndPolicy(oldPolicyReport, policy, resource)

			if oldResult != nil {
				log.Debug().Dict("response", zerolog.Dict().
					Str("policy", policy.GetUniqueName()).
					Str("resource", resource.GetName()).
					Str("resource UID", string(resource.GetUID())).
					Str("result", string(oldResult.Result)),
				).
					Msg("audit review response from previous audit")

				report.AddResultToPolicyReport(policyReport, oldResult)
				continue
			}
		}

		admissionReviewRequest := newAdmissionReview(resource)
		admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)

		errored := responseErr != nil
		if errored {
			// log responseErr, will end in PolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionReviewRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(admissionReviewResponse.Response.UID)).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()).
				Bool("allowed", admissionReviewResponse.Response.Allowed),
			).
				Msg("audit review response")
		}
		result := report.NewPolicyReportResult(policy, admissionReviewResponse, errored, metav1.Timestamp{Seconds: time.Now().Unix()})
		report.AddResultToPolicyReport(policyReport, result)
	}

	if s.outputScan {
		policyReportJSON, err := json.Marshal(policyReport)
		if err != nil {
			log.Error().Err(err).Msg("error while marshalling PolicyReport to JSON, skipping output scan")
		}

		log.Info().
			RawJSON("report", policyReportJSON).
			Msg("PolicyReport summary")
	}

	if !s.disableStore {
		err := s.policyReportStore.CreateOrUpdatePolicyReport(ctx, oldPolicyReport, policyReport)
		if err != nil {
			log.Error().Err(err).Msg("error adding PolicyReport to the store")
		}
	}
}

//nolint:funlen
func (s *Scanner) auditClusterResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured) {
	clusterPolicyReport := report.NewClusterPolicyReport(resource)
	oldClusterPolicyReport, err := s.policyReportStore.GetClusterPolicyReport(ctx, string(resource.GetUID()))
	if err != nil && !apimachineryerrors.IsNotFound(err) {
		log.Error().Err(err).Msg("error obtaining PolicyReport")
	}

	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		matches, err := policyMatches(policy, resource)
		if err != nil {
			log.Error().Err(err).Msg("error matching policy to resource")
		}

		if !matches {
			continue
		}

		// If the resource has been audited before, and the policy has not changed, we can skip the audit and use the previous result
		if oldClusterPolicyReport != nil {
			oldResult := report.FindClusterPolicyReportResultByResourceAndPolicy(oldClusterPolicyReport, policy, resource)

			if oldResult != nil {
				log.Debug().Dict("response", zerolog.Dict().
					Str("policy", policy.GetUniqueName()).
					Str("resource", resource.GetName()).
					Str("resource UID", string(resource.GetUID())).
					Str("result", string(oldResult.Result)),
				).
					Msg("audit review response from previous audit")

				report.AddResultToClusterPolicyReport(clusterPolicyReport, oldResult)
				continue
			}
		}

		admissionReviewRequest := newAdmissionReview(resource)
		admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)

		errored := responseErr != nil
		if errored {
			// log error, will end in ClusterPolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionReviewRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(admissionReviewResponse.Response.UID)).
				Bool("allowed", admissionReviewResponse.Response.Allowed).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("audit review response")
		}
		result := report.NewPolicyReportResult(policy, admissionReviewResponse, errored, metav1.Timestamp{Seconds: time.Now().Unix()})
		report.AddResultToClusterPolicyReport(clusterPolicyReport, result)
	}

	if s.outputScan {
		clusterPolicyReportJSON, err := json.Marshal(clusterPolicyReport)
		if err != nil {
			log.Error().Err(err).Msg("error while marshalling ClusterPolicyReport to JSON, skipping output scan")
		}

		log.Info().
			RawJSON("report", clusterPolicyReportJSON).
			Msg("ClusterPolicyReport summary")
	}

	if !s.disableStore {
		err := s.policyReportStore.CreateOrUpdateClusterPolicyReport(ctx, oldClusterPolicyReport, clusterPolicyReport)
		if err != nil {
			log.Error().Err(err).Msg("error adding ClusterPolicyReport to store")
		}
	}
}

func policyMatches(policy policiesv1.Policy, resource unstructured.Unstructured) (bool, error) {
	if policy.GetObjectSelector() == nil {
		return true, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(policy.GetObjectSelector())
	if err != nil {
		log.Error().Err(err).Msg("error creating label selector from policy")

		return false, err
	}

	labels := labels.Set(resource.GetLabels())
	if !selector.Matches(labels) {
		return false, nil
	}

	return true, nil
}

func (s *Scanner) sendAdmissionReviewToPolicyServer(ctx context.Context, url *url.URL, admissionRequest *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewBuffer(payload))
	req.Header.Add("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d body: %s", res.StatusCode, body)
	}

	admissionReview := admissionv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}
