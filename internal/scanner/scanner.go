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

	"github.com/gookit/goutil/dump"
	reportLogger "github.com/kubewarden/audit-scanner/internal/log"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/resources"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/pager"

	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
)

// A PoliciesFetcher interacts with the kubernetes api to return Kubewarden policies
type PoliciesFetcher interface {
	// GetPoliciesForANamespace gets all auditable policies for a given
	// namespace, and the number of skipped policies
	GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, int, error)
	// GetNamespace gets a given namespace
	GetNamespace(namespace string) (*v1.Namespace, error)
	// GetAuditedNamespaces gets all namespaces, minus those in the skipped ns list
	GetAuditedNamespaces() (*v1.NamespaceList, error)
	// Get all auditable ClusterAdmissionPolicies and the number of skipped policies
	GetClusterAdmissionPolicies() ([]policiesv1.Policy, int, error)
}

type ResourcesFetcher interface {
	GetResources(gvr schema.GroupVersionResource, nsName string, labelSelector *metav1.LabelSelector) (*pager.ListPager, error)
	// GetPolicyServerURLRunningPolicy gets the URL used to send API requests to the policy server
	GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error)
	// IsNamespacedResource returns true if the resource is namespaced
	IsNamespacedResource(gvr schema.GroupVersionResource) (bool, error)
}

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesFetcher  PoliciesFetcher
	resourcesFetcher ResourcesFetcher
	reportStore      report.PolicyReportStore
	reportLogger     reportLogger.PolicyReportLogger
	// http client used to make requests against the Policy Server
	httpClient http.Client
	outputScan bool
}

// NewScanner creates a new scanner with the PoliciesFetcher provided. If
// insecureClient is false, it will read the caCertFile and add it to the in-app
// cert trust store. This gets used by the httpClient when connection to
// PolicyServers endpoints.
func NewScanner(
	storeType string,
	policiesFetcher PoliciesFetcher,
	resourcesFetcher ResourcesFetcher,
	outputScan bool,
	insecureClient bool,
	caCertFile string,
) (*Scanner, error) {
	store, err := getPolicyReportStore(storeType)
	if err != nil {
		return nil, fmt.Errorf("failed to create PolicyReportStore: %w", err)
	}

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

	// initialize httpClient while conserving default settings
	httpClient := *http.DefaultClient
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
		policiesFetcher:  policiesFetcher,
		resourcesFetcher: resourcesFetcher,
		reportStore:      store,
		reportLogger:     reportLogger.PolicyReportLogger{},
		httpClient:       httpClient,
		outputScan:       outputScan,
	}, nil
}

func getPolicyReportStore(storeType string) (report.PolicyReportStore, error) { //nolint:ireturn // returning a generic type is ok here
	switch storeType {
	case report.KUBERNETES:
		return report.NewKubernetesPolicyReportStore()
	case report.MEMORY:
		return report.NewMemoryPolicyReportStore(), nil
	default:
		return nil, fmt.Errorf("invalid policyReport store type: %s", storeType)
	}
}

// ScanNamespace scans resources for a given namespace.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanNamespace(nsName string) error {
	log.Info().Str("namespace", nsName).Msg("namespace scan started")

	namespace, err := s.policiesFetcher.GetNamespace(nsName)
	if err != nil {
		return err
	}

	policies, skippedNum, err := s.policiesFetcher.GetPoliciesForANamespace(nsName)
	if err != nil {
		return err
	}

	log.Info().
		Str("namespace", nsName).
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", len(policies)).
			Int("policies skipped", skippedNum),
		).Msg("policy count")

	// create PolicyReport
	namespacedsReport := report.NewPolicyReport(namespace)
	namespacedsReport.Summary.Skip = skippedNum

	// old policy report to be used as cache
	previousNamespacedReport, err := s.reportStore.GetPolicyReport(nsName)
	if errors.Is(err, constants.ErrResourceNotFound) {
		log.Info().Str("namespace", nsName).
			Msg("no pre-existing PolicyReport, will create one at end of the scan if needed")
	} else if err != nil {
		log.Err(err).Str("namespace", nsName).
			Msg("error when obtaining PolicyReport")
	}

	policiesByResource := s.PoliciesByResource(policies)
	for gvr, objectFilters := range policiesByResource {
		isNamespaced, err := s.resourcesFetcher.IsNamespacedResource(gvr)
		if err != nil {
			if apimachineryerrors.IsNotFound(err) {
				log.Warn().
					Str("resource GVK", gvr.String()).
					Msg("API resource not found")
				continue
			}
			return err
		}
		if !isNamespaced {
			// continue if resource is clusterwide
			continue
		}

		for filter, policies := range objectFilters {
			pager, err := s.resourcesFetcher.GetResources(gvr, nsName, filter.labelSelector)
			if err != nil {
				return err
			}

			err = pager.EachListItem(context.Background(), metav1.ListOptions{}, func(obj runtime.Object) error {
				resource := obj.(*unstructured.Unstructured)
				auditResource(policies, *resource, &s.httpClient, &previousNamespacedReport, &namespacedsReport)

				return nil
			})
			if err != nil {
				return err
			}

		}
	}

	if err := s.reportStore.SavePolicyReport(&namespacedsReport); err != nil {
		log.Error().Err(err).Msg("error adding PolicyReport to store")
	}

	log.Info().Str("namespace", nsName).Msg("namespace scan finished")

	if s.outputScan {
		s.reportLogger.LogPolicyReport(&namespacedsReport)
	}

	return nil
}

// ScanAllNamespaces scans resources for all namespaces. Skips those namespaces
// passed in the skipped list on the policy fetcher.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces() error {
	log.Info().Msg("all-namespaces scan started")
	nsList, err := s.policiesFetcher.GetAuditedNamespaces()
	if err != nil {
		log.Error().Err(err).Msg("error scanning all namespaces")
	}
	var errs error
	for _, ns := range nsList.Items {
		if err := s.ScanNamespace(ns.Name); err != nil {
			log.Error().Err(err).Str("ns", ns.Name).Msg("error scanning namespace")
			errs = errors.New(errs.Error() + err.Error())
		}
	}
	log.Info().Msg("all-namespaces scan finished")
	return errs
}

// ScanClusterWideResources scans all cluster wide resources.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanClusterWideResources() error {
	log.Info().Msg("clusterwide resources scan started")

	policies, skippedNum, err := s.policiesFetcher.GetClusterAdmissionPolicies()
	if err != nil {
		return err
	}

	log.Info().
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", len(policies)).
			Int("policies skipped", skippedNum),
		).Msg("cluster admission policies count")

	// create PolicyReport
	clusterReport := report.NewClusterPolicyReport(constants.DefaultClusterwideReportName)
	clusterReport.Summary.Skip = skippedNum

	// old policy report to be used as cache
	previousClusterReport, err := s.reportStore.GetClusterPolicyReport(constants.DefaultClusterwideReportName)
	if err != nil {
		log.Info().Err(err).Msg("no-prexisting ClusterPolicyReport, will create one at the end of the scan")
	}

	policiesByResource := s.PoliciesByResource(policies)
	for gvr, objectFilters := range policiesByResource {
		isNamespaced, err := s.resourcesFetcher.IsNamespacedResource(gvr)
		if err != nil {
			if apimachineryerrors.IsNotFound(err) {
				log.Warn().
					Str("resource GVK", gvr.String()).
					Msg("API resource not found")
				continue
			}
			return err
		}
		if isNamespaced {
			// continue if resource is namespaced
			continue
		}

		for filter, policies := range objectFilters {
			pager, err := s.resourcesFetcher.GetResources(gvr, "", filter.labelSelector)
			if err != nil {
				return err
			}

			err = pager.EachListItem(context.Background(), metav1.ListOptions{}, func(obj runtime.Object) error {
				resource := obj.(*unstructured.Unstructured)
				auditClusterResource(policies, *resource, &s.httpClient, &clusterReport, &previousClusterReport)

				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if err := s.reportStore.SaveClusterPolicyReport(&clusterReport); err != nil {
		log.Error().Err(err).Msg("error adding PolicyReport to store")
	}

	log.Info().Msg("clusterwide resources scan finished")

	if s.outputScan {
		s.reportLogger.LogClusterPolicyReport(&clusterReport)
	}

	return nil
}

func auditClusterResource(policies []PolicyWithPolicyServer, resource unstructured.Unstructured, httpClient *http.Client, clusterReport, previousClusterReport *report.ClusterPolicyReport) {
	for _, p := range policies {
		url := p.policyServer
		policy := p.policy

		if result := previousClusterReport.GetReusablePolicyReportResult(policy, resource); result != nil {
			// We have a result from the same policy version for the same resource instance.
			// Skip the evaluation
			clusterReport.AddResult(result)
			log.Debug().Dict("skip-evaluation", zerolog.Dict().
				Str("policy", policy.GetName()).
				Str("policyResourceVersion", policy.GetResourceVersion()).
				Str("policyUID", string(policy.GetUID())).
				Str("resource", resource.GetName()).
				Str("resourceResourceVersion", resource.GetResourceVersion()),
			).Msg("Previous result found. Reusing result")
			continue
		}
		admissionRequest := resources.GenerateAdmissionReview(resource)
		auditResponse, responseErr := sendAdmissionReviewToPolicyServer(url, admissionRequest, httpClient)
		if responseErr != nil {
			// log error, will end in ClusterPolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(auditResponse.Response.UID)).
				Bool("allowed", auditResponse.Response.Allowed).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("audit review response")
			result := clusterReport.CreateResult(policy, resource, auditResponse, responseErr)
			clusterReport.AddResult(result)
		}
	}
}

func auditResource(policies []PolicyWithPolicyServer, resource unstructured.Unstructured, httpClient *http.Client, previousNsReport, nsReport *report.PolicyReport) {
	for _, p := range policies {
		url := p.policyServer
		policy := p.policy

		if result := previousNsReport.GetReusablePolicyReportResult(policy, resource); result != nil {
			dump.P("here")
			// We have a result from the same policy version for the same resource instance.
			// Skip the evaluation
			nsReport.AddResult(result)
			log.Debug().Dict("skip-evaluation", zerolog.Dict().
				Str("policy", policy.GetName()).
				Str("policyResourceVersion", policy.GetResourceVersion()).
				Str("policyUID", string(policy.GetUID())).
				Str("resource", resource.GetName()).
				Str("resourceResourceVersion", resource.GetResourceVersion()),
			).Msg("Previous result found. Reusing result")
			continue
		}

		admissionRequest := resources.GenerateAdmissionReview(resource)
		auditResponse, responseErr := sendAdmissionReviewToPolicyServer(url, admissionRequest, httpClient)
		if responseErr != nil {
			// log responseErr, will end in PolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(auditResponse.Response.UID)).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()).
				Bool("allowed", auditResponse.Response.Allowed),
			).
				Msg("audit review response")
			result := nsReport.CreateResult(policy, resource, auditResponse, responseErr)
			nsReport.AddResult(result)
		}
	}
}

func sendAdmissionReviewToPolicyServer(url *url.URL, admissionRequest *admv1.AdmissionReview, httpClient *http.Client) (*admv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), bytes.NewBuffer(payload))
	req.Header.Add("Content-Type", "application/json")

	res, err := httpClient.Do(req)
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

	admissionReview := admv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}

type ObjectFilter struct {
	labelSelector *metav1.LabelSelector
}

type PolicyWithPolicyServer struct {
	policy       policiesv1.Policy
	policyServer *url.URL
}

func (s *Scanner) PoliciesByResource(policies []policiesv1.Policy) map[schema.GroupVersionResource]map[ObjectFilter][]PolicyWithPolicyServer {
	resources := make(map[schema.GroupVersionResource]map[ObjectFilter][]PolicyWithPolicyServer)
	for _, policy := range policies {
		url, err := s.resourcesFetcher.GetPolicyServerURLRunningPolicy(context.Background(), policy)
		if err != nil {
			panic(err)
		}

		for _, rules := range policy.GetRules() {
			for _, resource := range rules.Resources {
				for _, version := range rules.APIVersions {
					for _, group := range rules.APIGroups {
						gvr := schema.GroupVersionResource{
							Group:    group,
							Version:  version,
							Resource: resource,
						}
						filter := ObjectFilter{
							labelSelector: policy.GetObjectSelector(),
						}

						p := PolicyWithPolicyServer{
							policy:       policy,
							policyServer: url,
						}

						if _, ok := resources[gvr]; !ok {
							resources[gvr] = map[ObjectFilter][]PolicyWithPolicyServer{
								filter: {p},
							}
							continue
						}

						if _, ok := resources[gvr][filter]; !ok {
							resources[gvr][filter] = []PolicyWithPolicyServer{p}
						} else {
							resources[gvr][filter] = append(resources[gvr][filter], p)
						}
					}
				}
			}
		}
	}

	return resources
}
