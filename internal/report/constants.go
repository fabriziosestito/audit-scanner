package report

const (
	PrefixNameClusterPolicyReport = "polr-"
	PrefixNamePolicyReport        = "polr-ns-"
	PolicyReportSource            = "kubewarden"
	PropertyPolicyResourceVersion = "policy-resource-version"
	PropertyPolicyUID             = "policy-uid"
)

const (
	// Status specifies state of a policy result
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusWarn  = "warn"
	StatusError = "error"
	StatusSkip  = "skip"
)

const (
	// Severity specifies severity of a policy result
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

const (
	// Category specifies the category of a policy result
	TypeMutating     = "mutating"
	TypeValidating   = "validating"
	TypeContextAware = "context-aware"
	ValueTypeTrue    = "true"
)

const (
	LabelAppManagedBy = "app.kubernetes.io/managed-by"
	LabelApp          = "kubewarden"
)
