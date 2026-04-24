package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

const (
	defaultCheckTimeoutSeconds  = 300
	schemaVersionV2             = "v2"
	sourceCloudCustodian        = "cloud-custodian"
	defaultRemotePolicyTimeout  = 30 * time.Second
	defaultMaxRemotePolicyBytes = 1 << 20 // 1 MiB
	evidenceBatchSize           = 100
)

var lookPath = exec.LookPath

// PluginConfig receives string-only config from the agent gRPC interface.
type PluginConfig struct {
	PoliciesYAML           string `mapstructure:"policies_yaml"`
	PoliciesPath           string `mapstructure:"policies_path"`
	CustodianBinary        string `mapstructure:"custodian_binary"`
	PolicyLabels           string `mapstructure:"policy_labels"`
	ResourceIdentityFields string `mapstructure:"resource_identity_fields"`
	CheckTimeoutSeconds    string `mapstructure:"check_timeout_seconds"`
	DebugDumpPayloads      string `mapstructure:"debug_dump_payloads"`
	DebugPayloadOutputDir  string `mapstructure:"debug_payload_output_dir"`
}

// ParsedConfig stores normalized and validated values for runtime use.
type ParsedConfig struct {
	PoliciesYAML           string
	PoliciesPath           string
	CustodianBinary        string
	PolicyLabels           map[string]string
	ResourceIdentityFields map[string][]string
	CheckTimeout           time.Duration
	DebugDumpPayloads      bool
	DebugPayloadOutputDir  string
}

func (c *PluginConfig) Parse() (*ParsedConfig, error) {
	inlineYAML := strings.TrimSpace(c.PoliciesYAML)
	policiesPath := strings.TrimSpace(c.PoliciesPath)

	if inlineYAML == "" && policiesPath == "" {
		return nil, errors.New("either policies_yaml or policies_path is required")
	}

	policyLabels := map[string]string{}
	if strings.TrimSpace(c.PolicyLabels) != "" {
		if err := json.Unmarshal([]byte(c.PolicyLabels), &policyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy_labels: %w", err)
		}
	}

	resourceIdentityFields := map[string][]string{}
	if strings.TrimSpace(c.ResourceIdentityFields) != "" {
		if err := json.Unmarshal([]byte(c.ResourceIdentityFields), &resourceIdentityFields); err != nil {
			return nil, fmt.Errorf("could not parse resource_identity_fields: %w", err)
		}
		for resourceType, fields := range resourceIdentityFields {
			if strings.TrimSpace(resourceType) == "" {
				return nil, errors.New("resource_identity_fields cannot contain an empty resource type")
			}
			normalizedFields := make([]string, 0, len(fields))
			for _, field := range fields {
				field = strings.TrimSpace(field)
				if field != "" {
					normalizedFields = append(normalizedFields, field)
				}
			}
			if len(normalizedFields) == 0 {
				return nil, fmt.Errorf("resource_identity_fields for %q must include at least one field", resourceType)
			}
			resourceIdentityFields[resourceType] = normalizedFields
		}
	}

	checkTimeoutSeconds := defaultCheckTimeoutSeconds
	if strings.TrimSpace(c.CheckTimeoutSeconds) != "" {
		parsedTimeout, err := strconv.Atoi(c.CheckTimeoutSeconds)
		if err != nil {
			return nil, fmt.Errorf("check_timeout_seconds must be a positive integer: %w", err)
		}
		if parsedTimeout <= 0 {
			return nil, errors.New("check_timeout_seconds must be greater than 0")
		}
		checkTimeoutSeconds = parsedTimeout
	}

	binary := strings.TrimSpace(c.CustodianBinary)
	if binary == "" {
		binary = "custodian"
	}

	resolvedBinary, err := lookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("could not resolve custodian binary %q: %w", binary, err)
	}

	debugDumpPayloads := false
	if strings.TrimSpace(c.DebugDumpPayloads) != "" {
		parsedDebug, err := strconv.ParseBool(c.DebugDumpPayloads)
		if err != nil {
			return nil, fmt.Errorf("debug_dump_payloads must be a boolean value: %w", err)
		}
		debugDumpPayloads = parsedDebug
	}

	debugPayloadOutputDir := strings.TrimSpace(c.DebugPayloadOutputDir)
	if debugPayloadOutputDir != "" {
		debugDumpPayloads = true
	}
	if debugDumpPayloads && debugPayloadOutputDir == "" {
		debugPayloadOutputDir = "debug-standardized-payloads"
	}

	return &ParsedConfig{
		PoliciesYAML:           inlineYAML,
		PoliciesPath:           policiesPath,
		CustodianBinary:        resolvedBinary,
		PolicyLabels:           policyLabels,
		ResourceIdentityFields: resourceIdentityFields,
		CheckTimeout:           time.Duration(checkTimeoutSeconds) * time.Second,
		DebugDumpPayloads:      debugDumpPayloads,
		DebugPayloadOutputDir:  debugPayloadOutputDir,
	}, nil
}

// CustodianCheck represents a single Cloud Custodian policy entry used as one check iteration.
type CustodianCheck struct {
	Index       int
	Name        string
	Resource    string
	Provider    string
	RawPolicy   map[string]interface{}
	ParseErrors []string
}

// CustodianExecutionRequest contains execution-time settings for one check run.
type CustodianExecutionRequest struct {
	BinaryPath string
	Check      CustodianCheck
	Timeout    time.Duration
	OutputDir  string
}

// CustodianExecutionResult captures runtime output and artifacts from one check run.
type CustodianExecutionResult struct {
	StartedAt     time.Time
	EndedAt       time.Time
	ExitCode      int
	Stdout        string
	Stderr        string
	Error         string
	Errors        []string
	Err           error
	Resources     []interface{}
	ArtifactPath  string
	ResourcesPath string
}

// CustodianExecutor runs one Cloud Custodian check and captures execution artifacts.
type CustodianExecutor interface {
	Execute(ctx context.Context, req CustodianExecutionRequest) CustodianExecutionResult
}

// CommandCustodianExecutor executes the custodian CLI.
type CommandCustodianExecutor struct {
	Logger hclog.Logger
}

func (e *CommandCustodianExecutor) Execute(ctx context.Context, req CustodianExecutionRequest) CustodianExecutionResult {
	e.Logger.Debug("Starting cloud custodian execution",
		"check_name", req.Check.Name,
		"check_index", req.Check.Index,
		"resource", req.Check.Resource,
		"provider", req.Check.Provider,
		"binary", req.BinaryPath,
		"timeout", req.Timeout.String(),
		"output_dir", req.OutputDir,
	)
	result := CustodianExecutionResult{
		StartedAt:    time.Now().UTC(),
		ExitCode:     -1,
		Resources:    []interface{}{},
		Errors:       []string{},
		ArtifactPath: req.OutputDir,
	}

	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		result.Err = fmt.Errorf("failed to create output directory: %w", err)
		result.Error = result.Err.Error()
		result.Errors = []string{result.Error}
		e.Logger.Error("Failed creating output directory for check", "check_name", req.Check.Name, "error", result.Error)
		result.EndedAt = time.Now().UTC()
		return result
	}
	e.Logger.Trace("Created output directory for check", "check_name", req.Check.Name, "output_dir", req.OutputDir)

	policyDocument := map[string]interface{}{
		"policies": []map[string]interface{}{req.Check.RawPolicy},
	}
	policyContent, err := yaml.Marshal(policyDocument)
	if err != nil {
		result.Err = fmt.Errorf("failed to marshal single policy document: %w", err)
		result.Error = result.Err.Error()
		result.Errors = []string{result.Error}
		e.Logger.Error("Failed marshaling single policy yaml for check", "check_name", req.Check.Name, "error", result.Error)
		result.EndedAt = time.Now().UTC()
		return result
	}

	policyPath := filepath.Join(req.OutputDir, "policy.yaml")
	if err := os.WriteFile(policyPath, policyContent, 0o600); err != nil {
		result.Err = fmt.Errorf("failed to write single policy file: %w", err)
		result.Error = result.Err.Error()
		result.Errors = []string{result.Error}
		e.Logger.Error("Failed writing single policy file for check", "check_name", req.Check.Name, "policy_path", policyPath, "error", result.Error)
		result.EndedAt = time.Now().UTC()
		return result
	}
	e.Logger.Trace("Wrote single policy file", "check_name", req.Check.Name, "policy_path", policyPath)

	runCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	args := []string{"run", "--dryrun", "-s", req.OutputDir, policyPath}
	if strings.EqualFold(req.Check.Provider, "aws") {
		// Ensure AWS policies evaluate across all regions by default.
		args = append(args, "--region", "all")
	}
	cmd := exec.CommandContext(runCtx, req.BinaryPath, args...)
	e.Logger.Debug("Executing custodian command",
		"check_name", req.Check.Name,
		"command", req.BinaryPath,
		"args", args,
	)
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	e.Logger.Debug("Custodian command finished",
		"check_name", req.Check.Name,
		"exit_code", result.ExitCode,
		"stdout_len", len(result.Stdout),
		"stderr_len", len(result.Stderr),
	)

	resourcesPath, resources, resourcesErr := readResourcesArtifact(req.OutputDir)
	result.ResourcesPath = resourcesPath
	if resources != nil {
		result.Resources = resources
	}

	if err != nil {
		result.Err = fmt.Errorf("custodian execution failed: %w", err)
		result.Errors = append(result.Errors, result.Err.Error())
		if result.Stderr != "" {
			result.Errors = append(result.Errors, result.Stderr)
		}
	}
	if runErr := runCtx.Err(); runErr != nil {
		// Avoid duplicating context timeout/cancel errors when cmd.Run already
		// returned an error that wraps the same context failure.
		if err == nil || !errors.Is(err, runErr) {
			result.Err = errors.Join(result.Err, runErr)
			result.Errors = append(result.Errors, runErr.Error())
		}
	}
	if resourcesErr != nil {
		result.Err = errors.Join(result.Err, resourcesErr)
		result.Errors = append(result.Errors, resourcesErr.Error())
	}

	if result.Err != nil {
		result.Error = strings.Join(result.Errors, "; ")
		e.Logger.Warn("Custodian execution completed with errors",
			"check_name", req.Check.Name,
			"error_count", len(result.Errors),
			"errors", result.Errors,
		)
	} else {
		e.Logger.Debug("Custodian execution completed successfully",
			"check_name", req.Check.Name,
			"resource_count", len(result.Resources),
			"resources_path", result.ResourcesPath,
		)
	}

	result.EndedAt = time.Now().UTC()
	return result
}

func readResourcesArtifact(outputDir string) (string, []interface{}, error) {
	resourcesPath, err := findResourcesJSON(outputDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", []interface{}{}, nil
		}
		return "", nil, fmt.Errorf("failed to locate resources.json: %w", err)
	}

	content, err := os.ReadFile(resourcesPath)
	if err != nil {
		return resourcesPath, nil, fmt.Errorf("failed to read resources.json: %w", err)
	}

	if len(content) == 0 {
		return resourcesPath, []interface{}{}, nil
	}

	resources := make([]interface{}, 0)
	if err := json.Unmarshal(content, &resources); err != nil {
		return resourcesPath, nil, fmt.Errorf("failed to parse resources.json: %w", err)
	}

	return resourcesPath, resources, nil
}

func findResourcesJSON(outputDir string) (string, error) {
	found := ""
	err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == "resources.json" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})

	if err != nil && !errors.Is(err, filepath.SkipAll) {
		return "", err
	}
	if found == "" {
		return "", fs.ErrNotExist
	}
	return found, nil
}

type StandardizedCheckInfo struct {
	Name     string                 `json:"name"`
	Resource string                 `json:"resource"`
	Provider string                 `json:"provider"`
	Index    int                    `json:"index"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type StandardizedExecution struct {
	Status     string   `json:"status"`
	DryRun     bool     `json:"dry_run"`
	ExitCode   int      `json:"exit_code"`
	StartedAt  string   `json:"started_at"`
	EndedAt    string   `json:"ended_at"`
	DurationMS int64    `json:"duration_ms"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	Error      string   `json:"error,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// StandardizedResourcePayload is the per-resource OPA input contract.
type StandardizedResourcePayload struct {
	SchemaVersion string                   `json:"schema_version"`
	Source        string                   `json:"source"`
	Check         StandardizedCheckInfo    `json:"check"`
	Resource      StandardizedResourceInfo `json:"resource"`
	Assessment    StandardizedAssessment   `json:"assessment"`
	Execution     StandardizedExecution    `json:"execution"`
	RawPolicy     map[string]interface{}   `json:"raw_policy"`
}

type StandardizedResourceInfo struct {
	ID             string            `json:"id"`
	Type           string            `json:"type"`
	Provider       string            `json:"provider"`
	AccountID      string            `json:"account_id,omitempty"`
	Region         string            `json:"region,omitempty"`
	IdentityFields map[string]string `json:"identity_fields,omitempty"`
	Data           interface{}       `json:"data"`
}

type StandardizedAssessment struct {
	Status               string `json:"status"`
	Matched              bool   `json:"matched"`
	InventoryStatus      string `json:"inventory_status"`
	MatchedResourceCount int    `json:"matched_resource_count"`
	ArtifactPath         string `json:"artifact_path,omitempty"`
	ResourcesPath        string `json:"resources_path,omitempty"`
}

type ResourceRecord struct {
	ID             string
	Type           string
	Provider       string
	AccountID      string
	Region         string
	IdentityFields map[string]string
	Data           interface{}
}

type InventoryBaseline struct {
	Execution    CustodianExecutionResult
	Resources    map[string]ResourceRecord
	ResourceType string
	Provider     string
	Err          error
}

func buildResourcePayload(
	check CustodianCheck,
	execution CustodianExecutionResult,
	record ResourceRecord,
	assessment StandardizedAssessment,
) *StandardizedResourcePayload {
	metadata := buildCheckMetadata(check)
	return &StandardizedResourcePayload{
		SchemaVersion: schemaVersionV2,
		Source:        sourceCloudCustodian,
		Check: StandardizedCheckInfo{
			Name:     check.Name,
			Resource: check.Resource,
			Provider: check.Provider,
			Index:    check.Index,
			Metadata: metadata,
		},
		Resource: StandardizedResourceInfo{
			ID:             record.ID,
			Type:           record.Type,
			Provider:       record.Provider,
			AccountID:      record.AccountID,
			Region:         record.Region,
			IdentityFields: record.IdentityFields,
			Data:           record.Data,
		},
		Assessment: assessment,
		Execution:  buildExecutionInfo(execution),
		RawPolicy:  check.RawPolicy,
	}
}

func buildCheckMetadata(check CustodianCheck) map[string]interface{} {
	var metadata map[string]interface{}
	for k, v := range check.RawPolicy {
		if k == "name" || k == "resource" {
			continue
		}
		if metadata == nil {
			metadata = map[string]interface{}{}
		}
		metadata[k] = v
	}
	return metadata
}

func buildExecutionInfo(execution CustodianExecutionResult) StandardizedExecution {
	status := "success"
	if execution.Error != "" {
		status = "error"
	}

	durationMS := int64(execution.EndedAt.Sub(execution.StartedAt) / time.Millisecond)
	if durationMS < 0 {
		durationMS = 0
	}

	var executionErrors []string
	if len(execution.Errors) > 0 {
		executionErrors = append([]string{}, execution.Errors...)
	}

	return StandardizedExecution{
		Status:     status,
		DryRun:     true,
		ExitCode:   execution.ExitCode,
		StartedAt:  execution.StartedAt.UTC().Format(time.RFC3339Nano),
		EndedAt:    execution.EndedAt.UTC().Format(time.RFC3339Nano),
		DurationMS: durationMS,
		Stdout:     execution.Stdout,
		Stderr:     execution.Stderr,
		Error:      execution.Error,
		Errors:     executionErrors,
	}
}

func resourceRecordKey(record ResourceRecord) string {
	return fmt.Sprintf("%s#%s", record.ID, hashResource(record.Data))
}

func disambiguateResourceRecords(records []ResourceRecord) (map[string]ResourceRecord, int) {
	grouped := map[string][]ResourceRecord{}
	for _, record := range records {
		grouped[record.ID] = append(grouped[record.ID], record)
	}

	result := make(map[string]ResourceRecord, len(records))
	collisionCount := 0
	for _, group := range grouped {
		if len(group) > 1 {
			collisionCount += len(group) - 1
		}
		for _, record := range group {
			disambiguated := record
			if disambiguated.IdentityFields == nil {
				disambiguated.IdentityFields = map[string]string{}
			}
			hash := hashResource(disambiguated.Data)
			disambiguated.IdentityFields["resource_hash"] = hash
			result[resourceRecordKey(disambiguated)] = disambiguated
		}
	}

	return result, collisionCount
}

func (p *CloudCustodianPlugin) buildResourceRecord(resourceType string, resource interface{}) ResourceRecord {
	provider := extractProvider(resourceType)
	identityFields := map[string]string{}
	fieldPaths := p.identityFieldPaths(resourceType)

	resourceID := ""
	for _, fieldPath := range fieldPaths {
		value, ok := resourceStringAtPath(resource, fieldPath)
		if !ok || value == "" {
			continue
		}
		identityFields[fieldPath] = value
		if resourceID == "" {
			resourceID = value
		}
	}
	if resourceID == "" {
		resourceID = hashResource(resource)
		identityFields["resource_hash"] = resourceID
	}
	resourceID = canonicalResourceID(resourceType, provider, resourceID)
	if strings.HasPrefix(resourceID, "arn:") {
		identityFields["arn"] = resourceID
	}

	record := ResourceRecord{
		ID:             resourceID,
		Type:           resourceType,
		Provider:       provider,
		IdentityFields: identityFields,
		Data:           resource,
	}
	if accountID, ok := firstResourceString(resource, []string{"AccountId", "AccountID", "account_id", "accountId", "OwnerId", "OwnerID", "owner_id", "c7n:account-id"}); ok {
		record.AccountID = accountID
	}
	if region, ok := firstResourceString(resource, []string{"Region", "region", "AwsRegion", "aws_region", "awsRegion", "c7n:region"}); ok {
		record.Region = region
	}
	return record
}

func canonicalResourceID(resourceType string, provider string, resourceID string) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" || strings.HasPrefix(resourceID, "arn:") {
		return resourceID
	}
	if provider == "aws" && resourceType == "aws.hostedzone" {
		hostedZoneID := strings.TrimPrefix(resourceID, "/")
		if strings.HasPrefix(hostedZoneID, "hostedzone/") {
			return "arn:aws:route53:::" + hostedZoneID
		}
		if strings.HasPrefix(hostedZoneID, "Z") {
			return "arn:aws:route53:::hostedzone/" + hostedZoneID
		}
	}
	return resourceID
}

func (p *CloudCustodianPlugin) identityFieldPaths(resourceType string) []string {
	paths := make([]string, 0)
	if p.parsedConfig != nil {
		if configured, ok := p.parsedConfig.ResourceIdentityFields[resourceType]; ok {
			paths = append(paths, configured...)
		}
	}
	paths = append(paths,
		"Arn",
		"ARN",
		"arn",
		"Id",
		"ID",
		"id",
		"InstanceId",
		"instance_id",
		"InstanceID",
		"ResourceId",
		"resource_id",
		"Name",
		"name",
	)
	return compactUniqueStrings(paths)
}

func compactUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func firstResourceString(resource interface{}, fieldPaths []string) (string, bool) {
	for _, fieldPath := range fieldPaths {
		value, ok := resourceStringAtPath(resource, fieldPath)
		if ok && value != "" {
			return value, true
		}
	}
	return "", false
}

func resourceStringAtPath(resource interface{}, fieldPath string) (string, bool) {
	current := resource
	for _, part := range strings.Split(fieldPath, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", false
		}
		switch typed := current.(type) {
		case map[string]interface{}:
			value, ok := typed[part]
			if !ok {
				return "", false
			}
			current = value
		case map[interface{}]interface{}:
			value, ok := typed[part]
			if !ok {
				return "", false
			}
			current = value
		default:
			return "", false
		}
	}

	switch value := current.(type) {
	case string:
		return strings.TrimSpace(value), strings.TrimSpace(value) != ""
	case json.Number:
		return value.String(), value.String() != ""
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(value), 'f', -1, 32), true
	case int:
		return strconv.Itoa(value), true
	case int64:
		return strconv.FormatInt(value, 10), true
	case bool:
		return strconv.FormatBool(value), true
	default:
		return "", false
	}
}

func hashResource(resource interface{}) string {
	content, err := json.Marshal(resource)
	if err != nil {
		content = []byte(fmt.Sprintf("%#v", resource))
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func buildInventoryCheck(resourceType string) CustodianCheck {
	provider := extractProvider(resourceType)
	name := fmt.Sprintf("inventory-%s", sanitizeIdentifier(resourceType))
	return CustodianCheck{
		Index:    -1,
		Name:     name,
		Resource: resourceType,
		Provider: provider,
		RawPolicy: map[string]interface{}{
			"name":     name,
			"resource": resourceType,
		},
	}
}

func parseCustodianChecks(policyYAML []byte) ([]CustodianCheck, error) {
	decoded := map[string]interface{}{}
	if err := yaml.Unmarshal(policyYAML, &decoded); err != nil {
		return nil, fmt.Errorf("failed to parse cloud custodian policies yaml: %w", err)
	}

	rawPolicies, ok := decoded["policies"]
	if !ok {
		return nil, errors.New("policy document must contain top-level policies array")
	}

	policies, ok := rawPolicies.([]interface{})
	if !ok {
		return nil, errors.New("top-level policies must be an array")
	}
	if len(policies) == 0 {
		return nil, errors.New("top-level policies array must not be empty")
	}

	checks := make([]CustodianCheck, 0, len(policies))
	for idx, raw := range policies {
		normalized := normalizeYAMLValue(raw)
		policyMap, mapOK := normalized.(map[string]interface{})
		if !mapOK {
			checks = append(checks, CustodianCheck{
				Index:       idx,
				Name:        fmt.Sprintf("policy-%d", idx+1),
				Resource:    "unknown",
				Provider:    "unknown",
				RawPolicy:   map[string]interface{}{"value": normalized},
				ParseErrors: []string{fmt.Sprintf("policy entry at index %d is not an object", idx)},
			})
			continue
		}

		name := strings.TrimSpace(asString(policyMap["name"]))
		resource := strings.TrimSpace(asString(policyMap["resource"]))
		parseIssues := make([]string, 0)
		if name == "" {
			name = fmt.Sprintf("policy-%d", idx+1)
			parseIssues = append(parseIssues, fmt.Sprintf("policy entry at index %d missing required name", idx))
		}
		if resource == "" {
			resource = "unknown"
			parseIssues = append(parseIssues, fmt.Sprintf("policy %q missing required resource", name))
		}

		checks = append(checks, CustodianCheck{
			Index:       idx,
			Name:        name,
			Resource:    resource,
			Provider:    extractProvider(resource),
			RawPolicy:   policyMap,
			ParseErrors: parseIssues,
		})
	}

	return checks, nil
}

func normalizeYAMLValue(in interface{}) interface{} {
	switch value := in.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(value))
		for k, v := range value {
			out[k] = normalizeYAMLValue(v)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(value))
		for k, v := range value {
			out[fmt.Sprint(k)] = normalizeYAMLValue(v)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(value))
		for i, v := range value {
			out[i] = normalizeYAMLValue(v)
		}
		return out
	default:
		return value
	}
}

func asString(value interface{}) string {
	stringValue, ok := value.(string)
	if !ok {
		return ""
	}
	return stringValue
}

func extractProvider(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "unknown"
	}

	parts := strings.SplitN(resource, ".", 2)
	if len(parts) < 2 {
		return "unknown"
	}
	provider := strings.TrimSpace(parts[0])
	if provider == "" {
		return "unknown"
	}
	return provider
}

func resolvePoliciesYAML(ctx context.Context, inlineYAML string, policiesPath string) ([]byte, error) {
	if strings.TrimSpace(inlineYAML) != "" {
		return []byte(inlineYAML), nil
	}

	pathValue := strings.TrimSpace(policiesPath)
	if pathValue == "" {
		return nil, errors.New("policies path is required when policies_yaml is empty")
	}

	// Treat values that do not look like URLs as local filesystem paths.
	// This handles Windows paths like `C:\policies.yaml` correctly.
	if !strings.Contains(pathValue, "://") {
		content, err := os.ReadFile(pathValue)
		if err != nil {
			return nil, fmt.Errorf("failed to read local policies file: %w", err)
		}
		return content, nil
	}

	parsedURL, err := url.Parse(pathValue)
	if err != nil {
		return nil, fmt.Errorf("invalid policies_path: %w", err)
	}

	switch parsedURL.Scheme {
	case "":
		content, err := os.ReadFile(pathValue)
		if err != nil {
			return nil, fmt.Errorf("failed to read local policies file: %w", err)
		}
		return content, nil
	case "file":
		if parsedURL.Path == "" {
			return nil, errors.New("file:// policies_path must include a file path")
		}
		content, err := os.ReadFile(parsedURL.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file:// policies file: %w", err)
		}
		return content, nil
	case "http", "https":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pathValue, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request for policies_path: %w", err)
		}
		httpClient := &http.Client{Timeout: defaultRemotePolicyTimeout}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch policies_path: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("unexpected status code %d while fetching policies_path", resp.StatusCode)
		}
		if resp.ContentLength > defaultMaxRemotePolicyBytes {
			return nil, fmt.Errorf("policies_path response too large: content-length=%d exceeds max=%d bytes", resp.ContentLength, defaultMaxRemotePolicyBytes)
		}

		content, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxRemotePolicyBytes+1))
		if err != nil {
			return nil, fmt.Errorf("failed to read policies_path response body: %w", err)
		}
		if len(content) > defaultMaxRemotePolicyBytes {
			return nil, fmt.Errorf("policies_path response too large: size=%d exceeds max=%d bytes", len(content), defaultMaxRemotePolicyBytes)
		}
		return content, nil
	default:
		return nil, fmt.Errorf("unsupported policies_path scheme: %s", parsedURL.Scheme)
	}
}

// PolicyEvaluator wraps OPA policy execution so eval loop behavior can be tested with mocks.
type PolicyEvaluator interface {
	Generate(
		ctx context.Context,
		policyPath string,
		labels map[string]string,
		subjects []*proto.Subject,
		components []*proto.Component,
		inventory []*proto.InventoryItem,
		actors []*proto.OriginActor,
		activities []*proto.Activity,
		data interface{},
	) ([]*proto.Evidence, error)
}

type DefaultPolicyEvaluator struct {
	Logger hclog.Logger
}

func (e *DefaultPolicyEvaluator) Generate(
	ctx context.Context,
	policyPath string,
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventory []*proto.InventoryItem,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
	data interface{},
) ([]*proto.Evidence, error) {
	e.Logger.Debug("Evaluating OPA policy against check payload", "policy_path", policyPath, "labels", labels)
	processor := policyManager.NewPolicyProcessor(
		e.Logger,
		labels,
		subjects,
		components,
		inventory,
		actors,
		activities,
	)
	evidence, err := processor.GenerateResults(ctx, policyPath, data)
	if err != nil {
		e.Logger.Warn("OPA policy evaluation failed", "policy_path", policyPath, "error", err)
		return evidence, err
	}
	e.Logger.Debug("OPA policy evaluation succeeded", "policy_path", policyPath, "evidence_count", len(evidence))
	return evidence, nil
}

type CloudCustodianPlugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig
	checks       []CustodianCheck

	executor  CustodianExecutor
	evaluator PolicyEvaluator
}

func (p *CloudCustodianPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.Logger.Debug("Received raw plugin configuration", "config_keys", sortedKeys(req.Config))

	config := &PluginConfig{}
	if err := mapstructure.Decode(req.Config, config); err != nil {
		p.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	parsed, err := config.Parse()
	if err != nil {
		p.Logger.Error("Error parsing config", "error", err)
		return nil, err
	}
	p.Logger.Debug("Parsed plugin configuration",
		"has_inline_policies_yaml", strings.TrimSpace(parsed.PoliciesYAML) != "",
		"policies_path", parsed.PoliciesPath,
		"custodian_binary", parsed.CustodianBinary,
		"check_timeout", parsed.CheckTimeout.String(),
		"policy_labels", parsed.PolicyLabels,
		"debug_dump_payloads", parsed.DebugDumpPayloads,
		"debug_payload_output_dir", parsed.DebugPayloadOutputDir,
	)

	resolvedPolicies, err := resolvePoliciesYAML(context.Background(), parsed.PoliciesYAML, parsed.PoliciesPath)
	if err != nil {
		p.Logger.Error("Error loading cloud custodian policies", "error", err)
		return nil, err
	}
	p.Logger.Debug("Resolved cloud custodian policy source", "policy_yaml_bytes", len(resolvedPolicies))

	checks, err := parseCustodianChecks(resolvedPolicies)
	if err != nil {
		p.Logger.Error("Error parsing cloud custodian policies", "error", err)
		return nil, err
	}
	parseErrorChecks := 0
	for _, check := range checks {
		if len(check.ParseErrors) > 0 {
			parseErrorChecks++
			p.Logger.Debug("Parsed check with non-fatal parse issues", "check_name", check.Name, "index", check.Index, "parse_errors", check.ParseErrors)
		}
	}

	parsed.PoliciesYAML = string(resolvedPolicies)
	p.config = config
	p.parsedConfig = parsed
	p.checks = checks

	if parsed.DebugDumpPayloads {
		if err := os.MkdirAll(parsed.DebugPayloadOutputDir, 0o755); err != nil {
			p.Logger.Error("Failed creating debug payload output directory", "debug_payload_output_dir", parsed.DebugPayloadOutputDir, "error", err)
			return nil, fmt.Errorf("failed creating debug payload output directory %q: %w", parsed.DebugPayloadOutputDir, err)
		}
		p.Logger.Debug("Debug payload dumping enabled", "debug_payload_output_dir", parsed.DebugPayloadOutputDir)
	}

	if p.executor == nil {
		p.executor = &CommandCustodianExecutor{Logger: p.Logger.Named("custodian-executor")}
	}
	if p.evaluator == nil {
		p.evaluator = &DefaultPolicyEvaluator{Logger: p.Logger.Named("policy-evaluator")}
	}

	p.Logger.Info("Cloud Custodian Plugin configured", "checks", len(checks), "checks_with_parse_errors", parseErrorChecks)
	return &proto.ConfigureResponse{}, nil
}

func (p *CloudCustodianPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	p.Logger.Debug("Cloud Custodian Plugin Init called",
		"configured", p.parsedConfig != nil,
		"policy_paths", req.GetPolicyPaths(),
		"policy_paths_count", len(req.GetPolicyPaths()),
		"checks_count", len(p.checks),
	)
	if p.parsedConfig == nil {
		p.Logger.Error("Cloud Custodian Plugin Init failed because plugin is not configured")
		return nil, errors.New("plugin not configured")
	}

	resourceTypes := p.uniqueResourceTypes()
	subjectTemplates := p.buildSubjectTemplates(resourceTypes)
	templateNames := make([]string, 0, len(subjectTemplates))
	for _, subjectTemplate := range subjectTemplates {
		templateNames = append(templateNames, subjectTemplate.GetName())
	}
	p.Logger.Debug("Cloud Custodian Plugin Init prepared subject templates",
		"resource_types", resourceTypes,
		"subject_template_count", len(subjectTemplates),
		"subject_template_names", templateNames,
	)

	p.Logger.Debug("Cloud Custodian Plugin Init delegating subject and risk template upsert",
		"policy_paths", req.GetPolicyPaths(),
		"subject_template_count", len(subjectTemplates),
	)
	resp, err := runner.InitWithSubjectsAndRisksFromPolicies(
		context.Background(),
		p.Logger,
		req,
		apiHelper,
		subjectTemplates,
	)
	if err != nil {
		p.Logger.Error("Cloud Custodian Plugin Init failed while upserting subject or risk templates", "error", err)
		return resp, err
	}
	p.Logger.Debug("Cloud Custodian Plugin Init completed",
		"subject_template_count", len(subjectTemplates),
		"policy_paths_count", len(req.GetPolicyPaths()),
	)
	return resp, nil
}

func (p *CloudCustodianPlugin) buildSubjectTemplates(resourceTypes []string) []*proto.SubjectTemplate {
	templates := make([]*proto.SubjectTemplate, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		provider := extractProvider(resourceType)
		templates = append(templates, &proto.SubjectTemplate{
			Name: fmt.Sprintf("cloud-custodian-%s", sanitizeIdentifier(resourceType)),
			// These templates represent cloud resources collected during evaluation.
			Type:                proto.SubjectType_SUBJECT_TYPE_RESOURCE,
			TitleTemplate:       "Cloud Resource: {{ .resource_type }} {{ .resource_id }}",
			DescriptionTemplate: "Cloud Custodian resource {{ .resource_id }} of type {{ .resource_type }} from provider {{ .provider }}",
			PurposeTemplate:     "Represents a cloud resource collected by Cloud Custodian for compliance evaluation.",
			IdentityLabelKeys:   []string{"provider", "resource_type", "resource_id"},
			Props: []*proto.SubjectProp{
				{Name: "provider", Value: provider},
				{Name: "resource_type", Value: resourceType},
			},
			SelectorLabels: []*proto.SubjectLabelSelector{
				{Key: "source", Value: sourceCloudCustodian},
				{Key: "resource_type", Value: resourceType},
			},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "provider", Description: "Cloud provider derived from the Cloud Custodian resource type."},
				{Key: "resource_type", Description: "Cloud Custodian resource type such as aws.ec2 or aws.s3."},
				{Key: "resource_id", Description: "Stable resource identifier extracted from the resource data."},
				{Key: "account_id", Description: "Cloud account identifier when available in the resource data."},
				{Key: "region", Description: "Cloud region when available in the resource data."},
			},
		})
	}
	return templates
}

func (p *CloudCustodianPlugin) uniqueResourceTypes() []string {
	seen := map[string]bool{}
	resourceTypes := make([]string, 0)
	for _, check := range p.checks {
		resourceType := strings.TrimSpace(check.Resource)
		if resourceType == "" || resourceType == "unknown" || len(check.ParseErrors) > 0 || seen[resourceType] {
			continue
		}
		seen[resourceType] = true
		resourceTypes = append(resourceTypes, resourceType)
	}
	slices.Sort(resourceTypes)
	return resourceTypes
}

func (p *CloudCustodianPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	if p.parsedConfig == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("plugin not configured")
	}
	if len(p.checks) == 0 {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("no cloud custodian checks configured")
	}
	if len(req.GetPolicyPaths()) == 0 {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("no policy paths provided")
	}

	executionRoot, err := os.MkdirTemp("", "ccf-cloud-custodian-*")
	if err != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("failed to create execution workspace: %w", err)
	}
	defer os.RemoveAll(executionRoot)
	p.Logger.Debug("Created temporary execution root", "execution_root", executionRoot)

	pendingEvidences := make([]*proto.Evidence, 0, evidenceBatchSize)
	totalEvidenceCount := 0
	var accumulatedErrors error
	successfulPolicyRuns := 0
	hadCheckExecutionFailures := false

	baselines := p.collectInventoryBaselines(ctx, executionRoot)
	for _, check := range p.checks {
		p.Logger.Debug("Processing check", "check_name", check.Name, "check_index", check.Index, "resource", check.Resource, "provider", check.Provider)
		if len(check.ParseErrors) > 0 {
			p.Logger.Warn("Skipping custodian execution due to check parse issues", "check_name", check.Name, "parse_errors", check.ParseErrors)
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("check %s has parse errors: %s", check.Name, strings.Join(check.ParseErrors, "; ")))
			continue
		}

		baseline := baselines[check.Resource]
		if baseline == nil || baseline.Err != nil {
			err := fmt.Errorf("inventory baseline unavailable for resource type %s", check.Resource)
			if baseline != nil && baseline.Err != nil {
				err = fmt.Errorf("%w: %v", err, baseline.Err)
			}
			p.Logger.Error("Skipping check due to unavailable inventory baseline", "check_name", check.Name, "resource", check.Resource, "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		checkDir := filepath.Join(executionRoot, fmt.Sprintf("%03d-%s", check.Index+1, sanitizeIdentifier(check.Name)))
		execution := p.executor.Execute(ctx, CustodianExecutionRequest{
			BinaryPath: p.parsedConfig.CustodianBinary,
			Check:      check,
			Timeout:    p.parsedConfig.CheckTimeout,
			OutputDir:  checkDir,
		})
		if execution.Err != nil || execution.Error != "" {
			err := formatExecutionFailure(check.Name, execution)
			p.Logger.Error("Skipping resource evaluation due to check execution error", "check_name", check.Name, "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			hadCheckExecutionFailures = true
			continue
		}

		payloads := p.buildResourcePayloadsForCheck(check, execution, baseline)
		payloadStats := summarizePayloadAssessments(payloads)
		p.Logger.Debug("Built standardized resource payloads",
			"check_name", check.Name,
			"payload_count", len(payloads),
			"matched_resource_count", len(execution.Resources),
			"baseline_resource_count", len(baseline.Resources),
			"compliant_resource_count", payloadStats.Compliant,
			"non_compliant_resource_count", payloadStats.NonCompliant,
			"missing_from_baseline_count", payloadStats.MissingFromBaseline,
		)
		if len(baseline.Resources) == 0 && len(execution.Resources) > 0 {
			p.Logger.Warn("No compliant resource payloads can be generated because inventory baseline is empty while policy returned matched resources",
				"check_name", check.Name,
				"resource", check.Resource,
				"matched_resource_count", len(execution.Resources),
				"resources_path", execution.ResourcesPath,
			)
		}
		if p.parsedConfig.DebugDumpPayloads {
			for _, payload := range payloads {
				if err := p.dumpStandardizedPayload(payload); err != nil {
					p.Logger.Warn("Failed writing debug standardized payload", "check_name", payload.Check.Name, "resource_id", payload.Resource.ID, "error", err)
				}
			}
		}

		for _, payload := range payloads {
			evidences, evalErr, successfulRuns := p.evaluateResourcePolicies(ctx, payload, req.GetPolicyPaths())
			pendingEvidences = append(pendingEvidences, evidences...)
			totalEvidenceCount += len(evidences)
			successfulPolicyRuns += successfulRuns
			p.Logger.Debug("Completed policy evaluations for resource",
				"check_name", payload.Check.Name,
				"resource_id", payload.Resource.ID,
				"assessment_status", payload.Assessment.Status,
				"successful_policy_runs", successfulRuns,
				"produced_evidence_count", len(evidences),
				"had_eval_error", evalErr != nil,
			)
			if evalErr != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, evalErr)
			}
			if len(pendingEvidences) >= evidenceBatchSize {
				if err := p.submitEvidenceBatch(ctx, apiHelper, pendingEvidences[:evidenceBatchSize]); err != nil {
					return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
				}
				pendingEvidences = pendingEvidences[evidenceBatchSize:]
			}
		}
	}

	if len(pendingEvidences) > 0 {
		if err := p.submitEvidenceBatch(ctx, apiHelper, pendingEvidences); err != nil {
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
	} else {
		p.Logger.Warn("No evidence generated by current evaluation run")
	}

	if successfulPolicyRuns == 0 && totalEvidenceCount == 0 {
		if accumulatedErrors == nil {
			accumulatedErrors = errors.New("policy evaluation failed for all checks")
		}
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulatedErrors
	}
	if hadCheckExecutionFailures {
		if accumulatedErrors == nil {
			accumulatedErrors = errors.New("one or more cloud custodian checks failed to execute")
		}
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulatedErrors
	}

	if accumulatedErrors != nil {
		p.Logger.Warn("Completed with non-fatal policy evaluation errors", "error", accumulatedErrors)
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func (p *CloudCustodianPlugin) submitEvidenceBatch(ctx context.Context, apiHelper runner.ApiHelper, evidences []*proto.Evidence) error {
	p.Logger.Debug("Submitting evidence batch via ApiHelper", "evidence_count", len(evidences))
	if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
		p.Logger.Error("Error creating evidence", "error", err)
		return err
	}
	return nil
}

func (p *CloudCustodianPlugin) collectInventoryBaselines(ctx context.Context, executionRoot string) map[string]*InventoryBaseline {
	baselines := map[string]*InventoryBaseline{}
	for _, resourceType := range p.uniqueResourceTypes() {
		check := buildInventoryCheck(resourceType)
		outputDir := filepath.Join(executionRoot, fmt.Sprintf("inventory-%s", sanitizeIdentifier(resourceType)))
		execution := p.executor.Execute(ctx, CustodianExecutionRequest{
			BinaryPath: p.parsedConfig.CustodianBinary,
			Check:      check,
			Timeout:    p.parsedConfig.CheckTimeout,
			OutputDir:  outputDir,
		})

		var baselineErr error
		if execution.Err != nil || execution.Error != "" {
			baselineErr = formatExecutionFailure(check.Name, execution)
		}
		baseline := &InventoryBaseline{
			Execution:    execution,
			Resources:    map[string]ResourceRecord{},
			ResourceType: resourceType,
			Provider:     extractProvider(resourceType),
			Err:          baselineErr,
		}
		records := make([]ResourceRecord, 0, len(execution.Resources))
		for _, resource := range execution.Resources {
			records = append(records, p.buildResourceRecord(resourceType, resource))
		}
		collisionCount := 0
		baseline.Resources, collisionCount = disambiguateResourceRecords(records)
		baselines[resourceType] = baseline
		p.Logger.Debug("Collected inventory baseline",
			"resource", resourceType,
			"resource_count", len(baseline.Resources),
			"raw_resource_count", len(execution.Resources),
			"id_collision_count", collisionCount,
			"resources_path", execution.ResourcesPath,
			"exit_code", execution.ExitCode,
			"had_error", baseline.Err != nil,
			"error", execution.Error,
		)
	}
	return baselines
}

func (p *CloudCustodianPlugin) buildResourcePayloadsForCheck(
	check CustodianCheck,
	execution CustodianExecutionResult,
	baseline *InventoryBaseline,
) []*StandardizedResourcePayload {
	matchedRecords := make([]ResourceRecord, 0, len(execution.Resources))
	for _, resource := range execution.Resources {
		matchedRecords = append(matchedRecords, p.buildResourceRecord(check.Resource, resource))
	}
	matched, collisionCount := disambiguateResourceRecords(matchedRecords)
	if collisionCount > 0 {
		p.Logger.Warn("Detected duplicate matched resource identifiers; disambiguating with resource hashes",
			"check_name", check.Name,
			"resource", check.Resource,
			"id_collision_count", collisionCount,
		)
	}

	resourceIDs := make([]string, 0, len(baseline.Resources)+len(matched))
	seen := map[string]bool{}
	for resourceID := range baseline.Resources {
		resourceIDs = append(resourceIDs, resourceID)
		seen[resourceID] = true
	}
	for resourceID := range matched {
		if seen[resourceID] {
			continue
		}
		resourceIDs = append(resourceIDs, resourceID)
	}
	slices.Sort(resourceIDs)

	payloads := make([]*StandardizedResourcePayload, 0, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		record, existsInBaseline := baseline.Resources[resourceID]
		matchedRecord, isMatched := matched[resourceID]
		inventoryStatus := "baseline"
		if !existsInBaseline {
			record = matchedRecord
			inventoryStatus = "missing_from_baseline"
		}

		status := "compliant"
		if isMatched {
			status = "non_compliant"
		}

		payloads = append(payloads, buildResourcePayload(check, execution, record, StandardizedAssessment{
			Status:               status,
			Matched:              isMatched,
			InventoryStatus:      inventoryStatus,
			MatchedResourceCount: len(execution.Resources),
			ArtifactPath:         execution.ArtifactPath,
			ResourcesPath:        execution.ResourcesPath,
		}))
	}
	return payloads
}

type PayloadAssessmentStats struct {
	Compliant           int
	NonCompliant        int
	MissingFromBaseline int
}

func summarizePayloadAssessments(payloads []*StandardizedResourcePayload) PayloadAssessmentStats {
	stats := PayloadAssessmentStats{}
	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		switch payload.Assessment.Status {
		case "compliant":
			stats.Compliant++
		case "non_compliant":
			stats.NonCompliant++
		}
		if payload.Assessment.InventoryStatus == "missing_from_baseline" {
			stats.MissingFromBaseline++
		}
	}
	return stats
}

func (p *CloudCustodianPlugin) evaluateResourcePolicies(
	ctx context.Context,
	payload *StandardizedResourcePayload,
	policyPaths []string,
) ([]*proto.Evidence, error, int) {
	p.Logger.Debug("Evaluating policy paths for resource",
		"check_name", payload.Check.Name,
		"resource_id", payload.Resource.ID,
		"assessment_status", payload.Assessment.Status,
		"policy_paths_count", len(policyPaths),
	)
	p.logPolicyPayload(payload)
	labels := resourcePolicyLabels(p.parsedConfig.PolicyLabels)
	labels["source"] = sourceCloudCustodian
	labels["tool"] = sourceCloudCustodian
	if _, exists := labels["provider"]; !exists {
		labels["provider"] = payload.Resource.Provider
	}
	labels["type"] = "resource"
	labels["check_name"] = payload.Check.Name
	labels["check_resource"] = payload.Check.Resource
	labels["check_status"] = payload.Execution.Status
	labels["resource_type"] = payload.Resource.Type
	labels["resource_id"] = payload.Resource.ID
	if payload.Resource.AccountID != "" {
		labels["account_id"] = payload.Resource.AccountID
	}
	if payload.Resource.Region != "" {
		labels["region"] = payload.Resource.Region
	}

	checkID := fmt.Sprintf("cloud-custodian-check/%s-%d", sanitizeIdentifier(payload.Check.Name), payload.Check.Index+1)
	providerID := fmt.Sprintf("cloud-provider/%s", sanitizeIdentifier(payload.Check.Provider))
	resourceSubjectID := fmt.Sprintf(
		"cloud-custodian-resource/%s/%s",
		url.PathEscape(payload.Resource.Type),
		url.PathEscape(payload.Resource.ID),
	)

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - Cloud Custodian Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-cloud-custodian",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework Cloud Custodian Plugin"),
				},
			},
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "cloud-custodian/runtime",
			Type:        "tool",
			Title:       "Cloud Custodian Runtime",
			Description: "Cloud Custodian CLI runtime used to execute provider policies in dry-run mode.",
			Purpose:     "To execute policy checks without mutating cloud resources.",
		},
		{
			Identifier:  providerID,
			Type:        "service",
			Title:       fmt.Sprintf("Cloud Provider: %s", payload.Check.Provider),
			Description: "Cloud service endpoint evaluated by the Cloud Custodian check.",
			Purpose:     "To provide resource inventory and configuration data for compliance checks.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: checkID,
			Type:       "cloud-custodian-check",
			Title:      fmt.Sprintf("Cloud Custodian Check %s", payload.Check.Name),
			// Local temp artifact paths are intentionally not exposed in evidence links
			// because they are ephemeral and not portable for downstream consumers.
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: "cloud-custodian/runtime"},
				{Identifier: providerID},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_RESOURCE,
			Identifier: resourceSubjectID,
			Links: []*proto.Link{
				{
					Href: payload.Resource.ID,
					Rel:  policyManager.Pointer("related"),
					Text: policyManager.Pointer("Cloud resource identifier"),
				},
			},
			Props: []*proto.Property{
				{Name: "resource_id", Value: payload.Resource.ID},
			},
		},
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: checkID},
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: providerID},
	}

	activities := []*proto.Activity{
		{
			Title: "Execute Cloud Custodian Check",
			Steps: []*proto.Step{
				{Title: "Load Policy", Description: "Load one Cloud Custodian policy entry from the configured policy document."},
				{Title: "Run Dry-Run Check", Description: "Execute Cloud Custodian using --dryrun and capture generated artifacts."},
				{Title: "Build Resource Payload", Description: "Compare policy matches with inventory baseline and build one standardized OPA input for this resource."},
			},
		},
		{
			Title: "Evaluate OPA Policy Bundles",
			Steps: []*proto.Step{
				{Title: "Evaluate Resource Payload", Description: "Run policy bundles against the standardized Cloud Custodian resource payload."},
			},
		},
	}

	allEvidences := make([]*proto.Evidence, 0)
	var accumulatedErrors error
	successfulRuns := 0

	for _, policyPath := range policyPaths {
		p.Logger.Trace("Running policy path for resource", "check_name", payload.Check.Name, "resource_id", payload.Resource.ID, "policy_path", policyPath)
		evidences, err := p.evaluator.Generate(
			ctx,
			policyPath,
			labels,
			subjects,
			components,
			inventory,
			actors,
			activities,
			payload,
		)
		allEvidences = append(allEvidences, evidences...)
		if err != nil {
			p.Logger.Warn("Policy path evaluation failed for resource",
				"check_name", payload.Check.Name,
				"resource_id", payload.Resource.ID,
				"policy_path", policyPath,
				"error", err,
			)
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("policy %s failed for check %s resource %s: %w", policyPath, payload.Check.Name, payload.Resource.ID, err))
			continue
		}
		p.Logger.Trace("Policy path evaluation succeeded for resource",
			"check_name", payload.Check.Name,
			"resource_id", payload.Resource.ID,
			"policy_path", policyPath,
			"evidence_count", len(evidences),
		)
		successfulRuns++
	}

	p.Logger.Debug("Completed policy path loop for resource",
		"check_name", payload.Check.Name,
		"resource_id", payload.Resource.ID,
		"successful_runs", successfulRuns,
		"evidence_count", len(allEvidences),
		"had_errors", accumulatedErrors != nil,
	)
	return allEvidences, accumulatedErrors, successfulRuns
}

func resourcePolicyLabels(policyLabels map[string]string) map[string]string {
	labels := map[string]string{}
	for key, value := range policyLabels {
		if isReservedResourceLabel(key) {
			continue
		}
		labels[key] = value
	}
	return labels
}

func isReservedResourceLabel(label string) bool {
	switch label {
	case "assessment", "assessment_status", "check_provider":
		return true
	default:
		return false
	}
}

func formatExecutionFailure(checkName string, execution CustodianExecutionResult) error {
	switch {
	case execution.Error != "" && execution.Err != nil:
		return fmt.Errorf("custodian policy execution failed for check %s: %s: %w", checkName, execution.Error, execution.Err)
	case execution.Error != "":
		return fmt.Errorf("custodian policy execution failed for check %s: %s", checkName, execution.Error)
	case execution.Err != nil:
		return fmt.Errorf("custodian policy execution failed for check %s: %w", checkName, execution.Err)
	default:
		return fmt.Errorf("custodian policy execution failed for check %s", checkName)
	}
}

func (p *CloudCustodianPlugin) logPolicyPayload(payload *StandardizedResourcePayload) {
	if payload == nil || !p.Logger.IsDebug() {
		return
	}

	p.Logger.Debug("Policy payload",
		"check_name", payload.Check.Name,
		"resource_id", payload.Resource.ID,
		"assessment_status", payload.Assessment.Status,
		"resource_type", payload.Resource.Type,
		"provider", payload.Resource.Provider,
		"debug_dump_payloads", p.parsedConfig != nil && p.parsedConfig.DebugDumpPayloads,
	)
}

func (p *CloudCustodianPlugin) dumpStandardizedPayload(payload *StandardizedResourcePayload) error {
	if payload == nil {
		return errors.New("payload is nil")
	}
	if p.parsedConfig == nil || !p.parsedConfig.DebugDumpPayloads {
		return nil
	}

	content, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	fileName := fmt.Sprintf("%03d-%s-%d.json",
		payload.Check.Index+1,
		fmt.Sprintf("%s-%s", sanitizeIdentifier(payload.Check.Name), sanitizeIdentifier(payload.Resource.ID)),
		time.Now().UTC().UnixNano(),
	)
	outputPath := filepath.Join(p.parsedConfig.DebugPayloadOutputDir, fileName)
	if err := os.WriteFile(outputPath, content, 0o600); err != nil {
		return fmt.Errorf("write payload file %s: %w", outputPath, err)
	}

	p.Logger.Debug("Wrote standardized payload debug file",
		"check_name", payload.Check.Name,
		"resource_id", payload.Resource.ID,
		"output_path", outputPath,
		"bytes", len(content),
	)
	return nil
}

func newCheckErrorExecution(messages []string) CustodianExecutionResult {
	now := time.Now().UTC()
	normalized := make([]string, 0, len(messages))
	for _, message := range messages {
		if strings.TrimSpace(message) == "" {
			continue
		}
		normalized = append(normalized, message)
	}
	joined := strings.Join(normalized, "; ")
	if joined == "" {
		joined = "check failed"
		normalized = []string{joined}
	}
	err := errors.New(joined)
	return CustodianExecutionResult{
		StartedAt: now,
		EndedAt:   now,
		ExitCode:  -1,
		Error:     joined,
		Errors:    normalized,
		Err:       err,
		Resources: []interface{}{},
	}
}

func sanitizeIdentifier(in string) string {
	trimmed := strings.TrimSpace(strings.ToLower(in))
	if trimmed == "" {
		return "unknown"
	}

	builder := strings.Builder{}
	prevDash := false
	for _, r := range trimmed {
		isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlphaNum {
			builder.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			builder.WriteRune('-')
			prevDash = true
		}
	}

	out := strings.Trim(builder.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func sortedKeys(input map[string]string) []string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		JSONFormat: true,
	})

	plugin := &CloudCustodianPlugin{Logger: logger}

	logger.Info("Starting Cloud Custodian Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{Impl: plugin},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
