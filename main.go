package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	defaultCheckTimeoutSeconds = 300
	schemaVersionV1            = "v1"
	sourceCloudCustodian       = "cloud-custodian"
)

var lookPath = exec.LookPath

// PluginConfig receives string-only config from the agent gRPC interface.
type PluginConfig struct {
	PoliciesYAML        string `mapstructure:"policies_yaml"`
	PoliciesPath        string `mapstructure:"policies_path"`
	CustodianBinary     string `mapstructure:"custodian_binary"`
	PolicyLabels        string `mapstructure:"policy_labels"`
	CheckTimeoutSeconds string `mapstructure:"check_timeout_seconds"`
}

// ParsedConfig stores normalized and validated values for runtime use.
type ParsedConfig struct {
	PoliciesYAML    string
	PoliciesPath    string
	CustodianBinary string
	PolicyLabels    map[string]string
	CheckTimeout    time.Duration
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

	return &ParsedConfig{
		PoliciesYAML:    inlineYAML,
		PoliciesPath:    policiesPath,
		CustodianBinary: resolvedBinary,
		PolicyLabels:    policyLabels,
		CheckTimeout:    time.Duration(checkTimeoutSeconds) * time.Second,
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
		result.EndedAt = time.Now().UTC()
		return result
	}

	policyDocument := map[string]interface{}{
		"policies": []map[string]interface{}{req.Check.RawPolicy},
	}
	policyContent, err := yaml.Marshal(policyDocument)
	if err != nil {
		result.Err = fmt.Errorf("failed to marshal single policy document: %w", err)
		result.Error = result.Err.Error()
		result.Errors = []string{result.Error}
		result.EndedAt = time.Now().UTC()
		return result
	}

	policyPath := filepath.Join(req.OutputDir, "policy.yaml")
	if err := os.WriteFile(policyPath, policyContent, 0o600); err != nil {
		result.Err = fmt.Errorf("failed to write single policy file: %w", err)
		result.Error = result.Err.Error()
		result.Errors = []string{result.Error}
		result.EndedAt = time.Now().UTC()
		return result
	}

	runCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, req.BinaryPath, "run", "--dryrun", "-s", req.OutputDir, policyPath)
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

	resourcesPath, resources, resourcesErr := readResourcesArtifact(req.OutputDir)
	result.ResourcesPath = resourcesPath
	if resources != nil {
		result.Resources = resources
	}

	if err != nil {
		result.Err = fmt.Errorf("custodian execution failed: %w", err)
		result.Errors = append(result.Errors, result.Err.Error())
	}
	if runCtx.Err() != nil {
		result.Err = errors.Join(result.Err, runCtx.Err())
		result.Errors = append(result.Errors, runCtx.Err().Error())
	}
	if resourcesErr != nil {
		result.Err = errors.Join(result.Err, resourcesErr)
		result.Errors = append(result.Errors, resourcesErr.Error())
	}

	if result.Err != nil {
		result.Error = strings.Join(result.Errors, "; ")
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
			return io.EOF
		}
		return nil
	})

	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if found == "" {
		return "", fs.ErrNotExist
	}
	return found, nil
}

// StandardizedCheckPayload is the per-check OPA input contract.
type StandardizedCheckPayload struct {
	SchemaVersion string                  `json:"schema_version"`
	Source        string                  `json:"source"`
	Check         StandardizedCheckInfo   `json:"check"`
	Execution     StandardizedExecution   `json:"execution"`
	Result        StandardizedCheckResult `json:"result"`
	RawPolicy     map[string]interface{}  `json:"raw_policy"`
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

type StandardizedCheckResult struct {
	MatchedResourceCount int           `json:"matched_resource_count"`
	Resources            []interface{} `json:"resources"`
	ArtifactPath         string        `json:"artifact_path,omitempty"`
	ResourcesPath        string        `json:"resources_path,omitempty"`
}

func buildCheckPayload(check CustodianCheck, execution CustodianExecutionResult) *StandardizedCheckPayload {
	status := "success"
	if execution.Error != "" {
		status = "error"
	}

	durationMS := int64(execution.EndedAt.Sub(execution.StartedAt) / time.Millisecond)
	if durationMS < 0 {
		durationMS = 0
	}

	metadata := map[string]interface{}{}
	for k, v := range check.RawPolicy {
		if k == "name" || k == "resource" {
			continue
		}
		metadata[k] = v
	}

	return &StandardizedCheckPayload{
		SchemaVersion: schemaVersionV1,
		Source:        sourceCloudCustodian,
		Check: StandardizedCheckInfo{
			Name:     check.Name,
			Resource: check.Resource,
			Provider: check.Provider,
			Index:    check.Index,
			Metadata: metadata,
		},
		Execution: StandardizedExecution{
			Status:     status,
			DryRun:     true,
			ExitCode:   execution.ExitCode,
			StartedAt:  execution.StartedAt.UTC().Format(time.RFC3339Nano),
			EndedAt:    execution.EndedAt.UTC().Format(time.RFC3339Nano),
			DurationMS: durationMS,
			Stdout:     execution.Stdout,
			Stderr:     execution.Stderr,
			Error:      execution.Error,
			Errors:     append([]string{}, execution.Errors...),
		},
		Result: StandardizedCheckResult{
			MatchedResourceCount: len(execution.Resources),
			Resources:            execution.Resources,
			ArtifactPath:         execution.ArtifactPath,
			ResourcesPath:        execution.ResourcesPath,
		},
		RawPolicy: check.RawPolicy,
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
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch policies_path: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("unexpected status code %d while fetching policies_path", resp.StatusCode)
		}

		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read policies_path response body: %w", err)
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
	processor := policyManager.NewPolicyProcessor(
		e.Logger,
		labels,
		subjects,
		components,
		inventory,
		actors,
		activities,
	)
	return processor.GenerateResults(ctx, policyPath, data)
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
	p.Logger.Info("Configuring Cloud Custodian Plugin")

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

	resolvedPolicies, err := resolvePoliciesYAML(context.Background(), parsed.PoliciesYAML, parsed.PoliciesPath)
	if err != nil {
		p.Logger.Error("Error loading cloud custodian policies", "error", err)
		return nil, err
	}

	checks, err := parseCustodianChecks(resolvedPolicies)
	if err != nil {
		p.Logger.Error("Error parsing cloud custodian policies", "error", err)
		return nil, err
	}

	parsed.PoliciesYAML = string(resolvedPolicies)
	p.config = config
	p.parsedConfig = parsed
	p.checks = checks

	if p.executor == nil {
		p.executor = &CommandCustodianExecutor{Logger: p.Logger.Named("custodian-executor")}
	}
	if p.evaluator == nil {
		p.evaluator = &DefaultPolicyEvaluator{Logger: p.Logger.Named("policy-evaluator")}
	}

	p.Logger.Info("Cloud Custodian Plugin configured", "checks", len(checks))
	return &proto.ConfigureResponse{}, nil
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

	allEvidences := make([]*proto.Evidence, 0)
	var accumulatedErrors error
	successfulPolicyRuns := 0

	for _, check := range p.checks {
		execution := CustodianExecutionResult{}
		if len(check.ParseErrors) > 0 {
			execution = newCheckErrorExecution(check.ParseErrors)
		} else {
			checkDir := filepath.Join(executionRoot, fmt.Sprintf("%03d-%s", check.Index+1, sanitizeIdentifier(check.Name)))
			execution = p.executor.Execute(ctx, CustodianExecutionRequest{
				BinaryPath: p.parsedConfig.CustodianBinary,
				Check:      check,
				Timeout:    p.parsedConfig.CheckTimeout,
				OutputDir:  checkDir,
			})
		}

		payload := buildCheckPayload(check, execution)
		evidences, evalErr, successfulRuns := p.evaluateCheckPolicies(ctx, payload, req.GetPolicyPaths())
		allEvidences = append(allEvidences, evidences...)
		successfulPolicyRuns += successfulRuns
		if evalErr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, evalErr)
		}
	}

	if len(allEvidences) > 0 {
		if err := apiHelper.CreateEvidence(ctx, allEvidences); err != nil {
			p.Logger.Error("Error creating evidence", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
	}

	if successfulPolicyRuns == 0 && len(allEvidences) == 0 {
		if accumulatedErrors == nil {
			accumulatedErrors = errors.New("policy evaluation failed for all checks")
		}
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulatedErrors
	}

	if accumulatedErrors != nil {
		p.Logger.Warn("Completed with non-fatal policy evaluation errors", "error", accumulatedErrors)
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func (p *CloudCustodianPlugin) evaluateCheckPolicies(
	ctx context.Context,
	payload *StandardizedCheckPayload,
	policyPaths []string,
) ([]*proto.Evidence, error, int) {
	labels := map[string]string{}
	maps.Copy(labels, p.parsedConfig.PolicyLabels)
	labels["provider"] = sourceCloudCustodian
	labels["type"] = "check"
	labels["check_name"] = payload.Check.Name
	labels["check_resource"] = payload.Check.Resource
	labels["check_provider"] = payload.Check.Provider
	labels["check_status"] = payload.Execution.Status

	checkID := fmt.Sprintf("cloud-custodian-check/%s-%d", sanitizeIdentifier(payload.Check.Name), payload.Check.Index+1)
	providerID := fmt.Sprintf("cloud-provider/%s", sanitizeIdentifier(payload.Check.Provider))

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

	inventoryLinks := []*proto.Link{}
	if payload.Result.ArtifactPath != "" {
		inventoryLinks = append(inventoryLinks, &proto.Link{Href: payload.Result.ArtifactPath, Text: policyManager.Pointer("Custodian Artifact Directory")})
	}
	if payload.Result.ResourcesPath != "" {
		inventoryLinks = append(inventoryLinks, &proto.Link{Href: payload.Result.ResourcesPath, Text: policyManager.Pointer("Custodian resources.json")})
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: checkID,
			Type:       "cloud-custodian-check",
			Title:      fmt.Sprintf("Cloud Custodian Check %s", payload.Check.Name),
			Links:      inventoryLinks,
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: "cloud-custodian/runtime"},
				{Identifier: providerID},
			},
		},
	}

	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: checkID},
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: providerID},
	}

	activities := []*proto.Activity{
		{
			Title: "Execute Cloud Custodian Check",
			Steps: []*proto.Step{
				{Title: "Load Policy", Description: "Load one Cloud Custodian policy entry from the configured policy document."},
				{Title: "Run Dry-Run Check", Description: "Execute Cloud Custodian using --dryrun and capture generated artifacts."},
				{Title: "Build Standardized Payload", Description: "Convert execution output and matched resources into standardized OPA input."},
			},
		},
		{
			Title: "Evaluate OPA Policy Bundles",
			Steps: []*proto.Step{
				{Title: "Evaluate Check Payload", Description: "Run policy bundles against the standardized Cloud Custodian check payload."},
			},
		},
	}

	allEvidences := make([]*proto.Evidence, 0)
	var accumulatedErrors error
	successfulRuns := 0

	for _, policyPath := range policyPaths {
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
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("policy %s failed for check %s: %w", policyPath, payload.Check.Name, err))
			continue
		}
		successfulRuns++
	}

	return allEvidences, accumulatedErrors, successfulRuns
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
			"runner": &runner.RunnerGRPCPlugin{Impl: plugin},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
