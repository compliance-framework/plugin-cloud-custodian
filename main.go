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
	schemaVersionV1             = "v1"
	sourceCloudCustodian        = "cloud-custodian"
	defaultRemotePolicyTimeout  = 30 * time.Second
	defaultMaxRemotePolicyBytes = 1 << 20 // 1 MiB
)

var lookPath = exec.LookPath

// PluginConfig receives string-only config from the agent gRPC interface.
type PluginConfig struct {
	PoliciesYAML          string `mapstructure:"policies_yaml"`
	PoliciesPath          string `mapstructure:"policies_path"`
	CustodianBinary       string `mapstructure:"custodian_binary"`
	PolicyLabels          string `mapstructure:"policy_labels"`
	CheckTimeoutSeconds   string `mapstructure:"check_timeout_seconds"`
	DebugDumpPayloads     string `mapstructure:"debug_dump_payloads"`
	DebugPayloadOutputDir string `mapstructure:"debug_payload_output_dir"`
}

// ParsedConfig stores normalized and validated values for runtime use.
type ParsedConfig struct {
	PoliciesYAML          string
	PoliciesPath          string
	CustodianBinary       string
	PolicyLabels          map[string]string
	CheckTimeout          time.Duration
	DebugDumpPayloads     bool
	DebugPayloadOutputDir string
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
		PoliciesYAML:          inlineYAML,
		PoliciesPath:          policiesPath,
		CustodianBinary:       resolvedBinary,
		PolicyLabels:          policyLabels,
		CheckTimeout:          time.Duration(checkTimeoutSeconds) * time.Second,
		DebugDumpPayloads:     debugDumpPayloads,
		DebugPayloadOutputDir: debugPayloadOutputDir,
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

	var executionErrors []string
	if len(execution.Errors) > 0 {
		executionErrors = append([]string{}, execution.Errors...)
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
			Errors:     executionErrors,
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

	allEvidences := make([]*proto.Evidence, 0)
	var accumulatedErrors error
	successfulPolicyRuns := 0

	for _, check := range p.checks {
		p.Logger.Debug("Processing check", "check_name", check.Name, "check_index", check.Index, "resource", check.Resource, "provider", check.Provider)
		execution := CustodianExecutionResult{}
		if len(check.ParseErrors) > 0 {
			p.Logger.Warn("Skipping custodian execution due to check parse issues", "check_name", check.Name, "parse_errors", check.ParseErrors)
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
		p.Logger.Debug("Built standardized check payload",
			"check_name", payload.Check.Name,
			"status", payload.Execution.Status,
			"matched_resource_count", payload.Result.MatchedResourceCount,
			"execution_error_count", len(payload.Execution.Errors),
		)
		if p.parsedConfig.DebugDumpPayloads {
			if err := p.dumpStandardizedPayload(payload); err != nil {
				p.Logger.Warn("Failed writing debug standardized payload", "check_name", payload.Check.Name, "error", err)
			}
		}
		evidences, evalErr, successfulRuns := p.evaluateCheckPolicies(ctx, payload, req.GetPolicyPaths())
		allEvidences = append(allEvidences, evidences...)
		successfulPolicyRuns += successfulRuns
		p.Logger.Debug("Completed policy evaluations for check",
			"check_name", payload.Check.Name,
			"successful_policy_runs", successfulRuns,
			"produced_evidence_count", len(evidences),
			"had_eval_error", evalErr != nil,
		)
		if evalErr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, evalErr)
		}
	}

	if len(allEvidences) > 0 {
		p.Logger.Debug("Submitting evidence batch via ApiHelper", "evidence_count", len(allEvidences))
		if err := apiHelper.CreateEvidence(ctx, allEvidences); err != nil {
			p.Logger.Error("Error creating evidence", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
	} else {
		p.Logger.Warn("No evidence generated by current evaluation run")
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
	p.Logger.Debug("Evaluating policy paths for check",
		"check_name", payload.Check.Name,
		"check_status", payload.Execution.Status,
		"policy_paths_count", len(policyPaths),
	)
	labels := map[string]string{}
	maps.Copy(labels, p.parsedConfig.PolicyLabels)
	labels["source"] = sourceCloudCustodian
	labels["tool"] = sourceCloudCustodian
	if _, exists := labels["provider"]; !exists {
		labels["provider"] = payload.Check.Provider
	}
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
		p.Logger.Trace("Running policy path for check", "check_name", payload.Check.Name, "policy_path", policyPath)
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
			p.Logger.Warn("Policy path evaluation failed for check",
				"check_name", payload.Check.Name,
				"policy_path", policyPath,
				"error", err,
			)
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("policy %s failed for check %s: %w", policyPath, payload.Check.Name, err))
			continue
		}
		p.Logger.Trace("Policy path evaluation succeeded for check",
			"check_name", payload.Check.Name,
			"policy_path", policyPath,
			"evidence_count", len(evidences),
		)
		successfulRuns++
	}

	p.Logger.Debug("Completed policy path loop for check",
		"check_name", payload.Check.Name,
		"successful_runs", successfulRuns,
		"evidence_count", len(allEvidences),
		"had_errors", accumulatedErrors != nil,
	)
	return allEvidences, accumulatedErrors, successfulRuns
}

func (p *CloudCustodianPlugin) dumpStandardizedPayload(payload *StandardizedCheckPayload) error {
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
		sanitizeIdentifier(payload.Check.Name),
		time.Now().UTC().UnixNano(),
	)
	outputPath := filepath.Join(p.parsedConfig.DebugPayloadOutputDir, fileName)
	if err := os.WriteFile(outputPath, content, 0o600); err != nil {
		return fmt.Errorf("write payload file %s: %w", outputPath, err)
	}

	p.Logger.Debug("Wrote standardized payload debug file",
		"check_name", payload.Check.Name,
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
			"runner": &runner.RunnerGRPCPlugin{Impl: plugin},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
