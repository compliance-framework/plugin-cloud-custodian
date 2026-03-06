package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func stubLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	original := lookPath
	lookPath = fn
	t.Cleanup(func() {
		lookPath = original
	})
}

func TestPluginConfigParse(t *testing.T) {
	stubLookPath(t, func(binary string) (string, error) {
		return "/usr/local/bin/" + binary, nil
	})

	t.Run("inline only", func(t *testing.T) {
		cfg := &PluginConfig{
			PoliciesYAML: `policies:
  - name: s3-check
    resource: aws.s3`,
		}

		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.PoliciesYAML == "" {
			t.Fatalf("expected inline yaml to be preserved")
		}
		if parsed.CheckTimeout != 300*time.Second {
			t.Fatalf("expected default timeout 300s, got %s", parsed.CheckTimeout)
		}
		if parsed.CustodianBinary != "/usr/local/bin/custodian" {
			t.Fatalf("unexpected resolved binary: %s", parsed.CustodianBinary)
		}
	})

	t.Run("path only", func(t *testing.T) {
		cfg := &PluginConfig{PoliciesPath: "/tmp/policies.yaml", CustodianBinary: "custom-custodian", CheckTimeoutSeconds: "45"}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.PoliciesPath != "/tmp/policies.yaml" {
			t.Fatalf("unexpected policies path: %s", parsed.PoliciesPath)
		}
		if parsed.CheckTimeout != 45*time.Second {
			t.Fatalf("expected timeout 45s, got %s", parsed.CheckTimeout)
		}
		if parsed.CustodianBinary != "/usr/local/bin/custom-custodian" {
			t.Fatalf("unexpected resolved binary: %s", parsed.CustodianBinary)
		}
	})

	t.Run("reject empty sources", func(t *testing.T) {
		_, err := (&PluginConfig{}).Parse()
		if err == nil {
			t.Fatalf("expected error for missing policies source")
		}
	})

	t.Run("reject invalid labels json", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", PolicyLabels: "{"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid policy_labels json")
		}
	})

	t.Run("reject invalid timeout", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", CheckTimeoutSeconds: "abc"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid timeout")
		}
	})

	t.Run("reject invalid debug boolean", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", DebugDumpPayloads: "not-bool"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid debug_dump_payloads")
		}
	})

	t.Run("enable debug dump when output dir is set", func(t *testing.T) {
		cfg := &PluginConfig{
			PoliciesYAML:          "policies: []",
			DebugPayloadOutputDir: "/tmp/custom-debug-dir",
		}
		parsed, err := cfg.Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !parsed.DebugDumpPayloads {
			t.Fatalf("expected debug dump to auto-enable when output dir is provided")
		}
		if parsed.DebugPayloadOutputDir != "/tmp/custom-debug-dir" {
			t.Fatalf("unexpected debug output dir: %s", parsed.DebugPayloadOutputDir)
		}
	})
}

func TestResolvePoliciesYAML(t *testing.T) {
	t.Run("inline preferred over path", func(t *testing.T) {
		content, err := resolvePoliciesYAML(context.Background(), "policies: []", "https://example.invalid/policies.yaml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(content) != "policies: []" {
			t.Fatalf("unexpected content: %s", string(content))
		}
	})

	t.Run("local file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "policies.yaml")
		if err := os.WriteFile(f, []byte("policies: []"), 0o600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		content, err := resolvePoliciesYAML(context.Background(), "", f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(content) != "policies: []" {
			t.Fatalf("unexpected content: %s", string(content))
		}
	})

	t.Run("http success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("policies:\n  - name: test\n    resource: aws.s3"))
		}))
		defer srv.Close()

		content, err := resolvePoliciesYAML(context.Background(), "", srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(string(content), "name: test") {
			t.Fatalf("expected fetched yaml content")
		}
	})

	t.Run("http non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()

		_, err := resolvePoliciesYAML(context.Background(), "", srv.URL)
		if err == nil {
			t.Fatalf("expected error for non-2xx response")
		}
	})

	t.Run("http response too large", func(t *testing.T) {
		oversized := strings.Repeat("a", defaultMaxRemotePolicyBytes+1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(oversized))
		}))
		defer srv.Close()

		_, err := resolvePoliciesYAML(context.Background(), "", srv.URL)
		if err == nil {
			t.Fatalf("expected error for oversized response body")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected oversized body error, got: %v", err)
		}
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		_, err := resolvePoliciesYAML(context.Background(), "", "s3://bucket/policies.yaml")
		if err == nil {
			t.Fatalf("expected error for unsupported scheme")
		}
	})

	t.Run("windows style path treated as local path", func(t *testing.T) {
		_, err := resolvePoliciesYAML(context.Background(), "", `C:\policies.yaml`)
		if err == nil {
			t.Fatalf("expected local file read error for missing windows-style path")
		}
		if !strings.Contains(err.Error(), "failed to read local policies file") {
			t.Fatalf("expected local file read path handling, got: %v", err)
		}
	})
}

func TestParseCustodianChecks(t *testing.T) {
	t.Run("valid policies", func(t *testing.T) {
		checks, err := parseCustodianChecks([]byte(`policies:
  - name: s3-public
    resource: aws.s3
    mode:
      type: periodic
  - name: vm-policy
    resource: azure.vm`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checks) != 2 {
			t.Fatalf("expected 2 checks, got %d", len(checks))
		}
		if checks[0].Provider != "aws" {
			t.Fatalf("expected provider aws, got %s", checks[0].Provider)
		}
		if len(checks[0].ParseErrors) != 0 {
			t.Fatalf("expected no parse errors, got %v", checks[0].ParseErrors)
		}
	})

	t.Run("invalid entries become check errors", func(t *testing.T) {
		checks, err := parseCustodianChecks([]byte(`policies:
  - "not-an-object"
  - name: missing-resource`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(checks) != 2 {
			t.Fatalf("expected 2 checks, got %d", len(checks))
		}
		if len(checks[0].ParseErrors) == 0 {
			t.Fatalf("expected parse error for first check")
		}
		if len(checks[1].ParseErrors) == 0 {
			t.Fatalf("expected parse error for second check")
		}
	})

	t.Run("missing top-level policies fails", func(t *testing.T) {
		_, err := parseCustodianChecks([]byte(`foo: bar`))
		if err == nil {
			t.Fatalf("expected error when top-level policies missing")
		}
	})
}

func writeExecutableScript(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script helper is not supported on windows")
	}

	binary := filepath.Join(t.TempDir(), "custodian")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return binary
}

func TestCommandCustodianExecutor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executor tests use POSIX shell scripts")
	}

	t.Run("passes required args and loads resources", func(t *testing.T) {
		argsFile := filepath.Join(t.TempDir(), "args.txt")
		t.Setenv("ARGS_FILE", argsFile)

		script := `#!/bin/sh
set -eu
echo "$@" > "$ARGS_FILE"
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-s" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
 done
mkdir -p "$out/test-policy"
printf '[{"id":"abc"}]' > "$out/test-policy/resources.json"
`
		binary := writeExecutableScript(t, script)

		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}
		outDir := filepath.Join(t.TempDir(), "out")
		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.s3",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.s3"},
			},
			Timeout:   5 * time.Second,
			OutputDir: outDir,
		})

		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", result.ExitCode)
		}
		if len(result.Resources) != 1 {
			t.Fatalf("expected one resource, got %d", len(result.Resources))
		}
		if result.ResourcesPath == "" {
			t.Fatalf("expected resources path to be set")
		}

		argsContent, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("failed to read args capture file: %v", err)
		}
		argsStr := string(argsContent)
		if !strings.Contains(argsStr, "run --dryrun -s") {
			t.Fatalf("expected dry-run args, got: %s", argsStr)
		}
		if !strings.Contains(argsStr, "policy.yaml") {
			t.Fatalf("expected policy.yaml argument, got: %s", argsStr)
		}
		if !strings.Contains(argsStr, "--region all") {
			t.Fatalf("expected aws region fanout args, got: %s", argsStr)
		}
	})

	t.Run("timeout cancellation", func(t *testing.T) {
		script := `#!/bin/sh
sleep 2
`
		binary := writeExecutableScript(t, script)
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}

		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "slow-check",
				Resource:  "aws.ec2",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "slow-check", "resource": "aws.ec2"},
			},
			Timeout:   100 * time.Millisecond,
			OutputDir: filepath.Join(t.TempDir(), "out"),
		})

		if result.Err == nil {
			t.Fatalf("expected timeout error")
		}
		if !strings.Contains(result.Error, "deadline exceeded") {
			t.Fatalf("expected deadline exceeded in error, got: %s", result.Error)
		}
		deadlineMentions := 0
		for _, msg := range result.Errors {
			if strings.Contains(msg, "deadline exceeded") {
				deadlineMentions++
			}
		}
		if deadlineMentions > 1 {
			t.Fatalf("expected at most one deadline exceeded entry, got: %v", result.Errors)
		}
	})
}

func TestBuildCheckPayload(t *testing.T) {
	now := time.Now().UTC()
	check := CustodianCheck{
		Index:    0,
		Name:     "s3-check",
		Resource: "aws.s3",
		Provider: "aws",
		RawPolicy: map[string]interface{}{
			"name":     "s3-check",
			"resource": "aws.s3",
			"mode": map[string]interface{}{
				"type": "periodic",
			},
		},
	}

	success := buildCheckPayload(check, CustodianExecutionResult{
		StartedAt:     now,
		EndedAt:       now.Add(2 * time.Second),
		ExitCode:      0,
		Stdout:        "ok",
		Resources:     []interface{}{map[string]interface{}{"id": "a"}},
		ArtifactPath:  "/tmp/out",
		ResourcesPath: "/tmp/out/s3/resources.json",
	})

	if success.SchemaVersion != "v1" {
		t.Fatalf("expected schema version v1")
	}
	if success.Execution.Status != "success" {
		t.Fatalf("expected success status")
	}
	if success.Result.MatchedResourceCount != 1 {
		t.Fatalf("expected matched count 1, got %d", success.Result.MatchedResourceCount)
	}
	if success.Check.Metadata["mode"] == nil {
		t.Fatalf("expected metadata to include non-name/resource fields")
	}

	failure := buildCheckPayload(check, newCheckErrorExecution([]string{"parse failure"}))
	if failure.Execution.Status != "error" {
		t.Fatalf("expected error status")
	}
	if failure.Result.MatchedResourceCount != 0 {
		t.Fatalf("expected matched count 0 for failed payload")
	}
	if len(failure.Execution.Errors) != 1 || failure.Execution.Errors[0] != "parse failure" {
		t.Fatalf("expected structured execution errors in payload, got %v", failure.Execution.Errors)
	}
}

type fakeExecutor struct {
	calls   []CustodianExecutionRequest
	results map[string]CustodianExecutionResult
}

func (f *fakeExecutor) Execute(ctx context.Context, req CustodianExecutionRequest) CustodianExecutionResult {
	f.calls = append(f.calls, req)
	if result, ok := f.results[req.Check.Name]; ok {
		return result
	}
	now := time.Now().UTC()
	return CustodianExecutionResult{StartedAt: now, EndedAt: now, ExitCode: 0, Resources: []interface{}{}}
}

type fakePolicyEvaluator struct {
	calls      []string
	failChecks map[string]bool
	labelsSeen []map[string]string
}

func (f *fakePolicyEvaluator) Generate(
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
	payload, ok := data.(*StandardizedCheckPayload)
	if !ok {
		return nil, errors.New("unexpected payload type")
	}

	f.calls = append(f.calls, fmt.Sprintf("%s|%s|%s", payload.Check.Name, policyPath, payload.Execution.Status))
	copiedLabels := map[string]string{}
	for k, v := range labels {
		copiedLabels[k] = v
	}
	f.labelsSeen = append(f.labelsSeen, copiedLabels)
	if f.failChecks[payload.Check.Name] {
		return nil, errors.New("forced evaluator error")
	}

	return []*proto.Evidence{{UUID: fmt.Sprintf("%s-%s", payload.Check.Name, policyPath), Labels: labels}}, nil
}

type fakeAPIHelper struct {
	calls    int
	evidence []*proto.Evidence
	err      error
}

func (f *fakeAPIHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	f.calls++
	f.evidence = append(f.evidence, evidence...)
	return f.err
}

func TestEvalLoopBehavior(t *testing.T) {
	now := time.Now().UTC()

	t.Run("continues on check execution errors and submits evidence", func(t *testing.T) {
		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"check-a": {
				StartedAt: now,
				EndedAt:   now.Add(20 * time.Millisecond),
				ExitCode:  0,
				Resources: []interface{}{map[string]interface{}{"id": "1"}},
			},
			"check-b": {
				StartedAt: now,
				EndedAt:   now.Add(10 * time.Millisecond),
				ExitCode:  1,
				Error:     "execution failed",
				Err:       errors.New("execution failed"),
				Resources: []interface{}{},
			},
		}}

		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &CloudCustodianPlugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				PolicyLabels: map[string]string{"team": "platform"},
				CheckTimeout: 30 * time.Second,
			},
			checks: []CustodianCheck{
				{Index: 0, Name: "check-a", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "check-a", "resource": "aws.s3"}},
				{Index: 1, Name: "check-b", Resource: "aws.ec2", Provider: "aws", RawPolicy: map[string]interface{}{"name": "check-b", "resource": "aws.ec2"}},
			},
			executor:  executor,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a", "bundle-b"}}, apiHelper)
		if err != nil {
			t.Fatalf("unexpected eval error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success status, got %s", resp.GetStatus().String())
		}
		if len(executor.calls) != 2 {
			t.Fatalf("expected 2 executor calls, got %d", len(executor.calls))
		}
		if len(evaluator.calls) != 4 {
			t.Fatalf("expected 4 evaluator calls, got %d", len(evaluator.calls))
		}
		if apiHelper.calls != 1 {
			t.Fatalf("expected CreateEvidence once, got %d", apiHelper.calls)
		}
		if len(apiHelper.evidence) != 4 {
			t.Fatalf("expected 4 evidences, got %d", len(apiHelper.evidence))
		}

		hasErrorStatusPayload := false
		for _, call := range evaluator.calls {
			if strings.Contains(call, "check-b|") && strings.HasSuffix(call, "|error") {
				hasErrorStatusPayload = true
				break
			}
		}
		if !hasErrorStatusPayload {
			t.Fatalf("expected check-b payload to carry error execution status")
		}
	})

	t.Run("fails when all policy evaluations fail", func(t *testing.T) {
		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"check-a": {
				StartedAt: now,
				EndedAt:   now,
				ExitCode:  0,
				Resources: []interface{}{},
			},
		}}

		evaluator := &fakePolicyEvaluator{failChecks: map[string]bool{"check-a": true}}
		apiHelper := &fakeAPIHelper{}

		plugin := &CloudCustodianPlugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				PolicyLabels: map[string]string{},
				CheckTimeout: 30 * time.Second,
			},
			checks: []CustodianCheck{
				{Index: 0, Name: "check-a", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "check-a", "resource": "aws.s3"}},
			},
			executor:  executor,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err == nil {
			t.Fatalf("expected eval failure when all policy evaluations fail")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status, got %s", resp.GetStatus().String())
		}
		if apiHelper.calls != 0 {
			t.Fatalf("expected no evidence submission, got %d calls", apiHelper.calls)
		}
	})

	t.Run("preserves user provider label and adds source labels", func(t *testing.T) {
		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"check-a": {
				StartedAt: now,
				EndedAt:   now,
				ExitCode:  0,
				Resources: []interface{}{},
			},
		}}

		evaluator := &fakePolicyEvaluator{}
		apiHelper := &fakeAPIHelper{}

		plugin := &CloudCustodianPlugin{
			Logger: hclog.NewNullLogger(),
			parsedConfig: &ParsedConfig{
				PolicyLabels: map[string]string{"provider": "custom-provider", "team": "platform"},
				CheckTimeout: 30 * time.Second,
			},
			checks: []CustodianCheck{
				{Index: 0, Name: "check-a", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "check-a", "resource": "aws.s3"}},
			},
			executor:  executor,
			evaluator: evaluator,
		}

		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
		if err != nil {
			t.Fatalf("unexpected eval error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success status, got %s", resp.GetStatus().String())
		}
		if len(evaluator.labelsSeen) == 0 {
			t.Fatalf("expected evaluator to capture labels")
		}

		labels := evaluator.labelsSeen[0]
		if labels["provider"] != "custom-provider" {
			t.Fatalf("expected provider label to be preserved, got: %s", labels["provider"])
		}
		if labels["source"] != sourceCloudCustodian {
			t.Fatalf("expected source label, got: %s", labels["source"])
		}
		if labels["tool"] != sourceCloudCustodian {
			t.Fatalf("expected tool label, got: %s", labels["tool"])
		}
		if labels["check_provider"] != "aws" {
			t.Fatalf("expected check_provider label to be aws, got: %s", labels["check_provider"])
		}
	})
}

func TestConfigureLoadsChecks(t *testing.T) {
	stubLookPath(t, func(binary string) (string, error) {
		return "/usr/local/bin/" + binary, nil
	})

	plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger()}
	resp, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"policies_yaml": `policies:
  - name: s3-check
    resource: aws.s3`,
		"policy_labels": `{"environment":"dev"}`,
	}})
	if err != nil {
		t.Fatalf("unexpected configure error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected configure response")
	}
	if len(plugin.checks) != 1 {
		t.Fatalf("expected one parsed check, got %d", len(plugin.checks))
	}
	if plugin.parsedConfig.PolicyLabels["environment"] != "dev" {
		t.Fatalf("expected parsed policy label")
	}
}

func TestDumpStandardizedPayload(t *testing.T) {
	plugin := &CloudCustodianPlugin{
		Logger: hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{
			DebugDumpPayloads:     true,
			DebugPayloadOutputDir: t.TempDir(),
		},
	}

	err := plugin.dumpStandardizedPayload(&StandardizedCheckPayload{
		SchemaVersion: "v1",
		Source:        "cloud-custodian",
		Check: StandardizedCheckInfo{
			Name:     "check-a",
			Resource: "aws.s3",
			Provider: "aws",
			Index:    0,
		},
		Execution: StandardizedExecution{
			Status: "success",
			DryRun: true,
		},
		Result: StandardizedCheckResult{
			MatchedResourceCount: 0,
			Resources:            []interface{}{},
		},
		RawPolicy: map[string]interface{}{"name": "check-a", "resource": "aws.s3"},
	})
	if err != nil {
		t.Fatalf("unexpected dump error: %v", err)
	}

	files, err := os.ReadDir(plugin.parsedConfig.DebugPayloadOutputDir)
	if err != nil {
		t.Fatalf("failed to read debug output dir: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected one dumped payload file, got %d", len(files))
	}
	content, err := os.ReadFile(filepath.Join(plugin.parsedConfig.DebugPayloadOutputDir, files[0].Name()))
	if err != nil {
		t.Fatalf("failed to read dumped payload file: %v", err)
	}
	if !strings.Contains(string(content), "\"schema_version\": \"v1\"") {
		t.Fatalf("dumped payload file content does not look like standardized payload json")
	}
}
