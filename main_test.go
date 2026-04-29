package main

import (
	"context"
	"encoding/json"
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
		cfg := &PluginConfig{
			PoliciesPath:        "/tmp/policies.yaml",
			CustodianBinary:     "custom-custodian",
			CheckTimeoutSeconds: "45",
			AWSRegions:          "us-east-1, eu-west-1 us-east-1",
		}
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
		if len(parsed.AWSRegions) != 2 || parsed.AWSRegions[0] != "us-east-1" || parsed.AWSRegions[1] != "eu-west-1" {
			t.Fatalf("unexpected aws regions: %#v", parsed.AWSRegions)
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

	t.Run("parse resource identity fields", func(t *testing.T) {
		parsed, err := (&PluginConfig{
			PoliciesYAML:           "x",
			ResourceIdentityFields: `{"aws.ec2":[" InstanceId ","Arn",""]}`,
		}).Parse()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := parsed.ResourceIdentityFields["aws.ec2"]
		if len(got) != 2 || got[0] != "InstanceId" || got[1] != "Arn" {
			t.Fatalf("unexpected normalized resource identity fields: %#v", got)
		}
	})

	t.Run("reject invalid resource identity fields json", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", ResourceIdentityFields: "{"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid resource_identity_fields json")
		}
	})

	t.Run("reject empty resource type in resource identity fields", func(t *testing.T) {
		_, err := (&PluginConfig{
			PoliciesYAML:           "x",
			ResourceIdentityFields: `{"":["Id"]}`,
		}).Parse()
		if err == nil {
			t.Fatalf("expected error for empty resource type key")
		}
	})

	t.Run("reject empty resource identity field list", func(t *testing.T) {
		_, err := (&PluginConfig{
			PoliciesYAML:           "x",
			ResourceIdentityFields: `{"aws.ec2":[" ",""]}`,
		}).Parse()
		if err == nil {
			t.Fatalf("expected error for empty resource identity field list")
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
    non_compliance_message: S3 bucket allows public access.
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
		if checks[0].RawPolicy[nonComplianceMessageField] != "S3 bucket allows public access." {
			t.Fatalf("expected non-compliance message to be preserved in raw policy, got %#v", checks[0].RawPolicy[nonComplianceMessageField])
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

	t.Run("passes configured aws regions without all fallback", func(t *testing.T) {
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
printf '[]' > "$out/test-policy/resources.json"
`
		binary := writeExecutableScript(t, script)

		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}
		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.s3",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.s3"},
			},
			Timeout:    5 * time.Second,
			OutputDir:  filepath.Join(t.TempDir(), "out"),
			AWSRegions: []string{"us-east-1", "eu-west-1"},
		})
		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}

		argsContent, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("failed to read args capture file: %v", err)
		}
		argsStr := string(argsContent)
		if !strings.Contains(argsStr, "--region us-east-1 --region eu-west-1") {
			t.Fatalf("expected configured aws region args, got: %s", argsStr)
		}
		if strings.Contains(argsStr, "--region all") {
			t.Fatalf("did not expect all-region fallback when aws regions are configured, got: %s", argsStr)
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

	t.Run("strips plugin-only policy fields before custodian execution", func(t *testing.T) {
		script := `#!/bin/sh
set -eu
out=""
policy=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-s" ]; then
    out="$2"
    shift 2
    continue
  fi
  case "$1" in
    *.yaml) policy="$1" ;;
  esac
  shift
done
if grep -q non_compliance_message "$policy"; then
  echo "unexpected non_compliance_message in custodian policy" >&2
  exit 17
fi
mkdir -p "$out/test-policy"
printf '[]' > "$out/test-policy/resources.json"
`
		binary := writeExecutableScript(t, script)

		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}
		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:     "test-policy",
				Resource: "aws.s3",
				Provider: "aws",
				RawPolicy: map[string]interface{}{
					"name":                    "test-policy",
					"resource":                "aws.s3",
					nonComplianceMessageField: "S3 bucket allows public access.",
				},
			},
			Timeout:   5 * time.Second,
			OutputDir: filepath.Join(t.TempDir(), "out"),
		})

		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("expected exit code 0, got %d: %s", result.ExitCode, result.Stderr)
		}
	})
}

func TestCustodianDiagnosticInterval(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "non-positive timeout uses default watch interval",
			timeout: 0,
			want:    custodianWatchInterval,
		},
		{
			name:    "long timeout uses default watch interval",
			timeout: 2 * custodianWatchInterval,
			want:    custodianWatchInterval,
		},
		{
			name:    "short timeout uses half timeout",
			timeout: 8 * time.Second,
			want:    4 * time.Second,
		},
		{
			name:    "very short timeout floors at one second",
			timeout: 1500 * time.Millisecond,
			want:    time.Second,
		},
		{
			name:    "negative timeout uses default watch interval",
			timeout: -time.Second,
			want:    custodianWatchInterval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := custodianDiagnosticInterval(tt.timeout); got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
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
	calls        []string
	failChecks   map[string]bool
	labelsSeen   []map[string]string
	subjectsSeen [][]*proto.Subject
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
	payload, ok := data.(*StandardizedResourcePayload)
	if !ok {
		return nil, errors.New("unexpected payload type")
	}

	f.calls = append(f.calls, fmt.Sprintf("%s|%s|%s|%s", payload.Check.Name, payload.Resource.ID, policyPath, payload.Assessment.Status))
	copiedLabels := map[string]string{}
	for k, v := range labels {
		copiedLabels[k] = v
	}
	f.labelsSeen = append(f.labelsSeen, copiedLabels)
	f.subjectsSeen = append(f.subjectsSeen, subjects)
	if f.failChecks[payload.Check.Name] {
		return nil, errors.New("forced evaluator error")
	}

	evidenceLabels := map[string]string{}
	for k, v := range labels {
		evidenceLabels[k] = v
	}
	return []*proto.Evidence{{UUID: fmt.Sprintf("%s-%s-%s", payload.Check.Name, payload.Resource.ID, policyPath), Labels: evidenceLabels}}, nil
}

type fakeAPIHelper struct {
	calls                int
	evidence             []*proto.Evidence
	err                  error
	subjectTemplates     []*proto.SubjectTemplate
	riskTemplateCalls    int
	riskTemplatePackages []string
}

func (f *fakeAPIHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	f.calls++
	f.evidence = append(f.evidence, evidence...)
	return f.err
}

func (f *fakeAPIHelper) UpsertRiskTemplates(ctx context.Context, packageName string, riskTemplates []*proto.RiskTemplate) error {
	f.riskTemplateCalls++
	f.riskTemplatePackages = append(f.riskTemplatePackages, packageName)
	return nil
}

func (f *fakeAPIHelper) UpsertSubjectTemplates(ctx context.Context, subjectTemplates []*proto.SubjectTemplate) error {
	f.subjectTemplates = append(f.subjectTemplates, subjectTemplates...)
	return nil
}

func TestEvalLoopBehavior(t *testing.T) {
	now := time.Now().UTC()

	t.Run("returns failure when a check execution fails but still submits successful evidence", func(t *testing.T) {
		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"inventory-aws-s3": {
				StartedAt: now,
				EndedAt:   now.Add(5 * time.Millisecond),
				ExitCode:  0,
				Resources: []interface{}{
					map[string]interface{}{"id": "1"},
					map[string]interface{}{"id": "2"},
				},
			},
			"inventory-aws-ec2": {
				StartedAt: now,
				EndedAt:   now.Add(5 * time.Millisecond),
				ExitCode:  0,
				Resources: []interface{}{map[string]interface{}{"id": "ec2-1"}},
			},
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
		if err == nil {
			t.Fatalf("expected eval failure when one check execution fails")
		}
		if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
			t.Fatalf("expected failure status, got %s", resp.GetStatus().String())
		}
		if len(executor.calls) != 4 {
			t.Fatalf("expected 4 executor calls, got %d", len(executor.calls))
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

		hasCompliantPayload := false
		hasNonCompliantPayload := false
		for _, call := range evaluator.calls {
			if strings.Contains(call, "check-a|1|") && strings.HasSuffix(call, "|non_compliant") {
				hasNonCompliantPayload = true
			}
			if strings.Contains(call, "check-a|2|") && strings.HasSuffix(call, "|compliant") {
				hasCompliantPayload = true
			}
		}
		if !hasCompliantPayload || !hasNonCompliantPayload {
			t.Fatalf("expected resource payloads to include compliant and non_compliant statuses, got %v", evaluator.calls)
		}
	})

	t.Run("fails when all policy evaluations fail", func(t *testing.T) {
		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"inventory-aws-s3": {
				StartedAt: now,
				EndedAt:   now,
				ExitCode:  0,
				Resources: []interface{}{map[string]interface{}{"id": "1"}},
			},
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
			"inventory-aws-s3": {
				StartedAt: now,
				EndedAt:   now,
				ExitCode:  0,
				Resources: []interface{}{map[string]interface{}{"id": "1"}},
			},
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
				PolicyLabels: map[string]string{
					"provider":          "custom-provider",
					"team":              "platform",
					"resource_id":       "must-not-leak",
					"assessment":        "must-not-leak",
					"assessment_status": "must-not-leak",
					"check_provider":    "must-not-leak",
				},
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
		if _, ok := labels["check_provider"]; ok {
			t.Fatalf("expected check_provider label to be removed, got labels: %v", labels)
		}
		if _, ok := labels["assessment_status"]; ok {
			t.Fatalf("expected assessment_status label to be removed, got labels: %v", labels)
		}
		if _, ok := labels["assessment"]; ok {
			t.Fatalf("expected assessment label to be removed, got labels: %v", labels)
		}
		if labels["resource_id"] != "1" {
			t.Fatalf("expected resource_id label to be set, got: %s", labels["resource_id"])
		}
		if len(apiHelper.evidence) == 0 {
			t.Fatalf("expected submitted evidence")
		}
		evidenceLabels := apiHelper.evidence[0].Labels
		if evidenceLabels["resource_id"] != "1" {
			t.Fatalf("expected submitted evidence resource_id label to be set, got: %s", evidenceLabels["resource_id"])
		}
		if len(evaluator.subjectsSeen) == 0 || len(evaluator.subjectsSeen[0]) == 0 {
			t.Fatalf("expected evaluator to capture subjects")
		}
		resourceSubject := evaluator.subjectsSeen[0][0]
		expectedResourceSubjectID := "cloud-custodian-resource/aws.s3/1"
		if resourceSubject.Identifier != expectedResourceSubjectID {
			t.Fatalf("expected escaped resource subject identifier %q, got %q", expectedResourceSubjectID, resourceSubject.Identifier)
		}
		if len(resourceSubject.Links) != 1 || resourceSubject.Links[0].Href != "1" {
			t.Fatalf("expected resource subject link to contain resource id, got %#v", resourceSubject.Links)
		}
		if len(resourceSubject.Props) != 1 || resourceSubject.Props[0].Name != "resource_id" || resourceSubject.Props[0].Value != "1" {
			t.Fatalf("expected resource_id subject prop, got %#v", resourceSubject.Props)
		}
	})

	t.Run("flushes evidence in bounded batches", func(t *testing.T) {
		baselineResources := make([]interface{}, 0, evidenceBatchSize+1)
		for i := 0; i < evidenceBatchSize+1; i++ {
			baselineResources = append(baselineResources, map[string]interface{}{
				"id": fmt.Sprintf("resource-%03d", i),
			})
		}

		executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
			"inventory-aws-s3": {
				StartedAt: now,
				EndedAt:   now,
				ExitCode:  0,
				Resources: baselineResources,
			},
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
		if err != nil {
			t.Fatalf("unexpected eval error: %v", err)
		}
		if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success status, got %s", resp.GetStatus().String())
		}
		if apiHelper.calls != 2 {
			t.Fatalf("expected CreateEvidence twice for batched submission, got %d", apiHelper.calls)
		}
		if len(apiHelper.evidence) != evidenceBatchSize+1 {
			t.Fatalf("expected %d evidences total, got %d", evidenceBatchSize+1, len(apiHelper.evidence))
		}
	})
}

func TestEvalFailsWhenInventoryBaselineErrors(t *testing.T) {
	now := time.Now().UTC()
	executor := &fakeExecutor{results: map[string]CustodianExecutionResult{
		"inventory-aws-s3": {
			StartedAt: now,
			EndedAt:   now.Add(5 * time.Millisecond),
			ExitCode:  1,
			Error:     "inventory execution failed",
			Err:       errors.New("inventory execution failed"),
			Resources: []interface{}{},
		},
		"check-a": {
			StartedAt: now,
			EndedAt:   now.Add(20 * time.Millisecond),
			ExitCode:  0,
			Resources: []interface{}{map[string]interface{}{"id": "1"}},
		},
	}}

	apiHelper := &fakeAPIHelper{}
	plugin := &CloudCustodianPlugin{
		Logger: hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{
			CheckTimeout: 30 * time.Second,
		},
		checks: []CustodianCheck{
			{Index: 0, Name: "check-a", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "check-a", "resource": "aws.s3"}},
		},
		executor:  executor,
		evaluator: &fakePolicyEvaluator{},
	}

	resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle-a"}}, apiHelper)
	if err == nil {
		t.Fatal("expected eval failure when inventory baseline errors")
	}
	if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("expected failure status, got %s", resp.GetStatus().String())
	}
	if apiHelper.calls != 0 {
		t.Fatalf("expected no evidence submitted when baseline unavailable, got %d calls", apiHelper.calls)
	}
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

func TestBuildResourceRecordCanonicalizesHostedZoneARN(t *testing.T) {
	plugin := &CloudCustodianPlugin{parsedConfig: &ParsedConfig{}}
	record := plugin.buildResourceRecord("aws.hostedzone", map[string]interface{}{
		"Id":   "/hostedzone/Z0819711ZIJQWWE99PT",
		"Name": "example.com.",
	})

	expected := "arn:aws:route53:::hostedzone/Z0819711ZIJQWWE99PT"
	if record.ID != expected {
		t.Fatalf("expected hosted zone arn %q, got %q", expected, record.ID)
	}
	if record.IdentityFields["arn"] != expected {
		t.Fatalf("expected identity fields to include synthesized arn, got %#v", record.IdentityFields)
	}
}

func TestBuildResourcePayloadsForCheckDisambiguatesDuplicateResourceIDs(t *testing.T) {
	plugin := &CloudCustodianPlugin{
		Logger: hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{
			ResourceIdentityFields: map[string][]string{
				"aws.s3": {"Name"},
			},
		},
	}

	resources := []interface{}{
		map[string]interface{}{
			"Name": "shared-name",
			"Arn":  "arn:aws:s3:::baseline-one",
		},
		map[string]interface{}{
			"Name": "shared-name",
			"Arn":  "arn:aws:s3:::baseline-two",
		},
	}
	baselineRecords := make([]ResourceRecord, 0, len(resources))
	for _, resource := range resources {
		baselineRecords = append(baselineRecords, plugin.buildResourceRecord("aws.s3", resource))
	}
	baseline := &InventoryBaseline{
		ResourceType: "aws.s3",
		Provider:     "aws",
		Records:      baselineRecords,
	}

	execution := CustodianExecutionResult{
		Resources: resources,
	}

	payloads := plugin.buildResourcePayloadsForCheck(
		CustodianCheck{Name: "duplicate-id-check", Resource: "aws.s3", Provider: "aws"},
		execution,
		baseline,
	)
	if len(payloads) != 2 {
		t.Fatalf("expected two payloads for duplicate resource IDs, got %d", len(payloads))
	}
	seenResourceIDs := make(map[string]struct{}, len(payloads))
	for _, payload := range payloads {
		if payload.Assessment.Status != "non_compliant" {
			t.Fatalf("expected duplicate matched resources to remain non_compliant, got %s", payload.Assessment.Status)
		}
		if payload.Resource.ID == "" {
			t.Fatalf("expected disambiguated resource ID to be non-empty, got empty ID in payload %#v", payload)
		}
		seenResourceIDs[payload.Resource.ID] = struct{}{}
	}
	if len(seenResourceIDs) != 2 {
		t.Fatalf("expected duplicate matched resources to have distinct resource IDs, got IDs %#v", seenResourceIDs)
	}
}

func TestResourceStringAtPath(t *testing.T) {
	tests := []struct {
		name     string
		resource interface{}
		path     string
		want     string
		ok       bool
	}{
		{
			name: "dotted path through nested string map",
			resource: map[string]interface{}{
				"metadata": map[string]interface{}{
					"uid": "abc-123",
				},
			},
			path: "metadata.uid",
			want: "abc-123",
			ok:   true,
		},
		{
			name: "dotted path through nested interface map",
			resource: map[interface{}]interface{}{
				"metadata": map[interface{}]interface{}{
					"uid": "xyz-789",
				},
			},
			path: "metadata.uid",
			want: "xyz-789",
			ok:   true,
		},
		{
			name: "json number conversion",
			resource: map[string]interface{}{
				"id": json.Number("42"),
			},
			path: "id",
			want: "42",
			ok:   true,
		},
		{
			name: "float64 conversion",
			resource: map[string]interface{}{
				"id": 42.5,
			},
			path: "id",
			want: "42.5",
			ok:   true,
		},
		{
			name: "float32 conversion",
			resource: map[string]interface{}{
				"id": float32(7.25),
			},
			path: "id",
			want: "7.25",
			ok:   true,
		},
		{
			name: "int conversion",
			resource: map[string]interface{}{
				"id": 17,
			},
			path: "id",
			want: "17",
			ok:   true,
		},
		{
			name: "int64 conversion",
			resource: map[string]interface{}{
				"id": int64(9001),
			},
			path: "id",
			want: "9001",
			ok:   true,
		},
		{
			name: "bool conversion",
			resource: map[string]interface{}{
				"id": true,
			},
			path: "id",
			want: "true",
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := resourceStringAtPath(tt.resource, tt.path)
			if ok != tt.ok {
				t.Fatalf("expected ok=%t, got %t", tt.ok, ok)
			}
			if got != tt.want {
				t.Fatalf("expected value %q, got %q", tt.want, got)
			}
		})
	}
}

func TestHashResourceUsesFullSHA256Digest(t *testing.T) {
	got := hashResource(map[string]interface{}{"id": "example", "name": "bucket"})
	if len(got) != 64 {
		t.Fatalf("expected full sha256 hex digest length 64, got %d (%q)", len(got), got)
	}
}

func TestFormatExecutionFailure(t *testing.T) {
	t.Run("uses both error string and wrapped error", func(t *testing.T) {
		err := formatExecutionFailure("check-a", CustodianExecutionResult{
			Error: "dryrun failed",
			Err:   errors.New("exit status 1"),
		})
		if !strings.Contains(err.Error(), "dryrun failed") {
			t.Fatalf("expected formatted error to include execution.Error, got %v", err)
		}
		if !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("expected formatted error to include execution.Err, got %v", err)
		}
	})

	t.Run("uses wrapped error when error string is empty", func(t *testing.T) {
		err := formatExecutionFailure("check-a", CustodianExecutionResult{
			Err: errors.New("exit status 1"),
		})
		if !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("expected formatted error to include execution.Err, got %v", err)
		}
	})
}

func TestInitUpsertsSubjectAndRiskTemplates(t *testing.T) {
	policyDir := t.TempDir()
	rego := `package compliance_framework.cloud_custodian_test

risk_templates := [{
	"name": "public_bucket",
	"title": "Public bucket",
	"statement": "A bucket is publicly accessible.",
	"likelihood_hint": "medium",
	"impact_hint": "high",
	"violation_ids": ["cloud.public_bucket"],
}]
`
	if err := os.WriteFile(filepath.Join(policyDir, "risk.rego"), []byte(rego), 0o600); err != nil {
		t.Fatalf("failed to write risk policy: %v", err)
	}

	apiHelper := &fakeAPIHelper{}
	plugin := &CloudCustodianPlugin{
		Logger:       hclog.NewNullLogger(),
		parsedConfig: &ParsedConfig{},
		checks: []CustodianCheck{
			{Index: 0, Name: "s3-check", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "s3-check", "resource": "aws.s3"}},
			{Index: 1, Name: "s3-check-2", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "s3-check-2", "resource": "aws.s3"}},
			{Index: 2, Name: "ec2-check", Resource: "aws.ec2", Provider: "aws", RawPolicy: map[string]interface{}{"name": "ec2-check", "resource": "aws.ec2"}},
		},
	}

	resp, err := plugin.Init(&proto.InitRequest{PolicyPaths: []string{policyDir}}, apiHelper)
	if err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected init response")
	}
	if len(apiHelper.subjectTemplates) != 2 {
		t.Fatalf("expected two unique subject templates, got %d", len(apiHelper.subjectTemplates))
	}
	if apiHelper.subjectTemplates[0].GetType() != proto.SubjectType_SUBJECT_TYPE_RESOURCE {
		t.Fatalf("expected resource subject template type")
	}
	if got := apiHelper.subjectTemplates[0].GetIdentityLabelKeys(); len(got) != 3 || got[2] != "resource_id" {
		t.Fatalf("expected resource_id identity label, got %v", got)
	}
	if apiHelper.riskTemplateCalls != 1 {
		t.Fatalf("expected one risk template upsert, got %d", apiHelper.riskTemplateCalls)
	}
	if len(apiHelper.riskTemplatePackages) != 1 || apiHelper.riskTemplatePackages[0] != "compliance_framework.cloud_custodian_test" {
		t.Fatalf("unexpected risk template packages: %v", apiHelper.riskTemplatePackages)
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

	err := plugin.dumpStandardizedPayload(&StandardizedResourcePayload{
		SchemaVersion: "v2",
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
		Resource: StandardizedResourceInfo{
			ID:       "resource-1",
			Type:     "aws.s3",
			Provider: "aws",
			Data:     map[string]interface{}{"id": "resource-1"},
		},
		Assessment: StandardizedAssessment{
			Status:          "compliant",
			InventoryStatus: "baseline",
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
	if !strings.Contains(string(content), "\"schema_version\": \"v2\"") {
		t.Fatalf("dumped payload file content does not look like standardized payload json")
	}
}
