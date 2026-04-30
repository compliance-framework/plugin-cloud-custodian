package main

import (
	"bytes"
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

func stubNetworkDiagnostics(
	t *testing.T,
	lookup func(context.Context, string) ([]string, error),
	tlsProbe func(context.Context, networkDiagnosticEndpoint) (tlsProbeResult, error),
) {
	t.Helper()
	originalLookup := lookupHost
	originalTLSProbe := tlsProbeEndpoint
	lookupHost = lookup
	tlsProbeEndpoint = tlsProbe
	t.Cleanup(func() {
		lookupHost = originalLookup
		tlsProbeEndpoint = originalTLSProbe
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
			PoliciesPath:                        "/tmp/policies.yaml",
			CustodianBinary:                     "custom-custodian",
			CustodianDebug:                      " true ",
			CustodianVerbose:                    " true ",
			CustodianAWSAPITrace:                " true ",
			CustodianNetworkDiag:                " true ",
			CustodianNetworkDiagnosticEndpoints: "https://vpce-123.backup.eu-west-1.vpce.amazonaws.com, vpce-456.ec2.eu-west-1.vpce.amazonaws.com",
			CustodianLogTail:                    " true ",
			CheckTimeoutSeconds:                 "45",
			AWSRegions:                          "us-east-1, eu-west-1 us-east-1",
			PreserveArtifacts:                   " true ",
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
		if !parsed.CustodianDebug {
			t.Fatalf("expected custodian debug to be enabled")
		}
		if !parsed.CustodianVerbose {
			t.Fatalf("expected custodian verbose to be enabled")
		}
		if !parsed.CustodianAWSAPITrace {
			t.Fatalf("expected custodian AWS API trace to be enabled")
		}
		if !parsed.CustodianNetworkDiag {
			t.Fatalf("expected custodian network diagnostics to be enabled")
		}
		if !parsed.CustodianLogTail {
			t.Fatalf("expected custodian log tailing to be enabled")
		}
		if !parsed.PreserveArtifacts {
			t.Fatalf("expected artifact preservation to be enabled")
		}
		if len(parsed.AWSRegions) != 2 || parsed.AWSRegions[0] != "us-east-1" || parsed.AWSRegions[1] != "eu-west-1" {
			t.Fatalf("unexpected aws regions: %#v", parsed.AWSRegions)
		}
		if len(parsed.CustodianNetworkDiagnosticEndpoints) != 2 || parsed.CustodianNetworkDiagnosticEndpoints[0] != "https://vpce-123.backup.eu-west-1.vpce.amazonaws.com" {
			t.Fatalf("unexpected network diagnostic endpoints: %#v", parsed.CustodianNetworkDiagnosticEndpoints)
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

	t.Run("reject invalid custodian debug boolean", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", CustodianDebug: "not-bool"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid custodian_debug")
		}
	})

	t.Run("reject invalid custodian verbose boolean", func(t *testing.T) {
		_, err := (&PluginConfig{PoliciesYAML: "x", CustodianVerbose: "not-bool"}).Parse()
		if err == nil {
			t.Fatalf("expected error for invalid custodian_verbose")
		}
	})

	t.Run("reject invalid diagnostic booleans", func(t *testing.T) {
		fields := []PluginConfig{
			{PoliciesYAML: "x", CustodianAWSAPITrace: "not-bool"},
			{PoliciesYAML: "x", CustodianNetworkDiag: "not-bool"},
			{PoliciesYAML: "x", CustodianLogTail: "not-bool"},
			{PoliciesYAML: "x", PreserveArtifacts: "not-bool"},
		}
		for _, cfg := range fields {
			_, err := cfg.Parse()
			if err == nil {
				t.Fatalf("expected error for invalid diagnostic boolean in %#v", cfg)
			}
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

	t.Run("network diagnostics failure prevents custodian execution", func(t *testing.T) {
		executedFile := filepath.Join(t.TempDir(), "executed.txt")
		t.Setenv("EXECUTED_FILE", executedFile)
		stubNetworkDiagnostics(
			t,
			func(ctx context.Context, host string) ([]string, error) {
				return []string{"10.0.0.10"}, nil
			},
			func(ctx context.Context, endpoint networkDiagnosticEndpoint) (tlsProbeResult, error) {
				if endpoint.Source != "aws-vpc-endpoint" {
					t.Fatalf("expected vpc endpoint source, got %s", endpoint.Source)
				}
				if endpoint.Host != "vpce-123.backup.eu-west-1.vpce.amazonaws.com" {
					t.Fatalf("unexpected endpoint host: %s", endpoint.Host)
				}
				return tlsProbeResult{}, errors.New("handshake failed")
			},
		)

		script := `#!/bin/sh
set -eu
touch "$EXECUTED_FILE"
`
		binary := writeExecutableScript(t, script)
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}

		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.backup-vault",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.backup-vault"},
			},
			Timeout:                    5 * time.Second,
			OutputDir:                  filepath.Join(t.TempDir(), "out"),
			NetworkDiagnostics:         true,
			NetworkDiagnosticEndpoints: []string{"https://vpce-123.backup.eu-west-1.vpce.amazonaws.com"},
		})

		if result.Err == nil {
			t.Fatalf("expected network diagnostics failure")
		}
		if !strings.Contains(result.Error, "aws endpoint network diagnostics failed") || !strings.Contains(result.Error, "handshake failed") {
			t.Fatalf("expected diagnostic failure detail, got: %s", result.Error)
		}
		if _, err := os.Stat(executedFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected custodian command not to execute, stat err: %v", err)
		}
	})

	t.Run("network diagnostics allow configured endpoints for unmapped resources", func(t *testing.T) {
		stubNetworkDiagnostics(
			t,
			func(ctx context.Context, host string) ([]string, error) {
				return []string{"10.0.0.10"}, nil
			},
			func(ctx context.Context, endpoint networkDiagnosticEndpoint) (tlsProbeResult, error) {
				if endpoint.Host != "vpce-123.example.eu-west-1.vpce.amazonaws.com" {
					t.Fatalf("unexpected endpoint host: %s", endpoint.Host)
				}
				return tlsProbeResult{RemoteAddr: "10.0.0.10:443", TLSVersion: "TLS1.3"}, nil
			},
		)

		script := `#!/bin/sh
set -eu
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
				Resource:  "aws.future-resource",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.future-resource"},
			},
			Timeout:                    5 * time.Second,
			OutputDir:                  filepath.Join(t.TempDir(), "out"),
			NetworkDiagnostics:         true,
			NetworkDiagnosticEndpoints: []string{"vpce-123.example.eu-west-1.vpce.amazonaws.com"},
		})

		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}
	})

	t.Run("network diagnostics stop when context is canceled", func(t *testing.T) {
		stubNetworkDiagnostics(
			t,
			func(ctx context.Context, host string) ([]string, error) {
				t.Fatalf("did not expect DNS probe after context cancellation, got host %s", host)
				return nil, nil
			},
			func(ctx context.Context, endpoint networkDiagnosticEndpoint) (tlsProbeResult, error) {
				t.Fatalf("did not expect TLS probe after context cancellation, got endpoint %#v", endpoint)
				return tlsProbeResult{}, nil
			},
		)
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := executor.runAWSEndpointDiagnostics(ctx, CustodianExecutionRequest{
			Check: CustodianCheck{
				Name:     "test-policy",
				Resource: "aws.backup-vault",
				Provider: "aws",
			},
			NetworkDiagnosticEndpoints: []string{"vpce-123.backup.eu-west-1.vpce.amazonaws.com"},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context canceled error, got %v", err)
		}
	})

	t.Run("network diagnostics skip service probes when regions are not concrete", func(t *testing.T) {
		stubNetworkDiagnostics(
			t,
			func(ctx context.Context, host string) ([]string, error) {
				t.Fatalf("did not expect DNS probe for non-concrete regions, got host %s", host)
				return nil, nil
			},
			func(ctx context.Context, endpoint networkDiagnosticEndpoint) (tlsProbeResult, error) {
				t.Fatalf("did not expect TLS probe for non-concrete regions, got endpoint %#v", endpoint)
				return tlsProbeResult{}, nil
			},
		)

		script := `#!/bin/sh
set -eu
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
				Resource:  "aws.backup-vault",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.backup-vault"},
			},
			Timeout:            5 * time.Second,
			OutputDir:          filepath.Join(t.TempDir(), "out"),
			AWSRegions:         []string{"all"},
			NetworkDiagnostics: true,
		})

		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}
	})

	t.Run("passes debug and verbose args", func(t *testing.T) {
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
			Timeout:   5 * time.Second,
			OutputDir: filepath.Join(t.TempDir(), "out"),
			Debug:     true,
			Verbose:   true,
		})
		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}

		argsContent, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatalf("failed to read args capture file: %v", err)
		}
		argsStr := string(argsContent)
		if !strings.Contains(argsStr, "run --debug -v --dryrun -s") {
			t.Fatalf("expected debug and verbose args before dry-run args, got: %s", argsStr)
		}
	})

	t.Run("injects AWS API trace environment", func(t *testing.T) {
		envFile := filepath.Join(t.TempDir(), "env.txt")
		t.Setenv("ENV_FILE", envFile)

		script := `#!/bin/sh
set -eu
printf '%s\n%s\n%s\n' "$PYTHONPATH" "$CCF_CUSTODIAN_AWS_API_TRACE_LOG" "$PYTHONUNBUFFERED" > "$ENV_FILE"
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
		outDir := filepath.Join(t.TempDir(), "out")
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}

		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.backup-vault",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.backup-vault"},
			},
			Timeout:     5 * time.Second,
			OutputDir:   outDir,
			AWSAPITrace: true,
		})
		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}

		content, err := os.ReadFile(envFile)
		if err != nil {
			t.Fatalf("failed to read env capture file: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(lines) != 3 {
			t.Fatalf("expected three env lines, got %q", string(content))
		}
		traceDir := strings.Split(lines[0], string(os.PathListSeparator))[0]
		if _, err := os.Stat(filepath.Join(traceDir, "sitecustomize.py")); err != nil {
			t.Fatalf("expected sitecustomize.py in trace dir: %v", err)
		}
		if lines[1] != filepath.Join(outDir, "custodian-aws-api-trace.jsonl") {
			t.Fatalf("unexpected trace log path: %s", lines[1])
		}
		if lines[2] != "1" {
			t.Fatalf("expected PYTHONUNBUFFERED=1, got %s", lines[2])
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

	t.Run("includes custodian log artifacts on failure", func(t *testing.T) {
		script := `#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-s" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$out/test-policy/us-east-1/test-policy"
printf 'custodian artifact detail\nlast api call before hang\n' > "$out/test-policy/us-east-1/test-policy/custodian-run.log"
exit 3
`
		binary := writeExecutableScript(t, script)
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}

		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.backup-vault",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.backup-vault"},
			},
			Timeout:   5 * time.Second,
			OutputDir: filepath.Join(t.TempDir(), "out"),
		})

		if result.Err == nil {
			t.Fatalf("expected execution failure")
		}
		if len(result.LogPaths) != 1 || !strings.HasSuffix(result.LogPaths[0], "custodian-run.log") {
			t.Fatalf("expected custodian log path to be captured, got %#v", result.LogPaths)
		}
		if !strings.Contains(result.Error, "custodian log tail from") {
			t.Fatalf("expected custodian log tail header in error, got: %s", result.Error)
		}
		if !strings.Contains(result.Error, "last api call before hang") {
			t.Fatalf("expected custodian log content in error, got: %s", result.Error)
		}
	})

	t.Run("does not read custodian log artifacts on success by default", func(t *testing.T) {
		script := `#!/bin/sh
set -eu
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-s" ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
mkdir -p "$out/test-policy/us-east-1/test-policy"
printf 'success log detail\n' > "$out/test-policy/us-east-1/test-policy/custodian-run.log"
printf '[]' > "$out/test-policy/resources.json"
`
		binary := writeExecutableScript(t, script)
		executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}

		result := executor.Execute(context.Background(), CustodianExecutionRequest{
			BinaryPath: binary,
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "aws.backup-vault",
				Provider:  "aws",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.backup-vault"},
			},
			Timeout:   5 * time.Second,
			OutputDir: filepath.Join(t.TempDir(), "out"),
		})

		if result.Err != nil {
			t.Fatalf("expected successful execution, got error: %v", result.Err)
		}
		if len(result.LogPaths) != 0 {
			t.Fatalf("expected successful execution not to walk log artifacts by default, got %#v", result.LogPaths)
		}
	})

	t.Run("finds custodian log artifacts in stable order", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "a", "custodian-run.log")
		second := filepath.Join(root, "z", "custodian-run.log")
		if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
			t.Fatalf("failed to create second log dir: %v", err)
		}
		if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
			t.Fatalf("failed to write second log: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
			t.Fatalf("failed to create first log dir: %v", err)
		}
		if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
			t.Fatalf("failed to write first log: %v", err)
		}

		logPaths, err := findCustodianRunLogs(root)
		if err != nil {
			t.Fatalf("unexpected log discovery error: %v", err)
		}
		want := []string{first, second}
		if strings.Join(logPaths, ",") != strings.Join(want, ",") {
			t.Fatalf("expected sorted log paths %#v, got %#v", want, logPaths)
		}
	})

	t.Run("ignores symlinked custodian log artifacts", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "outside.log")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatalf("failed to write target log: %v", err)
		}
		linkDir := filepath.Join(root, "nested")
		if err := os.MkdirAll(linkDir, 0o755); err != nil {
			t.Fatalf("failed to create symlink dir: %v", err)
		}
		link := filepath.Join(linkDir, "custodian-run.log")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}

		logPaths, err := findCustodianRunLogs(root)
		if err != nil {
			t.Fatalf("unexpected log discovery error: %v", err)
		}
		if len(logPaths) != 0 {
			t.Fatalf("expected symlinked custodian logs to be ignored, got %#v", logPaths)
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

func TestDiagnosticHelpers(t *testing.T) {
	t.Run("maps resource types to expected AWS endpoint hosts", func(t *testing.T) {
		hosts, known := awsEndpointHostsForCheck("aws.backup-vault", []string{"eu-west-1", "all", "eu-west-1"})
		if !known {
			t.Fatalf("expected backup-vault to be mapped")
		}
		want := []string{
			"sts.eu-west-1.amazonaws.com",
			"ec2.eu-west-1.amazonaws.com",
			"tagging.eu-west-1.amazonaws.com",
			"backup.eu-west-1.amazonaws.com",
		}
		if strings.Join(hosts, ",") != strings.Join(want, ",") {
			t.Fatalf("unexpected hosts: %#v", hosts)
		}
	})

	t.Run("uses global endpoints for global AWS services", func(t *testing.T) {
		hosts, known := awsEndpointHostsForCheck("aws.iam-role", []string{"eu-west-1", "us-east-1"})
		if !known {
			t.Fatalf("expected iam-role to be mapped")
		}
		want := []string{
			"sts.eu-west-1.amazonaws.com",
			"ec2.eu-west-1.amazonaws.com",
			"tagging.eu-west-1.amazonaws.com",
			"iam.amazonaws.com",
			"sts.us-east-1.amazonaws.com",
			"ec2.us-east-1.amazonaws.com",
			"tagging.us-east-1.amazonaws.com",
		}
		if strings.Join(hosts, ",") != strings.Join(want, ",") {
			t.Fatalf("unexpected hosts: %#v", hosts)
		}
		for _, host := range hosts {
			if strings.Contains(host, "iam.eu-west-1") || strings.Contains(host, "iam.us-east-1") {
				t.Fatalf("did not expect regional IAM endpoint host: %#v", hosts)
			}
		}
	})

	t.Run("uses china endpoint suffix for china regions", func(t *testing.T) {
		hosts, known := awsEndpointHostsForCheck("aws.iam-role", []string{"cn-north-1"})
		if !known {
			t.Fatalf("expected iam-role to be mapped")
		}
		want := []string{
			"sts.cn-north-1.amazonaws.com.cn",
			"ec2.cn-north-1.amazonaws.com.cn",
			"tagging.cn-north-1.amazonaws.com.cn",
			"iam.amazonaws.com.cn",
		}
		if strings.Join(hosts, ",") != strings.Join(want, ",") {
			t.Fatalf("unexpected china hosts: %#v", hosts)
		}
	})

	t.Run("uses gov endpoint host for gov global services", func(t *testing.T) {
		hosts, known := awsEndpointHostsForCheck("aws.iam-role", []string{"us-gov-west-1"})
		if !known {
			t.Fatalf("expected iam-role to be mapped")
		}
		want := []string{
			"sts.us-gov-west-1.amazonaws.com",
			"ec2.us-gov-west-1.amazonaws.com",
			"tagging.us-gov-west-1.amazonaws.com",
			"iam.us-gov.amazonaws.com",
		}
		if strings.Join(hosts, ",") != strings.Join(want, ",") {
			t.Fatalf("unexpected gov hosts: %#v", hosts)
		}
	})

	t.Run("includes configured vpc endpoint hosts", func(t *testing.T) {
		endpoints, known, err := awsDiagnosticEndpointsForCheck(
			"aws.backup-vault",
			nil,
			[]string{"https://vpce-123.backup.eu-west-1.vpce.amazonaws.com/path"},
		)
		if err != nil {
			t.Fatalf("unexpected endpoint parse error: %v", err)
		}
		if !known {
			t.Fatalf("expected backup-vault to be mapped")
		}
		if len(endpoints) != 1 {
			t.Fatalf("expected one configured endpoint, got %#v", endpoints)
		}
		if endpoints[0].Host != "vpce-123.backup.eu-west-1.vpce.amazonaws.com" {
			t.Fatalf("unexpected endpoint host: %#v", endpoints[0])
		}
		if endpoints[0].Port != "443" {
			t.Fatalf("unexpected endpoint port: %#v", endpoints[0])
		}
		if endpoints[0].Source != "aws-vpc-endpoint" {
			t.Fatalf("expected vpc endpoint source, got %#v", endpoints[0])
		}
	})

	t.Run("uses strict vpc endpoint suffix classification", func(t *testing.T) {
		if got := networkDiagnosticEndpointSource("evil.vpce.amazonaws.com.attacker.com"); got != "configured" {
			t.Fatalf("expected attacker suffix not to be classified as vpc endpoint, got %s", got)
		}
		if got := networkDiagnosticEndpointSource("vpce-123.backup.eu-west-1.vpce.amazonaws.com"); got != "aws-vpc-endpoint" {
			t.Fatalf("expected vpc endpoint classification, got %s", got)
		}
	})

	t.Run("rejects invalid configured endpoint ports", func(t *testing.T) {
		_, _, err := awsDiagnosticEndpointsForCheck("aws.backup-vault", nil, []string{"vpce-123.backup.eu-west-1.vpce.amazonaws.com:not-a-port"})
		if err == nil {
			t.Fatalf("expected invalid endpoint port error")
		}
		for _, endpoint := range []string{
			"vpce-123.backup.eu-west-1.vpce.amazonaws.com:0",
			"vpce-123.backup.eu-west-1.vpce.amazonaws.com:65536",
		} {
			if _, _, err := awsDiagnosticEndpointsForCheck("aws.backup-vault", nil, []string{endpoint}); err == nil {
				t.Fatalf("expected invalid endpoint port error for %s", endpoint)
			}
		}
	})

	t.Run("rejects non https configured endpoint schemes", func(t *testing.T) {
		_, _, err := awsDiagnosticEndpointsForCheck("aws.backup-vault", nil, []string{"http://vpce-123.backup.eu-west-1.vpce.amazonaws.com:80"})
		if err == nil {
			t.Fatalf("expected unsupported endpoint scheme error")
		}
		if !strings.Contains(err.Error(), "only https endpoints are supported") {
			t.Fatalf("expected unsupported scheme detail, got %v", err)
		}
	})

	t.Run("tls probe returns immediately when context is canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := defaultTLSProbeEndpoint(ctx, networkDiagnosticEndpoint{
			Host:       "example.invalid",
			Port:       "443",
			ServerName: "example.invalid",
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context canceled error, got %v", err)
		}
	})

	t.Run("does not info log empty socket snapshots", func(t *testing.T) {
		var logs bytes.Buffer
		executor := &CommandCustodianExecutor{Logger: hclog.New(&hclog.LoggerOptions{
			Name:   "test",
			Level:  hclog.Info,
			Output: &logs,
		})}

		executor.logCustodianProcessSockets(-1, "test-policy")
		if strings.Contains(logs.String(), "Custodian child socket snapshot") {
			t.Fatalf("expected no info socket snapshot log for empty sockets, got %q", logs.String())
		}
	})

	t.Run("reports unknown resource types", func(t *testing.T) {
		hosts, known := awsEndpointHostsForCheck("aws.not-yet-mapped", []string{"eu-west-1"})
		if known {
			t.Fatalf("expected resource to be unknown")
		}
		if len(hosts) != 0 {
			t.Fatalf("expected no hosts for unknown resource, got %#v", hosts)
		}
	})

	t.Run("allows configured endpoints for unknown resource types", func(t *testing.T) {
		endpoints, known, err := awsDiagnosticEndpointsForCheck("aws.not-yet-mapped", []string{"eu-west-1"}, []string{"vpce-123.example.eu-west-1.vpce.amazonaws.com"})
		if err != nil {
			t.Fatalf("unexpected endpoint parse error: %v", err)
		}
		if known {
			t.Fatalf("expected resource to remain unknown")
		}
		if len(endpoints) != 1 || endpoints[0].Host != "vpce-123.example.eu-west-1.vpce.amazonaws.com" {
			t.Fatalf("expected configured endpoint for unknown resource, got %#v", endpoints)
		}
	})

	t.Run("maps known policy resource services", func(t *testing.T) {
		resources := []string{
			"aws.app-elb",
			"aws.backup-plan",
			"aws.backup-vault",
			"aws.cache-cluster",
			"aws.distribution",
			"aws.dynamodb-table",
			"aws.ebs",
			"aws.ec2",
			"aws.ecs-service",
			"aws.efs",
			"aws.eks",
			"aws.firewall",
			"aws.hostedzone",
			"aws.iam-group",
			"aws.iam-policy",
			"aws.iam-role",
			"aws.iam-user",
			"aws.kms-key",
			"aws.lambda",
			"aws.log-group",
			"aws.rds",
			"aws.rds-cluster",
			"aws.s3",
			"aws.secrets-manager",
			"aws.sns",
			"aws.sqs",
			"aws.transfer-server",
			"aws.wafv2",
		}
		for _, resource := range resources {
			services, known := awsServicesForResource(resource)
			if !known {
				t.Fatalf("expected %s to be mapped", resource)
			}
			if len(services) == 0 {
				t.Fatalf("expected %s to have services", resource)
			}
		}
	})

	t.Run("decodes proc net tcp addresses", func(t *testing.T) {
		got := decodeProcNetAddress("0100007F:01BB", false)
		if got != "127.0.0.1:443" {
			t.Fatalf("unexpected decoded address: %s", got)
		}
		got = decodeProcNetAddress("00000000000000000000000001000000:01BB", true)
		if got != "[::1]:443" {
			t.Fatalf("unexpected decoded IPv6 address: %s", got)
		}
	})

	t.Run("upserts environment values", func(t *testing.T) {
		env := upsertEnv([]string{"A=1", "B=2"}, "A", "3")
		env = upsertEnv(env, "C", "4")
		got := strings.Join(env, ",")
		if got != "A=3,B=2,C=4" {
			t.Fatalf("unexpected env: %s", got)
		}
	})
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

func TestAWSResourceExplorerURL(t *testing.T) {
	tests := []struct {
		name     string
		payload  *StandardizedResourcePayload
		want     string
		wantLink bool
	}{
		{
			name: "regional aws arn uses arn region",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "arn:aws:ec2:eu-west-1:123456789012:instance/i-123",
					Provider: "aws",
					Region:   "us-east-1",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=eu-west-1#/search?query=id%3Aarn%3Aaws%3Aec2%3Aeu-west-1%3A123456789012%3Ainstance%2Fi-123",
			wantLink: true,
		},
		{
			name: "global aws arn falls back to us east 1",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "arn:aws:iam::123456789012:role/example",
					Provider: "aws",
					Region:   "global",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=us-east-1#/search?query=id%3Aarn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fexample",
			wantLink: true,
		},
		{
			name: "s3 bucket name uses bucket arn",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "example-bucket",
					Type:     "aws.s3",
					Provider: "aws",
					Region:   "us-west-2",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=us-west-2#/search?query=id%3Aarn%3Aaws%3As3%3A%3A%3Aexample-bucket",
			wantLink: true,
		},
		{
			name: "s3 uri uses bucket arn",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "s3://example-bucket/path/to/object",
					Type:     "aws.s3",
					Provider: "aws",
					Region:   "global",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=us-east-1#/search?query=id%3Aarn%3Aaws%3As3%3A%3A%3Aexample-bucket",
			wantLink: true,
		},
		{
			name: "s3 bucket in china region uses aws cn partition",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "example-bucket",
					Type:     "aws.s3",
					Provider: "aws",
					Region:   "cn-north-1",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=cn-north-1#/search?query=id%3Aarn%3Aaws-cn%3As3%3A%3A%3Aexample-bucket",
			wantLink: true,
		},
		{
			name: "s3 bucket in gov region uses aws us gov partition",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "example-bucket",
					Type:     "aws.s3",
					Provider: "aws",
					Region:   "us-gov-west-1",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=us-gov-west-1#/search?query=id%3Aarn%3Aaws-us-gov%3As3%3A%3A%3Aexample-bucket",
			wantLink: true,
		},
		{
			name: "s3 bucket uses account id arn partition hint",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:        "example-bucket",
					Type:      "aws.s3",
					Provider:  "aws",
					AccountID: "arn:aws-us-gov:iam::123456789012:root",
					Region:    "us-east-1",
				},
			},
			want:     "https://console.aws.amazon.com/resource-explorer/home?region=us-east-1#/search?query=id%3Aarn%3Aaws-us-gov%3As3%3A%3A%3Aexample-bucket",
			wantLink: true,
		},
		{
			name: "non arn non s3 resource id has no resource explorer link",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "bucket-name",
					Type:     "aws.ec2",
					Provider: "aws",
					Region:   "us-east-1",
				},
			},
		},
		{
			name: "invalid s3 bucket name has no resource explorer link",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "Not A Bucket",
					Type:     "aws.s3",
					Provider: "aws",
					Region:   "us-east-1",
				},
			},
		},
		{
			name: "non aws provider has no resource explorer link",
			payload: &StandardizedResourcePayload{
				Resource: StandardizedResourceInfo{
					ID:       "arn:azure:example",
					Provider: "azure",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := awsResourceExplorerURL(tt.payload)
			if got != tt.want {
				t.Fatalf("expected url %q, got %q", tt.want, got)
			}

			evidences := []*proto.Evidence{
				{
					UUID: "existing-link",
					Links: []*proto.Link{
						{
							Href: "https://example.com/evidence",
						},
					},
				},
				nil,
				{UUID: "empty-links"},
			}
			addResourceExplorerLinkToEvidence(evidences, tt.payload, hclog.NewNullLogger())

			hasExplorerLink := false
			for _, link := range evidences[0].Links {
				if link.GetText() == "Open in AWS Resource Explorer" {
					hasExplorerLink = true
					if link.Href != tt.want {
						t.Fatalf("expected resource explorer link %q, got %q", tt.want, link.Href)
					}
				}
			}
			if hasExplorerLink != tt.wantLink {
				t.Fatalf("expected resource explorer link presence %t, got %t in %#v", tt.wantLink, hasExplorerLink, evidences[0].Links)
			}
			if tt.wantLink {
				if len(evidences[0].Links) != 2 {
					t.Fatalf("expected resource explorer link to append after existing evidence link, got %#v", evidences[0].Links)
				}
				if len(evidences[2].Links) != 1 || evidences[2].Links[0].Href != tt.want {
					t.Fatalf("expected resource explorer link on evidence with no existing links, got %#v", evidences[2].Links)
				}
			} else {
				if len(evidences[0].Links) != 1 {
					t.Fatalf("expected non-aws/non-arn payload to preserve existing links only, got %#v", evidences[0].Links)
				}
				if len(evidences[2].Links) != 0 {
					t.Fatalf("expected non-aws/non-arn payload not to add links, got %#v", evidences[2].Links)
				}
			}
		})
	}

	t.Run("logs expected skipped link generation reason at warn", func(t *testing.T) {
		var logs bytes.Buffer
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   "test",
			Level:  hclog.Warn,
			Output: &logs,
		})
		evidences := []*proto.Evidence{{UUID: "empty-links"}}
		addResourceExplorerLinkToEvidence(evidences, &StandardizedResourcePayload{
			Check: StandardizedCheckInfo{Name: "check-a"},
			Resource: StandardizedResourceInfo{
				ID:       "Not A Bucket",
				Type:     "aws.s3",
				Provider: "aws",
			},
		}, logger)

		if len(evidences[0].Links) != 0 {
			t.Fatalf("expected no links to be added, got %#v", evidences[0].Links)
		}
		logOutput := logs.String()
		if !strings.Contains(logOutput, "Skipping AWS Resource Explorer evidence link generation") {
			t.Fatalf("expected skipped link warning, got %q", logOutput)
		}
		if !strings.Contains(logOutput, "aws.s3 resource id is not a valid S3 bucket name") {
			t.Fatalf("expected skipped link reason, got %q", logOutput)
		}
	})

	t.Run("does not warn for common non arn skipped link generation", func(t *testing.T) {
		var logs bytes.Buffer
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   "test",
			Level:  hclog.Warn,
			Output: &logs,
		})
		addResourceExplorerLinkToEvidence([]*proto.Evidence{{UUID: "empty-links"}}, &StandardizedResourcePayload{
			Check: StandardizedCheckInfo{Name: "check-a"},
			Resource: StandardizedResourceInfo{
				ID:       "instance-id",
				Type:     "aws.ec2",
				Provider: "aws",
			},
		}, logger)
		if logs.String() != "" {
			t.Fatalf("expected no warn log for common non-ARN skip, got %q", logs.String())
		}
	})
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
