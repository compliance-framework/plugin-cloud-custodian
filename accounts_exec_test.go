package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

// captureCustodianScript records its arguments (one per line) and the account
// environment, then writes an empty resources.json like c7n does.
const captureCustodianScript = `#!/bin/sh
set -eu
: > "$CAPTURE_DIR/args"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "$CAPTURE_DIR/args"
done
printf '%s\n%s\n' "${C7N_SESSION_SUFFIX-<unset>}" "${CCF_CUSTODIAN_ACCOUNT_ID-<unset>}" > "$CAPTURE_DIR/env"
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

type capturedCustodianRun struct {
	args          []string
	sessionSuffix string
	accountID     string
}

func runCapturedCustodian(t *testing.T, logger hclog.Logger, req CustodianExecutionRequest) (CustodianExecutionResult, capturedCustodianRun) {
	t.Helper()
	captureDir := t.TempDir()
	t.Setenv("CAPTURE_DIR", captureDir)
	// The parent environment must not leak the account variables into the
	// single-account assertions.
	for _, key := range []string{"C7N_SESSION_SUFFIX", "CCF_CUSTODIAN_ACCOUNT_ID"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
	if req.BinaryPath == "" {
		req.BinaryPath = writeExecutableScript(t, captureCustodianScript)
	}
	if req.Check.Name == "" {
		req.Check = CustodianCheck{
			Name:      "test-policy",
			Resource:  "aws.s3",
			Provider:  "aws",
			RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "aws.s3"},
		}
	}
	if req.Timeout == 0 {
		req.Timeout = 5 * time.Second
	}
	if req.OutputDir == "" {
		req.OutputDir = filepath.Join(t.TempDir(), "out")
	}
	result := (&CommandCustodianExecutor{Logger: logger}).Execute(context.Background(), req)

	var run capturedCustodianRun
	if content, err := os.ReadFile(filepath.Join(captureDir, "args")); err == nil {
		run.args = strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	}
	if content, err := os.ReadFile(filepath.Join(captureDir, "env")); err == nil {
		lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		if len(lines) == 2 {
			run.sessionSuffix, run.accountID = lines[0], lines[1]
		}
	}
	return result, run
}

// argValues returns the value after every occurrence of flag.
func argValues(args []string, flag string) []string {
	values := make([]string, 0)
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			values = append(values, args[i+1])
		}
	}
	return values
}

func TestCommandCustodianExecutorAccountFlags(t *testing.T) {
	const roleARN = "arn:aws:iam::222222222222:role/ccf-audit"

	t.Run("role account assumes the role with its external ID, cache and session suffix", func(t *testing.T) {
		result, run := runCapturedCustodian(t, hclog.NewNullLogger(), CustodianExecutionRequest{
			AWSRegions:        []string{"eu-west-1", "us-east-1"},
			AccountID:         "222222222222",
			AssumeRoleARN:     roleARN,
			ExternalID:        "external-id-value",
			SessionNameSuffix: "ccf",
			CachePath:         custodianAccountCachePath("222222222222"),
		})
		if result.Err != nil {
			t.Fatalf("unexpected execution error: %v", result.Err)
		}
		if got := argValues(run.args, "--assume"); !reflect.DeepEqual(got, []string{roleARN}) {
			t.Fatalf("expected --assume %s, got %v in %q", roleARN, got, run.args)
		}
		if got := argValues(run.args, "--external-id"); !reflect.DeepEqual(got, []string{"external-id-value"}) {
			t.Fatalf("expected one --external-id, got %v in %q", got, run.args)
		}
		wantCache := filepath.Join(os.TempDir(), "cloud-custodian-222222222222.cache")
		if got := argValues(run.args, "--cache"); !reflect.DeepEqual(got, []string{wantCache}) {
			t.Fatalf("expected --cache %s, got %v", wantCache, got)
		}
		if got := argValues(run.args, "--region"); !reflect.DeepEqual(got, []string{"eu-west-1", "us-east-1"}) {
			t.Fatalf("expected the account's regions, got %v", got)
		}
		if run.args[len(run.args)-5] != filepath.Join(result.ArtifactPath, "policy.yaml") {
			// The policy file stays the positional argument before the regions.
			t.Fatalf("expected policy.yaml before the regions, got %q", run.args)
		}
		if run.sessionSuffix != "ccf" {
			t.Fatalf("expected C7N_SESSION_SUFFIX=ccf, got %q", run.sessionSuffix)
		}
		if run.accountID != "222222222222" {
			t.Fatalf("expected CCF_CUSTODIAN_ACCOUNT_ID=222222222222, got %q", run.accountID)
		}
	})

	t.Run("role account without an external ID passes no --external-id", func(t *testing.T) {
		_, run := runCapturedCustodian(t, hclog.NewNullLogger(), CustodianExecutionRequest{
			AccountID:     "222222222222",
			AssumeRoleARN: roleARN,
		})
		if got := argValues(run.args, "--assume"); !reflect.DeepEqual(got, []string{roleARN}) {
			t.Fatalf("expected --assume, got %q", run.args)
		}
		if slices.Contains(run.args, "--external-id") {
			t.Fatalf("expected no --external-id, got %q", run.args)
		}
	})

	t.Run("ambient account keeps today's credential flags", func(t *testing.T) {
		_, run := runCapturedCustodian(t, hclog.NewNullLogger(), CustodianExecutionRequest{
			AccountID:         "111111111111",
			SessionNameSuffix: "ccf",
			CachePath:         custodianAccountCachePath("111111111111"),
		})
		if slices.Contains(run.args, "--assume") || slices.Contains(run.args, "--external-id") {
			t.Fatalf("ambient account must not assume a role, got %q", run.args)
		}
		if got := argValues(run.args, "--cache"); !reflect.DeepEqual(got, []string{custodianAccountCachePath("111111111111")}) {
			t.Fatalf("expected the account cache, got %v", got)
		}
		if run.accountID != "111111111111" {
			t.Fatalf("expected CCF_CUSTODIAN_ACCOUNT_ID for the ambient account, got %q", run.accountID)
		}
	})

	t.Run("no account fields keep today's command line and environment", func(t *testing.T) {
		_, run := runCapturedCustodian(t, hclog.NewNullLogger(), CustodianExecutionRequest{})
		outDir := run.args[3]
		want := []string{"run", "--dryrun", "-s", outDir, "--cache", custodianCachePath(), filepath.Join(outDir, "policy.yaml"), "--region", "all"}
		if !reflect.DeepEqual(run.args, want) {
			t.Fatalf("command line changed\n got: %q\nwant: %q", run.args, want)
		}
		if run.sessionSuffix != "<unset>" || run.accountID != "<unset>" {
			t.Fatalf("expected no account environment, got suffix=%q account=%q", run.sessionSuffix, run.accountID)
		}
	})

	t.Run("non-AWS checks never get --assume", func(t *testing.T) {
		_, run := runCapturedCustodian(t, hclog.NewNullLogger(), CustodianExecutionRequest{
			Check: CustodianCheck{
				Name:      "test-policy",
				Resource:  "gcp.instance",
				Provider:  "gcp",
				RawPolicy: map[string]interface{}{"name": "test-policy", "resource": "gcp.instance"},
			},
			AccountID:     "222222222222",
			AssumeRoleARN: roleARN,
			ExternalID:    "external-id-value",
		})
		if slices.Contains(run.args, "--assume") || slices.Contains(run.args, "--external-id") {
			t.Fatalf("expected no AWS role flags for a gcp check, got %q", run.args)
		}
	})
}

func TestCommandCustodianExecutorRedactsExternalID(t *testing.T) {
	const externalID = "very-secret-external-id"

	t.Run("in the executed command log", func(t *testing.T) {
		var logs bytes.Buffer
		logger := hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Trace})
		_, run := runCapturedCustodian(t, logger, CustodianExecutionRequest{
			AccountID:     "222222222222",
			AssumeRoleARN: "arn:aws:iam::222222222222:role/ccf-audit",
			ExternalID:    externalID,
		})
		if got := argValues(run.args, "--external-id"); !reflect.DeepEqual(got, []string{externalID}) {
			t.Fatalf("custodian must still receive the external ID, got %q", run.args)
		}
		if strings.Contains(logs.String(), externalID) {
			t.Fatalf("logs contain the external ID:\n%s", logs.String())
		}
		if !strings.Contains(logs.String(), `"--external-id", "`+redactedArgValue+`"`) {
			t.Fatalf("expected the redacted flag in the command log:\n%s", logs.String())
		}
	})

	t.Run("in the failed start log", func(t *testing.T) {
		var logs bytes.Buffer
		logger := hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Trace})
		result, _ := runCapturedCustodian(t, logger, CustodianExecutionRequest{
			BinaryPath:    filepath.Join(t.TempDir(), "missing-custodian"),
			AccountID:     "222222222222",
			AssumeRoleARN: "arn:aws:iam::222222222222:role/ccf-audit",
			ExternalID:    externalID,
		})
		if result.Err == nil {
			t.Fatalf("expected a start failure")
		}
		if !strings.Contains(logs.String(), "Failed to start custodian command process") {
			t.Fatalf("expected the failed start log:\n%s", logs.String())
		}
		if strings.Contains(logs.String(), externalID) || strings.Contains(result.Error, externalID) {
			t.Fatalf("the external ID leaked:\nlogs: %s\nerror: %s", logs.String(), result.Error)
		}
	})
}

func TestRedactCustodianArgs(t *testing.T) {
	args := []string{"run", "--assume", "arn:aws:iam::222222222222:role/r", "--external-id", "secret", "--external-id=other-secret", "policy.yaml", "--external-id"}
	got := redactCustodianArgs(args)
	want := []string{"run", "--assume", "arn:aws:iam::222222222222:role/r", "--external-id", redactedArgValue, "--external-id=" + redactedArgValue, "policy.yaml", "--external-id"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected redaction\n got: %q\nwant: %q", got, want)
	}
	if args[4] != "secret" {
		t.Fatalf("redaction must not modify the executed arguments")
	}
}

func TestCustodianAWSAPITraceIncludesAccountID(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	traceDir, traceLogPath, err := setupCustodianAWSAPITrace(t.TempDir())
	if err != nil {
		t.Fatalf("setup trace: %v", err)
	}

	writeRecord := func(accountID string) map[string]interface{} {
		t.Helper()
		if err := os.WriteFile(traceLogPath, nil, 0o600); err != nil {
			t.Fatalf("reset trace log: %v", err)
		}
		cmd := exec.Command(python, "-c", "import sitecustomize; sitecustomize._ccf_trace_write({'event': 'test'})")
		cmd.Env = append(os.Environ(), "PYTHONPATH="+traceDir, "CCF_CUSTODIAN_AWS_API_TRACE_LOG="+traceLogPath)
		if accountID != "" {
			cmd.Env = append(cmd.Env, "CCF_CUSTODIAN_ACCOUNT_ID="+accountID)
		} else {
			cmd.Env = append(cmd.Env, "CCF_CUSTODIAN_ACCOUNT_ID=")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run trace shim: %v\n%s", err, out)
		}
		content, err := os.ReadFile(traceLogPath)
		if err != nil {
			t.Fatalf("read trace log: %v", err)
		}
		var record map[string]interface{}
		for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
			var candidate map[string]interface{}
			if err := json.Unmarshal([]byte(line), &candidate); err != nil {
				t.Fatalf("parse trace line %q: %v", line, err)
			}
			if candidate["event"] == "test" {
				record = candidate
			}
		}
		if record == nil {
			t.Fatalf("trace record not written:\n%s", content)
		}
		return record
	}

	if got := writeRecord("222222222222")["account_id"]; got != "222222222222" {
		t.Fatalf("expected account_id in the trace record, got %v", got)
	}
	if _, ok := writeRecord("")["account_id"]; ok {
		t.Fatalf("expected no account_id outside accounts mode")
	}
}
