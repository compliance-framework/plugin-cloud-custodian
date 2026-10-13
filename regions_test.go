package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

// fakeRegionalCustodianScript mimics c7n's output layout (c7n
// resources/aws.py initialize_policies): with one --region it writes
// <out>/<policy>/resources.json; with several regions, or "all", it writes
// <out>/<region>/<policy>/resources.json for each region. "all" expands to
// $FAKE_ENABLED_REGIONS. Resources come from $FIXTURES/<run>/<region>.json,
// where <run> is the base name of the -s output dir (the policy name is the
// same here); a missing fixture yields [].
const fakeRegionalCustodianScript = `#!/bin/sh
set -eu
out=""
regions=""
count=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -s) out="$2"; shift 2; continue ;;
    --region) regions="$regions $2"; count=$((count + 1)); shift 2; continue ;;
  esac
  shift
done
run=$(basename "$out")
case " $regions " in
  *" all "*) regions="$FAKE_ENABLED_REGIONS"; count=2 ;;
esac
for region in $regions; do
  if [ "$count" -gt 1 ]; then
    dir="$out/$region/$run"
  else
    dir="$out/$run"
  fi
  mkdir -p "$dir"
  if [ -f "$FIXTURES/$run/$region.json" ]; then
    cp "$FIXTURES/$run/$region.json" "$dir/resources.json"
  else
    printf '[]' > "$dir/resources.json"
  fi
done
`

func writeRegionFixtures(t *testing.T, fixtures map[string]map[string][]map[string]interface{}) string {
	t.Helper()
	root := t.TempDir()
	for run, byRegion := range fixtures {
		for region, resources := range byRegion {
			dir := filepath.Join(root, run)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir fixture dir: %v", err)
			}
			content, err := json.Marshal(resources)
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, region+".json"), content, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
		}
	}
	return root
}

func executeFakeRegional(t *testing.T, resource string, regions []string, fixtures map[string]map[string][]map[string]interface{}) CustodianExecutionResult {
	t.Helper()
	t.Setenv("FIXTURES", writeRegionFixtures(t, fixtures))
	t.Setenv("FAKE_ENABLED_REGIONS", "us-east-1 eu-west-1 ap-southeast-2")
	binary := writeExecutableScript(t, fakeRegionalCustodianScript)
	executor := &CommandCustodianExecutor{Logger: hclog.NewNullLogger()}
	result := executor.Execute(context.Background(), CustodianExecutionRequest{
		BinaryPath: binary,
		Check: CustodianCheck{
			Name:      "policy",
			Resource:  resource,
			Provider:  "aws",
			RawPolicy: map[string]interface{}{"name": "policy", "resource": resource},
		},
		Timeout:    5 * time.Second,
		OutputDir:  filepath.Join(t.TempDir(), "policy"),
		AWSRegions: regions,
	})
	if result.Err != nil {
		t.Fatalf("unexpected execution error: %v", result.Err)
	}
	return result
}

func resourceIDsWithRegions(result CustodianExecutionResult) []string {
	pairs := make([]string, 0, len(result.Resources))
	for i, resource := range result.Resources {
		id, _ := resourceStringAtPath(resource, "InstanceId")
		if id == "" {
			id, _ = resourceStringAtPath(resource, "Name")
		}
		region := ""
		if i < len(result.ResourceRegions) {
			region = result.ResourceRegions[i]
		}
		pairs = append(pairs, id+"@"+region)
	}
	slices.Sort(pairs)
	return pairs
}

func TestCommandCustodianExecutorReadsEveryRegion(t *testing.T) {
	fixtures := map[string]map[string][]map[string]interface{}{
		"policy": {
			"us-east-1":      {{"InstanceId": "i-use1"}},
			"eu-west-1":      {{"InstanceId": "i-euw1a"}, {"InstanceId": "i-euw1b"}},
			"ap-southeast-2": {{"InstanceId": "i-apse2"}},
		},
	}

	t.Run("one region keeps the single-region layout", func(t *testing.T) {
		result := executeFakeRegional(t, "aws.ec2", []string{"eu-west-1"}, fixtures)
		if got, want := resourceIDsWithRegions(result), []string{"i-euw1a@", "i-euw1b@"}; !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
		if result.ResourceRegions != nil {
			t.Fatalf("expected no path regions for the single-region layout, got %v", result.ResourceRegions)
		}
		if len(result.ResourcesPaths) != 1 || result.ResourcesPath != result.ResourcesPaths[0] {
			t.Fatalf("expected one resources path, got %q / %v", result.ResourcesPath, result.ResourcesPaths)
		}
	})

	t.Run("several regions are all read and tagged", func(t *testing.T) {
		result := executeFakeRegional(t, "aws.ec2", []string{"us-east-1", "eu-west-1"}, fixtures)
		want := []string{"i-euw1a@eu-west-1", "i-euw1b@eu-west-1", "i-use1@us-east-1"}
		if got := resourceIDsWithRegions(result); !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
		if len(result.ResourcesPaths) != 2 {
			t.Fatalf("expected two resources paths, got %v", result.ResourcesPaths)
		}
	})

	t.Run("all regions are read and tagged", func(t *testing.T) {
		result := executeFakeRegional(t, "aws.ec2", nil, fixtures)
		want := []string{"i-apse2@ap-southeast-2", "i-euw1a@eu-west-1", "i-euw1b@eu-west-1", "i-use1@us-east-1"}
		if got := resourceIDsWithRegions(result); !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
		if len(result.ResourcesPaths) != 3 {
			t.Fatalf("expected three resources paths, got %v", result.ResourcesPaths)
		}
	})

	t.Run("a resource returned by every region is kept once without a region", func(t *testing.T) {
		bucket := map[string]interface{}{"Name": "shared-bucket", "Location": map[string]interface{}{"LocationConstraint": "eu-west-1"}}
		result := executeFakeRegional(t, "aws.s3", nil, map[string]map[string][]map[string]interface{}{
			"policy": {
				"us-east-1":      {bucket},
				"eu-west-1":      {bucket, {"Name": "eu-only"}},
				"ap-southeast-2": {bucket},
			},
		})
		want := []string{"eu-only@eu-west-1", "shared-bucket@"}
		if got := resourceIDsWithRegions(result); !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
	})

	t.Run("duplicates within one region are kept", func(t *testing.T) {
		result := executeFakeRegional(t, "aws.ec2", []string{"us-east-1", "eu-west-1"}, map[string]map[string][]map[string]interface{}{
			"policy": {"eu-west-1": {{"InstanceId": "i-dup"}, {"InstanceId": "i-dup"}}},
		})
		want := []string{"i-dup@eu-west-1", "i-dup@eu-west-1"}
		if got := resourceIDsWithRegions(result); !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
	})

	t.Run("global resource types are not tagged with the run region", func(t *testing.T) {
		result := executeFakeRegional(t, "aws.iam-role", []string{"us-east-1", "eu-west-1"}, map[string]map[string][]map[string]interface{}{
			"policy": {"us-east-1": {{"Name": "role-a"}}},
		})
		if got, want := resourceIDsWithRegions(result), []string{"role-a@"}; !slices.Equal(got, want) {
			t.Fatalf("resources = %v, want %v", got, want)
		}
		if result.ResourceRegions != nil {
			t.Fatalf("expected no path regions for a global resource type, got %v", result.ResourceRegions)
		}
	})
}

func TestBuildExecutionRecordsPrefersRegionFromData(t *testing.T) {
	plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
	records := plugin.buildExecutionRecords("aws.ec2", CustodianExecutionResult{
		Resources: []interface{}{
			map[string]interface{}{"InstanceId": "i-1", "Region": "eu-central-1"},
			map[string]interface{}{"InstanceId": "i-2"},
		},
		ResourceRegions: []string{"us-east-1", "us-west-2"},
	})
	if records[0].Region != "eu-central-1" {
		t.Fatalf("expected the region in the data to win, got %q", records[0].Region)
	}
	if records[1].Region != "us-west-2" {
		t.Fatalf("expected the path region, got %q", records[1].Region)
	}
}

// TestEvalEvaluatesResourcesFromEveryRegion runs Eval end to end with the
// real executor against the fake c7n script: both the inventory baseline and
// the check must see every region, so a resource matched in a later region is
// non_compliant against the baseline instead of being dropped.
func TestEvalEvaluatesResourcesFromEveryRegion(t *testing.T) {
	fixtures := map[string]map[string][]map[string]interface{}{
		"inventory-aws-ec2": {
			"us-east-1":      {{"InstanceId": "i-use1"}},
			"eu-west-1":      {{"InstanceId": "i-euw1"}},
			"ap-southeast-2": {{"InstanceId": "i-apse2"}},
		},
		"001-ec2-check": {
			"eu-west-1":      {{"InstanceId": "i-euw1"}},
			"ap-southeast-2": {{"InstanceId": "i-apse2"}},
		},
	}

	tests := []struct {
		name    string
		regions []string
		want    []string // check|resource_id|status|region label
	}{
		{
			name:    "one region",
			regions: []string{"eu-west-1"},
			want:    []string{"ec2-check|i-euw1|non_compliant|"},
		},
		{
			name:    "several regions",
			regions: []string{"us-east-1", "eu-west-1"},
			want: []string{
				"ec2-check|i-euw1|non_compliant|eu-west-1",
				"ec2-check|i-use1|compliant|us-east-1",
			},
		},
		{
			name: "all regions",
			want: []string{
				"ec2-check|i-apse2|non_compliant|ap-southeast-2",
				"ec2-check|i-euw1|non_compliant|eu-west-1",
				"ec2-check|i-use1|compliant|us-east-1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FIXTURES", writeRegionFixtures(t, fixtures))
			t.Setenv("FAKE_ENABLED_REGIONS", "us-east-1 eu-west-1 ap-southeast-2")
			binary := writeExecutableScript(t, fakeRegionalCustodianScript)

			evaluator := &fakePolicyEvaluator{}
			apiHelper := &fakeAPIHelper{}
			plugin := &CloudCustodianPlugin{
				Logger: hclog.NewNullLogger(),
				parsedConfig: &ParsedConfig{
					CustodianBinary: binary,
					AWSRegions:      tt.regions,
					CheckTimeout:    10 * time.Second,
				},
				checks: []CustodianCheck{
					{Index: 0, Name: "ec2-check", Resource: "aws.ec2", Provider: "aws", RawPolicy: map[string]interface{}{"name": "ec2-check", "resource": "aws.ec2"}},
				},
				executor:  &CommandCustodianExecutor{Logger: hclog.NewNullLogger()},
				evaluator: evaluator,
			}

			resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle"}}, apiHelper)
			if err != nil {
				t.Fatalf("unexpected eval error: %v", err)
			}
			if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
				t.Fatalf("expected success, got %s", resp.GetStatus())
			}

			if len(evaluator.calls) != len(evaluator.labelsSeen) {
				t.Fatalf("evaluator recorded %d calls but %d label sets", len(evaluator.calls), len(evaluator.labelsSeen))
			}
			got := make([]string, 0, len(evaluator.labelsSeen))
			for i, labels := range evaluator.labelsSeen {
				// calls[i] is "check|resource_id|policy_path|status".
				call := evaluator.calls[i]
				status := call[strings.LastIndex(call, "|")+1:]
				got = append(got, strings.Join([]string{labels["check_name"], labels["resource_id"], status, labels["region"]}, "|"))
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("evaluated payloads = %v, want %v", got, tt.want)
			}
			if len(apiHelper.evidence) != len(tt.want) {
				t.Fatalf("expected %d evidences, got %d", len(tt.want), len(apiHelper.evidence))
			}
		})
	}
}
