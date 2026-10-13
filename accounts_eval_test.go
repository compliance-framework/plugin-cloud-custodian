package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata golden files")

var fixedRunTime = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

// accountFakeExecutor returns results keyed by "<account id>/<check name>",
// falling back to "<check name>", and records every request.
type accountFakeExecutor struct {
	calls   []CustodianExecutionRequest
	results map[string]CustodianExecutionResult
}

func (f *accountFakeExecutor) Execute(ctx context.Context, req CustodianExecutionRequest) CustodianExecutionResult {
	f.calls = append(f.calls, req)
	if result, ok := f.results[req.AccountID+"/"+req.Check.Name]; ok {
		return result
	}
	if result, ok := f.results[req.Check.Name]; ok {
		return result
	}
	return CustodianExecutionResult{StartedAt: fixedRunTime, EndedAt: fixedRunTime, ExitCode: 0, Resources: []interface{}{}}
}

type recordedEvaluation struct {
	PolicyPath string            `json:"policy_path"`
	Labels     map[string]string `json:"labels"`
	Subjects   []recordedSubject `json:"subjects"`
	Payload    json.RawMessage   `json:"payload"`
}

type recordedSubject struct {
	Type       string            `json:"type"`
	Identifier string            `json:"identifier"`
	Props      map[string]string `json:"props,omitempty"`
	Links      []string          `json:"links,omitempty"`
}

// recordingEvaluator records every evaluation and returns one evidence whose
// UUID, like policy-manager's, is seeded from the labels.
type recordingEvaluator struct {
	evaluations []recordedEvaluation
}

func (r *recordingEvaluator) Generate(
	ctx context.Context,
	policyPath string,
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventory []*proto.InventoryItem,
	actors []*proto.OriginActor,
	activities []*proto.Activity,
	policyData map[string]interface{},
	data interface{},
) ([]*proto.Evidence, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	recorded := recordedEvaluation{PolicyPath: policyPath, Labels: map[string]string{}, Payload: payload}
	for key, value := range labels {
		recorded.Labels[key] = value
	}
	for _, subject := range subjects {
		rs := recordedSubject{Type: subject.GetType().String(), Identifier: subject.GetIdentifier()}
		for _, prop := range subject.GetProps() {
			if rs.Props == nil {
				rs.Props = map[string]string{}
			}
			rs.Props[prop.GetName()] = prop.GetValue()
		}
		for _, link := range subject.GetLinks() {
			rs.Links = append(rs.Links, link.GetHref())
		}
		recorded.Subjects = append(recorded.Subjects, rs)
	}
	r.evaluations = append(r.evaluations, recorded)
	seed := map[string]string{"policy": policyPath}
	for key, value := range labels {
		seed[key] = value
	}
	return []*proto.Evidence{{UUID: stableHashValue(seed), Labels: recorded.Labels}}, nil
}

type recordedExecution struct {
	Check             string   `json:"check"`
	OutputDir         string   `json:"output_dir"`
	AWSRegions        []string `json:"aws_regions"`
	AccountID         string   `json:"account_id,omitempty"`
	AssumeRoleARN     string   `json:"assume_role_arn,omitempty"`
	ExternalID        string   `json:"external_id,omitempty"`
	SessionNameSuffix string   `json:"session_name_suffix,omitempty"`
	CachePath         string   `json:"cache_path,omitempty"`
}

type evalTranscript struct {
	Status              string               `json:"status"`
	Error               string               `json:"error"`
	Executions          []recordedExecution  `json:"executions"`
	Evaluations         []recordedEvaluation `json:"evaluations"`
	EvidenceUUIDs       []string             `json:"evidence_uuids"`
	CreateEvidenceCalls int                  `json:"create_evidence_calls"`
}

var executionRootPattern = regexp.MustCompile(`^.*ccf-cloud-custodian-[^/]+/`)

func runEvalTranscript(t *testing.T, plugin *CloudCustodianPlugin, executor *accountFakeExecutor, policyPaths []string) evalTranscript {
	t.Helper()
	evaluator := &recordingEvaluator{}
	apiHelper := &fakeAPIHelper{}
	plugin.executor = executor
	plugin.evaluator = evaluator
	if plugin.Logger == nil {
		plugin.Logger = hclog.NewNullLogger()
	}
	resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: policyPaths}, apiHelper)

	transcript := evalTranscript{
		Status:              resp.GetStatus().String(),
		Evaluations:         evaluator.evaluations,
		CreateEvidenceCalls: apiHelper.calls,
	}
	if err != nil {
		transcript.Error = err.Error()
	}
	for _, call := range executor.calls {
		transcript.Executions = append(transcript.Executions, recordedExecution{
			Check:             call.Check.Name,
			OutputDir:         executionRootPattern.ReplaceAllString(call.OutputDir, "<root>/"),
			AWSRegions:        call.AWSRegions,
			AccountID:         call.AccountID,
			AssumeRoleARN:     call.AssumeRoleARN,
			ExternalID:        call.ExternalID,
			SessionNameSuffix: call.SessionNameSuffix,
			CachePath:         call.CachePath,
		})
	}
	for _, evidence := range apiHelper.evidence {
		transcript.EvidenceUUIDs = append(transcript.EvidenceUUIDs, evidence.GetUUID())
	}
	return transcript
}

func fixedExecution(resources ...interface{}) CustodianExecutionResult {
	return CustodianExecutionResult{
		StartedAt:     fixedRunTime,
		EndedAt:       fixedRunTime.Add(1500 * time.Millisecond),
		ExitCode:      0,
		Stdout:        "custodian stdout",
		Resources:     resources,
		ArtifactPath:  "/artifacts/run",
		ResourcesPath: "/artifacts/run/resources.json",
	}
}

func goldenScenarioChecks() []CustodianCheck {
	return []CustodianCheck{
		{Index: 0, Name: "s3-public", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "s3-public", "resource": "aws.s3", "description": "public buckets"}},
		{Index: 1, Name: "broken", Resource: "unknown", Provider: "unknown", RawPolicy: map[string]interface{}{"value": "x"}, ParseErrors: []string{"policy entry at index 1 is not an object"}},
		{Index: 2, Name: "ec2-public", Resource: "aws.ec2", Provider: "aws", RawPolicy: map[string]interface{}{"name": "ec2-public", "resource": "aws.ec2"}},
		{Index: 3, Name: "rds-encryption", Resource: "aws.rds", Provider: "aws", RawPolicy: map[string]interface{}{"name": "rds-encryption", "resource": "aws.rds"}},
	}
}

func goldenScenarioResults() map[string]CustodianExecutionResult {
	failed := fixedExecution()
	failed.ExitCode = 1
	failed.Stderr = "Traceback: AccessDenied"
	failed.Error = "custodian execution failed: exit status 1; Traceback: AccessDenied"
	failed.Errors = []string{"custodian execution failed: exit status 1", "Traceback: AccessDenied"}
	failed.Err = errors.New("custodian execution failed: exit status 1")
	return map[string]CustodianExecutionResult{
		"inventory-aws-s3": fixedExecution(
			map[string]interface{}{"Name": "bucket-a", "c7n:region": "us-east-1"},
			map[string]interface{}{"Name": "bucket-b"},
		),
		"inventory-aws-ec2": fixedExecution(
			map[string]interface{}{"InstanceId": "i-1", "OwnerId": "999999999999", "Region": "eu-west-1"},
		),
		"inventory-aws-rds": fixedExecution(
			map[string]interface{}{"DBInstanceArn": "arn:aws:rds:us-east-1:999999999999:db:main"},
		),
		"s3-public":      fixedExecution(map[string]interface{}{"Name": "bucket-b", "c7n:MatchedFilters": []interface{}{"Acl"}}),
		"ec2-public":     fixedExecution(),
		"rds-encryption": failed,
	}
}

// TestEvalWithoutAccountsMatchesGolden pins the single-account behaviour: the
// golden file was recorded before accounts mode existed, so any change to the
// requests, labels, subjects, payloads, evidence or error fails here.
func TestEvalWithoutAccountsMatchesGolden(t *testing.T) {
	plugin := &CloudCustodianPlugin{
		parsedConfig: &ParsedConfig{
			PolicyLabels: map[string]string{"team": "platform", "account_id": "from-policy-labels", "account_name": "from-policy-labels"},
			AWSRegions:   []string{"us-east-1", "eu-west-1"},
			CheckTimeout: 30 * time.Second,
		},
		checks: goldenScenarioChecks(),
	}
	transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{results: goldenScenarioResults()}, []string{"bundle-a", "bundle-b"})

	got, err := json.MarshalIndent(transcript, "", "  ")
	if err != nil {
		t.Fatalf("marshal transcript: %v", err)
	}
	goldenPath := filepath.Join("testdata", "eval_without_accounts.golden.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, append(got, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update-golden to create it): %v", err)
	}
	if string(append(got, '\n')) != string(want) {
		t.Fatalf("single-account Eval output changed; diff %s against:\n%s", goldenPath, got)
	}
	if len(transcript.Evaluations) == 0 || transcript.Error == "" {
		t.Fatalf("the golden scenario must exercise evaluations and the failure path")
	}
}
