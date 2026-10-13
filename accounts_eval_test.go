package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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
	return []*proto.Evidence{{UUID: stableHashValue(seed), Labels: maps.Clone(recorded.Labels)}}, nil
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
	EvidenceLabels      []map[string]string  `json:"-"`
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
		transcript.EvidenceLabels = append(transcript.EvidenceLabels, evidence.GetLabels())
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

	got := formatEvalTranscript(t, transcript)
	goldenPath := filepath.Join("testdata", "eval_without_accounts.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update-golden to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("single-account Eval output changed; diff %s against:\n%s", goldenPath, got)
	}
	if len(transcript.Evaluations) == 0 || transcript.Error == "" {
		t.Fatalf("the golden scenario must exercise evaluations and the failure path")
	}
}

// formatEvalTranscript writes one JSON value per line, so the golden file stays
// short and a change shows up as the line of the item that changed.
func formatEvalTranscript(t *testing.T, transcript evalTranscript) []byte {
	t.Helper()
	var out bytes.Buffer
	line := func(prefix string, value interface{}) {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal %s: %v", prefix, err)
		}
		out.WriteString(prefix)
		out.Write(encoded)
		out.WriteByte('\n')
	}
	line("status: ", transcript.Status)
	line("error: ", transcript.Error)
	line("create_evidence_calls: ", transcript.CreateEvidenceCalls)
	for _, execution := range transcript.Executions {
		line("execution: ", execution)
	}
	for _, evaluation := range transcript.Evaluations {
		line("evaluation: ", evaluation)
	}
	for _, uuid := range transcript.EvidenceUUIDs {
		line("evidence: ", uuid)
	}
	return out.Bytes()
}

func accountsPlugin(accounts []AWSAccount, regions []string, checks []CustodianCheck) *CloudCustodianPlugin {
	return &CloudCustodianPlugin{
		parsedConfig: &ParsedConfig{
			PolicyLabels:         map[string]string{"team": "platform", "account_id": "from-policy-labels", "account_name": "from-policy-labels"},
			AWSRegions:           regions,
			CheckTimeout:         30 * time.Second,
			AWSAccounts:          accounts,
			AWSSessionNameSuffix: "ccf",
		},
		checks: checks,
	}
}

func twoTypeChecks() []CustodianCheck {
	return []CustodianCheck{
		{Index: 0, Name: "s3-public", Resource: "aws.s3", Provider: "aws", RawPolicy: map[string]interface{}{"name": "s3-public", "resource": "aws.s3"}},
		{Index: 1, Name: "ec2-public", Resource: "aws.ec2", Provider: "aws", RawPolicy: map[string]interface{}{"name": "ec2-public", "resource": "aws.ec2"}},
	}
}

var (
	hubAccount  = AWSAccount{ID: "111111111111", Name: "hub", UseAmbientCredentials: true, Regions: []string{"eu-west-1"}}
	prodAccount = AWSAccount{ID: "222222222222", Name: "prod", RoleARN: "arn:aws:iam::222222222222:role/ccf-audit", ExternalID: "prod-external-id"}
	devAccount  = AWSAccount{ID: "333333333333", RoleARN: "arn:aws:iam::333333333333:role/ccf-audit"}
)

func TestEvalAccountsRunsEachAccountWithItsCredentials(t *testing.T) {
	var logs bytes.Buffer
	plugin := accountsPlugin([]AWSAccount{hubAccount, prodAccount}, []string{"us-east-1"}, twoTypeChecks())
	plugin.Logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Trace})
	transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{}, []string{"bundle"})

	// Two baselines and two checks per account, one account after the other.
	want := []recordedExecution{
		{Check: "inventory-aws-ec2", OutputDir: "<root>/acct-111111111111/inventory-aws-ec2", AWSRegions: []string{"eu-west-1"}, AccountID: "111111111111", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("111111111111")},
		{Check: "inventory-aws-s3", OutputDir: "<root>/acct-111111111111/inventory-aws-s3", AWSRegions: []string{"eu-west-1"}, AccountID: "111111111111", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("111111111111")},
		{Check: "s3-public", OutputDir: "<root>/acct-111111111111/001-s3-public", AWSRegions: []string{"eu-west-1"}, AccountID: "111111111111", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("111111111111")},
		{Check: "ec2-public", OutputDir: "<root>/acct-111111111111/002-ec2-public", AWSRegions: []string{"eu-west-1"}, AccountID: "111111111111", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("111111111111")},
		{Check: "inventory-aws-ec2", OutputDir: "<root>/acct-222222222222/inventory-aws-ec2", AWSRegions: []string{"us-east-1"}, AccountID: "222222222222", AssumeRoleARN: prodAccount.RoleARN, ExternalID: "prod-external-id", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("222222222222")},
		{Check: "inventory-aws-s3", OutputDir: "<root>/acct-222222222222/inventory-aws-s3", AWSRegions: []string{"us-east-1"}, AccountID: "222222222222", AssumeRoleARN: prodAccount.RoleARN, ExternalID: "prod-external-id", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("222222222222")},
		{Check: "s3-public", OutputDir: "<root>/acct-222222222222/001-s3-public", AWSRegions: []string{"us-east-1"}, AccountID: "222222222222", AssumeRoleARN: prodAccount.RoleARN, ExternalID: "prod-external-id", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("222222222222")},
		{Check: "ec2-public", OutputDir: "<root>/acct-222222222222/002-ec2-public", AWSRegions: []string{"us-east-1"}, AccountID: "222222222222", AssumeRoleARN: prodAccount.RoleARN, ExternalID: "prod-external-id", SessionNameSuffix: "ccf", CachePath: custodianAccountCachePath("222222222222")},
	}
	if !reflect.DeepEqual(transcript.Executions, want) {
		t.Fatalf("unexpected executions\n got: %+v\nwant: %+v", transcript.Executions, want)
	}
	if strings.Contains(logs.String(), "Scanning all regions") {
		t.Fatalf("no account scans all regions, but got the warning:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "prod-external-id") {
		t.Fatalf("logs contain an external ID")
	}
}

func TestEvalAccountsWarnsWhenScanningAllRegions(t *testing.T) {
	var logs bytes.Buffer
	plugin := accountsPlugin([]AWSAccount{prodAccount, hubAccount, devAccount}, nil, twoTypeChecks()[:1])
	plugin.parsedConfig.AWSAccounts[2].Regions = []string{"all"}
	plugin.Logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn, JSONFormat: true})
	transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{results: map[string]CustodianExecutionResult{
		"inventory-aws-s3": fixedExecution(map[string]interface{}{"Name": "bucket"}),
	}}, []string{"bundle"})

	warned := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if strings.HasPrefix(entry["@message"].(string), "Scanning all regions of an AWS account") {
			warned[entry["account_id"].(string)] = true
		}
	}
	// prod inherits the empty aws_regions (all), dev sets "all", hub sets eu-west-1.
	if !reflect.DeepEqual(warned, map[string]bool{"222222222222": true, "333333333333": true}) {
		t.Fatalf("expected the all-regions warning for prod and dev only, got %v", warned)
	}
	if transcript.Status != proto.ExecutionStatus_SUCCESS.String() {
		t.Fatalf("the all-regions caveat only warns, got %s: %s", transcript.Status, transcript.Error)
	}
	if got := transcript.Executions[0].AWSRegions; len(got) != 0 {
		t.Fatalf("an account without regions must inherit the empty aws_regions (c7n's all), got %v", got)
	}
}

func TestEvalAccountsLabelsPayloadAndSubject(t *testing.T) {
	plugin := accountsPlugin([]AWSAccount{prodAccount, devAccount}, []string{"us-east-1"}, twoTypeChecks()[:1])
	results := map[string]CustodianExecutionResult{
		// The data names another account, which the scanned account overrides.
		"inventory-aws-s3": fixedExecution(map[string]interface{}{"Name": "shared-name", "AccountId": "999999999999"}),
	}
	transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{results: results}, []string{"bundle"})
	if transcript.Status != proto.ExecutionStatus_SUCCESS.String() {
		t.Fatalf("expected success, got %s: %s", transcript.Status, transcript.Error)
	}
	if len(transcript.Evaluations) != 2 {
		t.Fatalf("expected one evaluation per account, got %d", len(transcript.Evaluations))
	}

	for i, account := range []AWSAccount{prodAccount, devAccount} {
		evaluation := transcript.Evaluations[i]
		if evaluation.Labels["account_id"] != account.ID {
			t.Fatalf("expected account_id %s, got %q", account.ID, evaluation.Labels["account_id"])
		}
		if name, seeded := evaluation.Labels["account_name"]; seeded {
			t.Fatalf("account_name must not seed the evidence UUID, got %q", name)
		}
		// Added after the UUID; an account without a name gets none (not the policy_labels one).
		if name := transcript.EvidenceLabels[i]["account_name"]; name != account.Name {
			t.Fatalf("expected the evidence label account_name %q, got %q", account.Name, name)
		}
		if evaluation.Labels["team"] != "platform" {
			t.Fatalf("other policy_labels must be kept, got %v", evaluation.Labels)
		}

		var payload StandardizedResourcePayload
		if err := json.Unmarshal(evaluation.Payload, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Account == nil || payload.Account.ID != account.ID || payload.Account.Name != account.Name {
			t.Fatalf("expected payload account %+v, got %+v", account, payload.Account)
		}
		if payload.Resource.AccountID != account.ID {
			t.Fatalf("expected resource.account_id %s, got %s", account.ID, payload.Resource.AccountID)
		}
		if !strings.Contains(string(evaluation.Payload), `"account":{"id":"`+account.ID+`","name":"`+account.Name+`"}`) {
			t.Fatalf("expected the account object in the payload JSON, got %s", evaluation.Payload)
		}
		wantSubject := "cloud-custodian-resource/" + account.ID + "/aws.s3/shared-name"
		if evaluation.Subjects[0].Identifier != wantSubject || evaluation.Subjects[0].Type != "SUBJECT_TYPE_RESOURCE" {
			t.Fatalf("expected resource subject %s, got %+v", wantSubject, evaluation.Subjects[0])
		}
	}
	if transcript.EvidenceUUIDs[0] == transcript.EvidenceUUIDs[1] {
		t.Fatalf("the same resource id in two accounts must give distinct evidence UUIDs")
	}
}

func TestEvalAccountsEvidenceUUIDsDifferPerAccountNotPerName(t *testing.T) {
	policyDir := t.TempDir()
	policy := `package compliance_framework.accounts_test

title := "Accounts test"

description := "Passes for every resource."

violation := []
`
	if err := os.WriteFile(filepath.Join(policyDir, "policy.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	evidence := func(prodName, devName string) []*proto.Evidence {
		prod, dev := prodAccount, devAccount
		prod.Name, dev.Name = prodName, devName
		plugin := accountsPlugin([]AWSAccount{prod, dev}, []string{"us-east-1"}, twoTypeChecks()[:1])
		plugin.Logger = hclog.NewNullLogger()
		plugin.executor = &accountFakeExecutor{results: map[string]CustodianExecutionResult{
			"inventory-aws-s3": fixedExecution(map[string]interface{}{"Name": "same-bucket"}),
		}}
		plugin.evaluator = &DefaultPolicyEvaluator{Logger: hclog.NewNullLogger()}
		apiHelper := &fakeAPIHelper{}
		resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{policyDir}}, apiHelper)
		if err != nil || resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
			t.Fatalf("expected success, got %s: %v", resp.GetStatus(), err)
		}
		if len(apiHelper.evidence) != 2 {
			t.Fatalf("expected one evidence per account, got %d", len(apiHelper.evidence))
		}
		return apiHelper.evidence
	}
	named := evidence(prodAccount.Name, devAccount.Name)
	first, second := named[0], named[1]
	if first.GetUUID() == "" || first.GetUUID() == second.GetUUID() {
		t.Fatalf("expected distinct evidence UUIDs, got %q and %q", first.GetUUID(), second.GetUUID())
	}
	if first.GetLabels()["resource_id"] != second.GetLabels()["resource_id"] {
		t.Fatalf("the test needs the same resource id in both accounts")
	}
	// Renaming accounts (prod renamed, dev given a name) keeps their evidence streams.
	renamed := evidence("production", "dev")
	for i := range named {
		if named[i].GetUUID() != renamed[i].GetUUID() {
			t.Fatalf("renaming an account changed its evidence UUID from %q to %q", named[i].GetUUID(), renamed[i].GetUUID())
		}
	}
	if renamed[0].GetLabels()["account_name"] != "production" {
		t.Fatalf("expected the evidence label account_name production, got %v", renamed[0].GetLabels())
	}
}

func TestEvalAccountsVerifiesTheAmbientAccount(t *testing.T) {
	lambda := func(arns ...string) CustodianExecutionResult {
		resources := []interface{}{map[string]interface{}{"FunctionName": "no-arn"}}
		for _, arn := range arns {
			resources = append(resources, map[string]interface{}{"FunctionArn": arn})
		}
		return fixedExecution(resources...)
	}
	checks := []CustodianCheck{{Name: "lambda-check", Resource: "aws.lambda", Provider: "aws", RawPolicy: map[string]interface{}{"name": "lambda-check", "resource": "aws.lambda"}}}
	for _, tc := range []struct {
		name, wantErr, wantLog string
		hub                    CustodianExecutionResult
	}{
		{"mismatch fails the account", "use_ambient_credentials entry 111111111111 is scanning account 222222222222", "", lambda("arn:aws:lambda:eu-west-1:222222222222:function:f")},
		{"match", "", "", lambda("arn:aws:lambda:eu-west-1:111111111111:function:f", "arn:aws:s3:::no-account")},
		{"no account in any ARN warns", "", "Cannot verify the use_ambient_credentials account id", lambda()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			plugin := accountsPlugin([]AWSAccount{hubAccount, devAccount}, nil, checks)
			plugin.Logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
			transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{results: map[string]CustodianExecutionResult{
				"111111111111/inventory-aws-lambda": tc.hub,
				"inventory-aws-lambda":              lambda("arn:aws:lambda:us-east-1:333333333333:function:dev"),
			}}, []string{"bundle"})
			hubEvaluations := 0
			for _, evaluation := range transcript.Evaluations {
				if evaluation.Labels["account_id"] == hubAccount.ID {
					hubEvaluations++
				}
			}
			wantFirst := "cloud custodian failed in 1 of 2 AWS account(s): 111111111111 (hub); evidence from the other 1 account(s) was submitted\n"
			if tc.wantErr != "" && (transcript.Status != "FAILURE" || !strings.HasPrefix(transcript.Error, wantFirst) || !strings.Contains(transcript.Error, tc.wantErr) || hubEvaluations != 0 || len(transcript.EvidenceUUIDs) != 2) {
				t.Fatalf("expected only the hub to fail, with no hub evidence: %s, %d hub evaluation(s), %d evidence\n%s", transcript.Status, hubEvaluations, len(transcript.EvidenceUUIDs), transcript.Error)
			}
			if tc.wantErr == "" && (transcript.Status != "SUCCESS" || hubEvaluations == 0) {
				t.Fatalf("expected success with hub evidence, got %s with %d hub evaluation(s): %s", transcript.Status, hubEvaluations, transcript.Error)
			}
			if !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("expected the log to contain %q:\n%s", tc.wantLog, logs.String())
			}
		})
	}
}

func TestEvalAccountsSubmissionErrorNamesEarlierFailures(t *testing.T) {
	plugin := accountsPlugin([]AWSAccount{prodAccount, devAccount}, []string{"us-east-1"}, twoTypeChecks()[:1])
	plugin.Logger = hclog.NewNullLogger()
	plugin.executor = &accountFakeExecutor{results: map[string]CustodianExecutionResult{
		"222222222222/inventory-aws-s3": assumeRoleFailureResult(prodAccount.RoleARN),
		"inventory-aws-s3":              fixedExecution(map[string]interface{}{"Name": "bucket"}),
	}}
	plugin.evaluator = &recordingEvaluator{}
	apiErr := errors.New("api unavailable")
	apiHelper := &fakeAPIHelper{err: apiErr}
	resp, err := plugin.Eval(&proto.EvalRequest{PolicyPaths: []string{"bundle"}}, apiHelper)
	// prod fails first without evidence; dev's submission is the only CreateEvidence call.
	if resp.GetStatus() != proto.ExecutionStatus_FAILURE || apiHelper.calls != 1 || !errors.Is(err, apiErr) {
		t.Fatalf("expected the submission error, got %s after %d call(s): %v", resp.GetStatus(), apiHelper.calls, err)
	}
	for _, want := range []string{"AWS account 333333333333: submitting evidence: api unavailable", "cloud custodian failed in 1 of 1 AWS account(s): 222222222222 (prod) [could not assume role]"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected the error to contain %q:\n%s", want, err)
		}
	}
}

func assumeRoleFailureResult(roleARN string) CustodianExecutionResult {
	result := fixedExecution()
	result.ExitCode = 1
	result.Stderr = "2026-10-13 12:00:00: custodian.commands:ERROR Unable to assume role " + roleARN + "\nTraceback (most recent call last):\nbotocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the AssumeRole operation"
	result.Err = errors.New("custodian execution failed: exit status 1")
	result.Errors = []string{result.Err.Error(), result.Stderr}
	result.Error = strings.Join(result.Errors, "; ")
	return result
}

func TestEvalAccountsFailureAggregatesFailedAccounts(t *testing.T) {
	var logs bytes.Buffer
	plugin := accountsPlugin([]AWSAccount{prodAccount, hubAccount, devAccount}, []string{"us-east-1"}, twoTypeChecks())
	plugin.Logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Trace})
	failedCheck := fixedExecution()
	failedCheck.ExitCode = 2
	failedCheck.Stderr = "Traceback: AccessDenied for ec2:DescribeInstances"
	failedCheck.Err = errors.New("custodian execution failed: exit status 2")
	failedCheck.Errors = []string{failedCheck.Err.Error(), failedCheck.Stderr}
	failedCheck.Error = strings.Join(failedCheck.Errors, "; ")
	executor := &accountFakeExecutor{results: map[string]CustodianExecutionResult{
		"222222222222/inventory-aws-ec2": assumeRoleFailureResult(prodAccount.RoleARN),
		"333333333333/ec2-public":        failedCheck,
		"inventory-aws-s3":               fixedExecution(map[string]interface{}{"Name": "bucket"}),
		"inventory-aws-ec2":              fixedExecution(map[string]interface{}{"InstanceId": "i-1"}),
	}}
	transcript := runEvalTranscript(t, plugin, executor, []string{"bundle"})

	if transcript.Status != proto.ExecutionStatus_FAILURE.String() {
		t.Fatalf("expected FAILURE, got %s", transcript.Status)
	}
	// prod stops after its first run; hub and dev run everything.
	perAccount := map[string]int{}
	for _, execution := range transcript.Executions {
		perAccount[execution.AccountID]++
	}
	if !reflect.DeepEqual(perAccount, map[string]int{"222222222222": 1, "111111111111": 4, "333333333333": 4}) {
		t.Fatalf("unexpected runs per account: %v", perAccount)
	}
	// Evidence from the accounts that ran: hub (s3 + ec2) and dev (s3 only).
	if len(transcript.EvidenceUUIDs) != 3 {
		t.Fatalf("expected the other accounts' evidence to be submitted, got %d", len(transcript.EvidenceUUIDs))
	}
	for _, evaluation := range transcript.Evaluations {
		if evaluation.Labels["account_id"] == prodAccount.ID {
			t.Fatalf("no evidence may come from the account whose role could not be assumed")
		}
	}

	msg := transcript.Error
	t.Logf("aggregated error:\n%s", msg)
	firstLine := strings.SplitN(msg, "\n", 2)[0]
	wantFirst := "cloud custodian failed in 2 of 3 AWS account(s): 222222222222 (prod) [could not assume role], 333333333333; evidence from the other 1 account(s) was submitted"
	if firstLine != wantFirst {
		t.Fatalf("unexpected first line\n got: %s\nwant: %s", firstLine, wantFirst)
	}
	for _, want := range []string{
		"=== AWS account 222222222222 (prod) ===",
		"role: arn:aws:iam::222222222222:role/ccf-audit",
		"could not assume the role; skipped the account's 3 remaining custodian run(s)",
		"Unable to assume role arn:aws:iam::222222222222:role/ccf-audit",
		"=== AWS account 333333333333 ===",
		"custodian policy execution failed for check ec2-public",
		"Traceback: AccessDenied for ec2:DescribeInstances",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected the error to contain %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "=== AWS account 111111111111") {
		t.Fatalf("the hub succeeded and must not be reported as failed:\n%s", msg)
	}
	if strings.Contains(msg, "prod-external-id") || strings.Contains(logs.String(), "prod-external-id") {
		t.Fatalf("the external ID leaked into the error or logs")
	}
	if !strings.Contains(logs.String(), "Cloud Custodian could not assume the AWS account's role") {
		t.Fatalf("expected the assume-role failure to be logged:\n%s", logs.String())
	}
}

func TestEvalAccountsReportsParseErrorsOnce(t *testing.T) {
	checks := append(twoTypeChecks()[:1], CustodianCheck{Index: 1, Name: "broken", Resource: "unknown", Provider: "unknown", ParseErrors: []string{"policy entry at index 1 is not an object"}})
	plugin := accountsPlugin([]AWSAccount{prodAccount, devAccount}, []string{"us-east-1"}, checks)
	transcript := runEvalTranscript(t, plugin, &accountFakeExecutor{results: map[string]CustodianExecutionResult{
		"inventory-aws-s3": fixedExecution(map[string]interface{}{"Name": "bucket"}),
	}}, []string{"bundle"})
	if transcript.Status != proto.ExecutionStatus_FAILURE.String() {
		t.Fatalf("a policy that doesn't parse still fails the run, got %s", transcript.Status)
	}
	if got := strings.Count(transcript.Error, "check broken has parse errors"); got != 1 {
		t.Fatalf("expected the parse error once, got %d times:\n%s", got, transcript.Error)
	}
	if len(transcript.EvidenceUUIDs) != 2 {
		t.Fatalf("expected evidence from both accounts, got %d", len(transcript.EvidenceUUIDs))
	}
}

func TestFormatAccountFailuresBoundsTheError(t *testing.T) {
	failures := make([]accountFailure, 0)
	for i := 0; i < 20; i++ {
		account := AWSAccount{ID: fmt.Sprintf("%012d", i), RoleARN: fmt.Sprintf("arn:aws:iam::%012d:role/r", i)}
		failures = append(failures, accountFailure{
			account:     account,
			err:         errors.New(strings.Repeat("e", 10*1024)),
			diagnostics: []executionDiagnostic{{name: "inventory-aws-s3", resource: "aws.s3", isBaseline: true, exitCode: 1, stderrTail: strings.Repeat("s", 4096), logTail: strings.Repeat("l", 4096), hadError: true}},
		})
	}
	msg := formatAccountFailures(failures, 25).Error()
	if len(msg) > accountFailuresCap+256 {
		t.Fatalf("expected the error to stay bounded, got %d bytes", len(msg))
	}
	first := strings.SplitN(msg, "\n", 2)[0]
	for _, failure := range failures {
		if !strings.Contains(first, failure.account.ID) {
			t.Fatalf("the first line must name every failed account, missing %s", failure.account.ID)
		}
	}
	if !strings.Contains(msg, "more failed account(s) omitted") || !strings.Contains(msg, "... (truncated)") {
		t.Fatalf("expected truncation markers in the bounded error")
	}
	if formatAccountFailures(nil, 3) != nil {
		t.Fatalf("no failed account means no error")
	}
}

func TestIsAssumeRoleFailure(t *testing.T) {
	if !isAssumeRoleFailure(assumeRoleFailureResult("arn:aws:iam::222222222222:role/r")) {
		t.Fatalf("expected c7n's assume-role exit to be detected")
	}
	other := assumeRoleFailureResult("arn")
	other.ExitCode = 2
	if isAssumeRoleFailure(other) {
		t.Fatalf("only c7n's exit 1 means the role could not be assumed")
	}
	if isAssumeRoleFailure(fixedExecution()) {
		t.Fatalf("a successful run is not an assume-role failure")
	}
}

func TestInitIdentityLabelKeysPerMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accounts []AWSAccount
		wantKeys []string
		wantName bool
	}{
		{name: "single account", wantKeys: []string{"provider", "resource_type", "resource_id"}},
		{name: "accounts mode", accounts: []AWSAccount{prodAccount}, wantKeys: []string{"provider", "account_id", "resource_type", "resource_id"}, wantName: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apiHelper := &fakeAPIHelper{}
			plugin := accountsPlugin(tc.accounts, nil, twoTypeChecks())
			plugin.Logger = hclog.NewNullLogger()
			if _, err := plugin.Init(&proto.InitRequest{PolicyPaths: []string{t.TempDir()}}, apiHelper); err != nil {
				t.Fatalf("unexpected init error: %v", err)
			}
			if len(apiHelper.subjectTemplates) != 2 {
				t.Fatalf("expected two templates, got %d", len(apiHelper.subjectTemplates))
			}
			for _, template := range apiHelper.subjectTemplates {
				if got := template.GetIdentityLabelKeys(); !reflect.DeepEqual(got, tc.wantKeys) {
					t.Fatalf("expected identity keys %v, got %v", tc.wantKeys, got)
				}
				if template.GetType() != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
					t.Fatalf("templates stay COMPONENT, got %s", template.GetType())
				}
				hasName := false
				for _, schema := range template.GetLabelSchema() {
					hasName = hasName || schema.GetKey() == "account_name"
				}
				if hasName != tc.wantName {
					t.Fatalf("account_name in the label schema: got %t, want %t", hasName, tc.wantName)
				}
			}
		})
	}
}

func TestConfigureAccountsModePolicies(t *testing.T) {
	stubLookPath(t, func(binary string) (string, error) {
		return "/usr/local/bin/" + binary, nil
	})
	accounts := `[{"id": "222222222222", "role_name": "ccf-audit"}]`

	plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger()}
	_, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"policies_yaml": "policies:\n  - name: s3\n    resource: aws.s3\n  - name: vm\n    resource: gcp.instance",
		"aws_accounts":  accounts,
	}})
	if err == nil || !strings.Contains(err.Error(), `aws_accounts scans AWS policies only; policy "vm" uses resource "gcp.instance"`) {
		t.Fatalf("expected non-AWS policies to be rejected in accounts mode, got %v", err)
	}

	var logs bytes.Buffer
	plugin = &CloudCustodianPlugin{Logger: hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})}
	_, err = plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"policies_yaml": "policies:\n  - name: s3\n    resource: aws.s3",
		"aws_accounts":  accounts,
		"policy_labels": `{"account_id": "x", "account_name": "y", "team": "z"}`,
	}})
	if err != nil {
		t.Fatalf("unexpected configure error: %v", err)
	}
	if !strings.Contains(logs.String(), "reserved in accounts mode") || !strings.Contains(logs.String(), "account_name") {
		t.Fatalf("expected a warning about reserved policy_labels:\n%s", logs.String())
	}

	plugin = &CloudCustodianPlugin{Logger: hclog.NewNullLogger()}
	if _, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
		"policies_yaml": "policies:\n  - name: vm\n    resource: gcp.instance",
	}}); err != nil {
		t.Fatalf("non-AWS policies stay allowed without aws_accounts: %v", err)
	}
}
