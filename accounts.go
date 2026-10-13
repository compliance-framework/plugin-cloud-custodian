package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"gopkg.in/yaml.v3"
)

const (
	defaultAWSPartition         = "aws"
	defaultAWSSessionNameSuffix = "ccf"
	// c7n names its STS sessions "CloudCustodian", or "CloudCustodian@<suffix>"
	// when C7N_SESSION_SUFFIX is set (c7n credentials.py SessionFactory).
	custodianSessionNamePrefix = "CloudCustodian@"
	// STS RoleSessionName is at most 64 characters.
	maxAWSRoleSessionNameLength = 64
	minAWSExternalIDLength      = 2
	maxAWSExternalIDLength      = 1224
)

var (
	awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
	awsPartitionPattern = regexp.MustCompile(`^aws(-[a-z]+)*$`)
	// IAM role names may carry a path (path/name); names use [\w+=,.@-].
	awsRoleNamePattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+(/[A-Za-z0-9_+=,.@-]+)*$`)
	awsRoleARNPattern  = regexp.MustCompile(`^arn:(aws(?:-[a-z]+)*):iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@-]+(?:/[A-Za-z0-9_+=,.@-]+)*)$`)
	// STS ExternalId and RoleSessionName character sets.
	awsExternalIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]+$`)
	awsSessionSuffixPattern  = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]+$`)
	unresolvedEnvPlaceholder = "${env:"
)

// awsAccountEntry is one aws_accounts entry as configured.
type awsAccountEntry struct {
	ID                    string   `yaml:"id"`
	Name                  string   `yaml:"name"`
	RoleARN               string   `yaml:"role_arn"`
	RoleName              string   `yaml:"role_name"`
	ExternalID            string   `yaml:"external_id"`
	Regions               []string `yaml:"regions"`
	UseAmbientCredentials bool     `yaml:"use_ambient_credentials"`
}

// AWSAccount is a validated aws_accounts entry with every default applied.
type AWSAccount struct {
	ID   string
	Name string
	// RoleARN is the role c7n assumes (--assume); empty for an ambient account.
	RoleARN string
	// ExternalID is passed with --external-id when set. Never log it.
	ExternalID string
	// Regions are the entry's own regions; empty means aws_regions, then all.
	Regions               []string
	UseAmbientCredentials bool
}

// Label returns "<id> (<name>)", or the id when the account has no name.
func (a AWSAccount) Label() string {
	if a.Name == "" {
		return a.ID
	}
	return fmt.Sprintf("%s (%s)", a.ID, a.Name)
}

// awsAccountDefaults are the plugin-level values aws_accounts entries fall back to.
type awsAccountDefaults struct {
	AssumeRoleName string
	ExternalID     string
	Partition      string
	Regions        []string
}

// parseAWSAccountSettings parses aws_accounts and the keys that only apply to
// it. Without aws_accounts it returns no accounts and no error, whatever the
// other keys hold: the plugin then behaves exactly as it did before accounts
// existed.
func parseAWSAccountSettings(c *PluginConfig, awsRegions []string) ([]AWSAccount, string, error) {
	if strings.TrimSpace(c.AWSAccounts) == "" {
		return nil, "", nil
	}

	defaults := awsAccountDefaults{
		AssumeRoleName: strings.TrimSpace(c.AWSAssumeRoleName),
		ExternalID:     strings.TrimSpace(c.AWSExternalID),
		Partition:      strings.TrimSpace(c.AWSPartition),
		Regions:        awsRegions,
	}
	if defaults.AssumeRoleName != "" && !awsRoleNamePattern.MatchString(defaults.AssumeRoleName) {
		return nil, "", fmt.Errorf("aws_assume_role_name %q is not a valid IAM role name", defaults.AssumeRoleName)
	}
	if defaults.ExternalID != "" {
		if err := validateAWSExternalID(defaults.ExternalID); err != nil {
			return nil, "", fmt.Errorf("aws_external_id %w", err)
		}
	}
	if defaults.Partition != "" && !awsPartitionPattern.MatchString(defaults.Partition) {
		return nil, "", fmt.Errorf("aws_partition %q is not an AWS partition such as aws, aws-cn or aws-us-gov", defaults.Partition)
	}

	sessionSuffix := strings.TrimSpace(c.AWSSessionNameSuffix)
	if sessionSuffix == "" {
		sessionSuffix = defaultAWSSessionNameSuffix
	}
	if !awsSessionSuffixPattern.MatchString(sessionSuffix) {
		return nil, "", fmt.Errorf("aws_session_name_suffix %q may only contain letters, digits and _+=,.@-", sessionSuffix)
	}
	if len(custodianSessionNamePrefix)+len(sessionSuffix) > maxAWSRoleSessionNameLength {
		return nil, "", fmt.Errorf("aws_session_name_suffix is too long: the STS session name %q%s exceeds %d characters",
			custodianSessionNamePrefix, sessionSuffix, maxAWSRoleSessionNameLength)
	}

	accounts, err := parseAWSAccounts(c.AWSAccounts, defaults)
	if err != nil {
		return nil, "", err
	}
	return accounts, sessionSuffix, nil
}

// parseAWSAccounts decodes aws_accounts (JSON, or YAML) and validates every
// entry. Errors name the entry but never contain an external ID.
func parseAWSAccounts(raw string, defaults awsAccountDefaults) ([]AWSAccount, error) {
	decoder := yaml.NewDecoder(bytes.NewBufferString(raw))
	decoder.KnownFields(true)
	var entries []awsAccountEntry
	if err := decoder.Decode(&entries); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("aws_accounts must list at least one account")
		}
		return nil, fmt.Errorf("could not parse aws_accounts: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("aws_accounts must list at least one account")
	}

	accounts := make([]AWSAccount, 0, len(entries))
	seen := map[string]int{}
	ambientIndex := -1
	for index, entry := range entries {
		account, err := resolveAWSAccount(entry, defaults)
		if err != nil {
			return nil, fmt.Errorf("aws_accounts[%d]: %w", index, err)
		}
		if previous, ok := seen[account.ID]; ok {
			return nil, fmt.Errorf("aws_accounts[%d]: id %s is already listed at aws_accounts[%d]", index, account.ID, previous)
		}
		seen[account.ID] = index
		if account.UseAmbientCredentials {
			// Ambient credentials belong to one account: a second ambient entry
			// would scan that same account again under another id.
			if ambientIndex >= 0 {
				return nil, fmt.Errorf("aws_accounts[%d]: only one account may set use_ambient_credentials (aws_accounts[%d] already does)", index, ambientIndex)
			}
			ambientIndex = index
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func resolveAWSAccount(entry awsAccountEntry, defaults awsAccountDefaults) (AWSAccount, error) {
	id := strings.TrimSpace(entry.ID)
	if !awsAccountIDPattern.MatchString(id) {
		return AWSAccount{}, fmt.Errorf("id %q must be a 12-digit AWS account ID", id)
	}
	account := AWSAccount{
		ID:                    id,
		Name:                  strings.TrimSpace(entry.Name),
		UseAmbientCredentials: entry.UseAmbientCredentials,
	}
	if regions := compactUniqueStrings(entry.Regions); len(regions) > 0 {
		account.Regions = regions
	}
	roleARN := strings.TrimSpace(entry.RoleARN)
	roleName := strings.TrimSpace(entry.RoleName)
	externalID := strings.TrimSpace(entry.ExternalID)

	if account.UseAmbientCredentials {
		if roleARN != "" || roleName != "" || externalID != "" {
			return AWSAccount{}, fmt.Errorf("account %s sets use_ambient_credentials, which cannot be combined with role_arn, role_name or external_id", id)
		}
		return account, nil
	}

	switch {
	case roleARN != "":
		match := awsRoleARNPattern.FindStringSubmatch(roleARN)
		if match == nil {
			return AWSAccount{}, fmt.Errorf("account %s: role_arn %q is not an IAM role ARN (arn:<partition>:iam::<account>:role/<name>)", id, roleARN)
		}
		if match[2] != id {
			return AWSAccount{}, fmt.Errorf("account %s: role_arn %q belongs to account %s", id, roleARN, match[2])
		}
		account.RoleARN = roleARN
	case roleName != "" || defaults.AssumeRoleName != "":
		if roleName == "" {
			roleName = defaults.AssumeRoleName
		} else if !awsRoleNamePattern.MatchString(roleName) {
			return AWSAccount{}, fmt.Errorf("account %s: role_name %q is not a valid IAM role name", id, roleName)
		}
		partition, err := awsAccountPartition(defaults.Partition, account.Regions, defaults.Regions)
		if err != nil {
			return AWSAccount{}, fmt.Errorf("account %s: %w", id, err)
		}
		account.RoleARN = awsRoleARN(partition, id, roleName)
	default:
		return AWSAccount{}, fmt.Errorf("account %s needs role_arn, role_name, aws_assume_role_name or use_ambient_credentials: true", id)
	}

	if externalID != "" {
		if err := validateAWSExternalID(externalID); err != nil {
			return AWSAccount{}, fmt.Errorf("account %s: external_id %w", id, err)
		}
		account.ExternalID = externalID
	} else {
		account.ExternalID = defaults.ExternalID
	}
	return account, nil
}

// validateAWSExternalID checks an external ID against STS's limits. The error
// never repeats the value.
func validateAWSExternalID(value string) error {
	if strings.Contains(value, unresolvedEnvPlaceholder) {
		return errors.New("contains an unresolved ${env:...} placeholder; set the environment variable on the agent")
	}
	if len(value) < minAWSExternalIDLength || len(value) > maxAWSExternalIDLength {
		return fmt.Errorf("must be %d to %d characters long, got %d", minAWSExternalIDLength, maxAWSExternalIDLength, len(value))
	}
	if !awsExternalIDPattern.MatchString(value) {
		return errors.New("may only contain letters, digits and _+=,.@:/-")
	}
	return nil
}

func awsRoleARN(partition, accountID, roleName string) string {
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName)
}

// awsAccountPartition is the partition of a role_name ARN: aws_partition when
// set, else the single partition of the account's effective regions (its own,
// then aws_regions; aws when there are none or only "all").
func awsAccountPartition(configured string, accountRegions, defaultRegions []string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	regions := accountRegions
	if len(regions) == 0 {
		regions = defaultRegions
	}
	partitions := make([]string, 0, 1)
	for _, region := range regions {
		if strings.EqualFold(region, "all") {
			continue
		}
		partition := awsPartitionForRegion(region)
		if !slices.Contains(partitions, partition) {
			partitions = append(partitions, partition)
		}
	}
	switch len(partitions) {
	case 0:
		return defaultAWSPartition, nil
	case 1:
		return partitions[0], nil
	default:
		return "", fmt.Errorf("regions %s span the partitions %s; set aws_partition or use role_arn",
			strings.Join(regions, ","), strings.Join(partitions, ","))
	}
}

// awsAccountsLogSummary describes the accounts for logs, without external IDs.
func awsAccountsLogSummary(accounts []AWSAccount) []map[string]interface{} {
	summary := make([]map[string]interface{}, 0, len(accounts))
	for _, account := range accounts {
		summary = append(summary, map[string]interface{}{
			"id":                      account.ID,
			"name":                    account.Name,
			"role_arn":                account.RoleARN,
			"has_external_id":         account.ExternalID != "",
			"use_ambient_credentials": account.UseAmbientCredentials,
			"regions":                 account.Regions,
		})
	}
	return summary
}

// ignoredAWSAccountKeys lists the account keys that are set although
// aws_accounts is not, so Configure can warn that they have no effect.
func ignoredAWSAccountKeys(c *PluginConfig) []string {
	if strings.TrimSpace(c.AWSAccounts) != "" {
		return nil
	}
	keys := make([]string, 0)
	for _, key := range []struct{ name, value string }{
		{"aws_assume_role_name", c.AWSAssumeRoleName},
		{"aws_external_id", c.AWSExternalID},
		{"aws_partition", c.AWSPartition},
		{"aws_session_name_suffix", c.AWSSessionNameSuffix},
	} {
		if strings.TrimSpace(key.value) != "" {
			keys = append(keys, key.name)
		}
	}
	return keys
}

const (
	// c7n logs this and exits 1 when --assume fails (c7n commands.py run).
	custodianAssumeRoleFailureMessage = "Unable to assume role"
	// Bounds of the aggregated accounts error: the first part of each
	// account's error messages, each account's whole section, and all sections.
	accountErrorMessageCap  = 2 * 1024
	accountFailureDetailCap = 16 * 1024
	accountFailuresCap      = 128 * 1024
)

// accountsMode reports whether aws_accounts is set.
func (p *CloudCustodianPlugin) accountsMode() bool {
	return p.parsedConfig != nil && len(p.parsedConfig.AWSAccounts) > 0
}

// accountScanRegions are the regions of one account: its own, else aws_regions
// (empty means all).
func accountScanRegions(account AWSAccount, defaultRegions []string) []string {
	if len(account.Regions) > 0 {
		return account.Regions
	}
	return defaultRegions
}

// scansAllRegions mirrors the executor: no regions means c7n's "all".
func scansAllRegions(regions []string) bool {
	return len(regions) == 0 || slices.Contains(regions, "all")
}

// accountFailure is everything Eval reports about one failed account.
type accountFailure struct {
	account          AWSAccount
	assumeRoleFailed bool
	skippedRuns      int
	err              error
	// diagnostics are the account's failed executions, with output tails.
	diagnostics []executionDiagnostic
}

// evalAccounts scans every account in aws_accounts, one after the other. An
// account's failure doesn't stop the others: they still submit their
// evidence, and Eval then fails with every failed account's error and output.
func (p *CloudCustodianPlugin) evalAccounts(ctx context.Context, req *proto.EvalRequest, apiHelper runner.ApiHelper, executionRoot string, run *evalRun) (*proto.EvalResponse, error) {
	// A policy entry that didn't parse fails the same way in every account.
	for _, check := range p.checks {
		if len(check.ParseErrors) > 0 {
			p.recordCheckParseErrors(run, check)
		}
	}

	accounts := p.parsedConfig.AWSAccounts
	failures := make([]accountFailure, 0)
	for i := range accounts {
		account := accounts[i]
		scope := &evalScope{
			account: &account,
			root:    filepath.Join(executionRoot, "acct-"+account.ID),
			regions: accountScanRegions(account, p.parsedConfig.AWSRegions),
		}
		p.Logger.Info("Scanning AWS account",
			"account_id", account.ID,
			"account_name", account.Name,
			"role_arn", account.RoleARN,
			"use_ambient_credentials", account.UseAmbientCredentials,
			"aws_regions", scope.regions,
		)
		if scansAllRegions(scope.regions) {
			p.Logger.Warn("Scanning all regions of an AWS account: Cloud Custodian lists the regions with the plugin's own credentials, so regions enabled only in this account can be missed; set the account's regions or aws_regions to scan them",
				"account_id", account.ID,
				"account_name", account.Name,
			)
		}

		accountRun := newEvalRun()
		if err := p.evalScope(ctx, req, apiHelper, scope, accountRun); err != nil {
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
		if err := p.flushEvidence(ctx, apiHelper, accountRun); err != nil {
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
		}
		run.totalEvidenceCount += accountRun.totalEvidenceCount
		run.successfulPolicyRuns += accountRun.successfulPolicyRuns
		run.hadCheckExecutionFailures = run.hadCheckExecutionFailures || accountRun.hadCheckExecutionFailures
		run.executionDiagnostics = append(run.executionDiagnostics, accountRun.executionDiagnostics...)
		run.runSummaries = append(run.runSummaries, accountRun.runSummaries...)

		if scope.assumeRoleFailure == nil && !accountRun.hadCheckExecutionFailures {
			if accountRun.accumulatedErrors != nil {
				// Non-fatal policy evaluation errors, as in single-account mode.
				run.accumulatedErrors = errors.Join(run.accumulatedErrors, fmt.Errorf("AWS account %s: %w", account.Label(), accountRun.accumulatedErrors))
			}
			continue
		}
		failure := accountFailure{
			account:          account,
			assumeRoleFailed: scope.assumeRoleFailure != nil,
			skippedRuns:      scope.skippedRuns,
			err:              accountRun.accumulatedErrors,
		}
		for _, diagnostic := range accountRun.executionDiagnostics {
			if diagnostic.hadError {
				failure.diagnostics = append(failure.diagnostics, diagnostic)
			}
		}
		p.Logger.Error("Cloud Custodian scan of an AWS account failed; continuing with the other accounts",
			"account_id", account.ID,
			"account_name", account.Name,
			"assume_role_failed", failure.assumeRoleFailed,
			"skipped_runs", failure.skippedRuns,
			"error", failure.detail(),
		)
		failures = append(failures, failure)
	}

	if run.totalEvidenceCount == 0 {
		p.Logger.Warn("No evidence generated by current evaluation run")
	}
	return p.evalOutcome(run, formatAccountFailures(failures, len(accounts)))
}

// detectAssumeRoleFailure marks the scope when c7n couldn't assume its
// account's role, so the account's remaining runs are skipped.
func (p *CloudCustodianPlugin) detectAssumeRoleFailure(scope *evalScope, execution CustodianExecutionResult) {
	if scope.account == nil || scope.account.RoleARN == "" || scope.assumeRoleFailure != nil || !isAssumeRoleFailure(execution) {
		return
	}
	scope.assumeRoleFailure = &execution
	p.Logger.Error("Cloud Custodian could not assume the AWS account's role; skipping the account's remaining runs",
		"account_id", scope.account.ID,
		"account_name", scope.account.Name,
		"role_arn", scope.account.RoleARN,
		"stderr_tail", tailString(execution.Stderr, custodianOutputTailBytes),
	)
}

func isAssumeRoleFailure(execution CustodianExecutionResult) bool {
	if execution.ExitCode != 1 {
		return false
	}
	return strings.Contains(execution.Stderr, custodianAssumeRoleFailureMessage) ||
		strings.Contains(execution.Stdout, custodianAssumeRoleFailureMessage) ||
		strings.Contains(execution.LogTail, custodianAssumeRoleFailureMessage)
}

// setPayloadAccount makes the scanned account the resource's account,
// overriding any account found in the resource data.
func setPayloadAccount(payload *StandardizedResourcePayload, account AWSAccount) {
	payload.Resource.AccountID = account.ID
	payload.Account = &StandardizedAccountInfo{ID: account.ID, Name: account.Name}
}

// detail renders one failed account: its role, why it failed, the start of
// its error messages and the output tails of its failed runs.
func (f accountFailure) detail() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "=== AWS account %s ===\n", f.account.Label())
	if f.account.RoleARN != "" {
		fmt.Fprintf(&sb, "role: %s\n", f.account.RoleARN)
	} else {
		sb.WriteString("credentials: ambient\n")
	}
	if f.assumeRoleFailed {
		fmt.Fprintf(&sb, "could not assume the role; skipped the account's %d remaining custodian run(s)\n", f.skippedRuns)
	}
	if f.err != nil {
		sb.WriteString(headString(strings.TrimSpace(f.err.Error()), accountErrorMessageCap))
		sb.WriteString("\n")
	}
	for _, diagnostic := range f.diagnostics {
		sb.WriteString(formatExecutionDiagnosticDetail(diagnostic))
	}
	return headString(strings.TrimSpace(sb.String()), accountFailureDetailCap)
}

// formatAccountFailures aggregates the failed accounts into Eval's error. Its
// first line names every failed account, so the agent's run status says which
// accounts failed even when the details are cut to bound the error size.
func formatAccountFailures(failures []accountFailure, accountCount int) error {
	if len(failures) == 0 {
		return nil
	}
	labels := make([]string, 0, len(failures))
	for _, failure := range failures {
		label := failure.account.Label()
		if failure.assumeRoleFailed {
			label += " [could not assume role]"
		}
		labels = append(labels, label)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "cloud custodian failed in %d of %d AWS account(s): %s", len(failures), accountCount, strings.Join(labels, ", "))
	if succeeded := accountCount - len(failures); succeeded > 0 {
		fmt.Fprintf(&sb, "; evidence from the other %d account(s) was submitted", succeeded)
	}
	omitted := 0
	for _, failure := range failures {
		detail := failure.detail()
		if sb.Len()+len(detail)+1 > accountFailuresCap {
			omitted++
			continue
		}
		sb.WriteString("\n")
		sb.WriteString(detail)
	}
	if omitted > 0 {
		fmt.Fprintf(&sb, "\n(details of %d more failed account(s) omitted to bound the error size; see the plugin log)", omitted)
	}
	return errors.New(sb.String())
}

// headString returns at most the first maxBytes bytes of s, marking the cut.
func headString(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return strings.ToValidUTF8(s[:maxBytes], "") + "\n... (truncated)"
}

func isAccountLabel(label string) bool {
	return label == "account_id" || label == "account_name"
}

// ignoredAccountPolicyLabels lists the policy_labels keys that accounts mode
// reserves.
func ignoredAccountPolicyLabels(parsed *ParsedConfig) []string {
	if len(parsed.AWSAccounts) == 0 {
		return nil
	}
	ignored := make([]string, 0)
	for _, key := range sortedKeys(parsed.PolicyLabels) {
		if isAccountLabel(key) {
			ignored = append(ignored, key)
		}
	}
	return ignored
}

// validateAccountsModeChecks rejects non-AWS policies in accounts mode: the
// accounts and their roles only mean something to AWS policies.
func validateAccountsModeChecks(parsed *ParsedConfig, checks []CustodianCheck) error {
	if len(parsed.AWSAccounts) == 0 {
		return nil
	}
	for _, check := range checks {
		if len(check.ParseErrors) > 0 || strings.EqualFold(check.Provider, "aws") {
			continue
		}
		return fmt.Errorf("aws_accounts scans AWS policies only; policy %q uses resource %q", check.Name, check.Resource)
	}
	return nil
}
