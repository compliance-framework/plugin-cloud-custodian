package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestREADMEAccountsExampleParses keeps the README's cross-account example
// valid and its description true.
func TestREADMEAccountsExampleParses(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	section := string(readme)
	start := strings.Index(section, "## Cross-Account Scanning")
	if start < 0 {
		t.Fatalf("README has no Cross-Account Scanning section")
	}
	section = section[start:]
	begin := strings.Index(section, "```yaml\n")
	if begin < 0 {
		t.Fatalf("no yaml example in the Cross-Account Scanning section")
	}
	example := section[begin+len("```yaml\n"):]
	end := strings.Index(example, "```")
	if end < 0 {
		t.Fatalf("unterminated yaml example in the Cross-Account Scanning section")
	}
	var doc struct {
		Plugins map[string]struct {
			Config map[string]string `yaml:"config"`
		} `yaml:"plugins"`
	}
	if err := yaml.Unmarshal([]byte(example[:end]), &doc); err != nil {
		t.Fatalf("parse README example: %v", err)
	}
	config := doc.Plugins["cloud_custodian"].Config
	// The agent resolves ${env:...} placeholders before the plugin sees them.
	resolved := map[string]string{}
	for key, value := range config {
		value = strings.ReplaceAll(value, "${env:CCF_CUSTODIAN_EXTERNAL_ID}", "global-external-id")
		resolved[key] = strings.ReplaceAll(value, "${env:CCF_PROD_EXTERNAL_ID}", "prod-external-id")
	}
	parsed, err := parseAccountsConfig(t, PluginConfig{
		AWSRegions:        resolved["aws_regions"],
		AWSAssumeRoleName: resolved["aws_assume_role_name"],
		AWSExternalID:     resolved["aws_external_id"],
		AWSAccounts:       resolved["aws_accounts"],
	})
	if err != nil {
		t.Fatalf("README example doesn't parse: %v", err)
	}
	want := []AWSAccount{
		{ID: "111111111111", Name: "hub", UseAmbientCredentials: true},
		{ID: "222222222222", Name: "prod", RoleARN: "arn:aws:iam::222222222222:role/ccf-prod-audit", ExternalID: "prod-external-id"},
		{ID: "333333333333", Name: "dev", RoleARN: "arn:aws:iam::333333333333:role/ccf-audit", ExternalID: "global-external-id", Regions: []string{"eu-west-1"}},
		{ID: "444444444444", Name: "legacy", RoleARN: "arn:aws:iam::444444444444:role/security/ccf-audit", ExternalID: "global-external-id"},
	}
	if !reflect.DeepEqual(parsed.AWSAccounts, want) {
		t.Fatalf("README example parses differently than it says\n got: %#v\nwant: %#v", parsed.AWSAccounts, want)
	}
}
