package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func parseAccountsConfig(t *testing.T, cfg PluginConfig) (*ParsedConfig, error) {
	t.Helper()
	stubLookPath(t, func(binary string) (string, error) {
		return "/usr/local/bin/" + binary, nil
	})
	cfg.PoliciesYAML = "policies:\n  - name: s3-check\n    resource: aws.s3"
	return cfg.Parse()
}

func TestParseAWSAccounts(t *testing.T) {
	// The example from the README: per-account role_name overrides, a global
	// external ID with an override, and the hub listed with ambient credentials.
	userExample := `[
  {"id": "111111111111", "name": "hub", "use_ambient_credentials": true},
  {"id": "222222222222", "name": "prod", "role_name": "ccf-prod-audit", "external_id": "prod-external-id"},
  {"id": "333333333333", "name": "dev", "regions": ["eu-west-1"]},
  {"id": "444444444444", "role_arn": "arn:aws:iam::444444444444:role/path/ccf-audit"}
]`
	tests := []struct {
		name          string
		cfg           PluginConfig
		want          []AWSAccount
		wantSuffix    string
		wantErr       string
		errMustNotHas string
	}{
		{
			name: "no aws_accounts keeps today's single-account mode and ignores the other keys",
			cfg: PluginConfig{
				AWSAssumeRoleName:    "not a role name",
				AWSExternalID:        "x",
				AWSPartition:         "not-a-partition",
				AWSSessionNameSuffix: "bad suffix",
			},
			want:       nil,
			wantSuffix: "",
		},
		{
			name: "user example with defaults",
			cfg: PluginConfig{
				AWSAccounts:       userExample,
				AWSAssumeRoleName: "ccf-audit",
				AWSExternalID:     "global-external-id",
			},
			want: []AWSAccount{
				{ID: "111111111111", Name: "hub", UseAmbientCredentials: true},
				{ID: "222222222222", Name: "prod", RoleARN: "arn:aws:iam::222222222222:role/ccf-prod-audit", ExternalID: "prod-external-id"},
				{ID: "333333333333", Name: "dev", RoleARN: "arn:aws:iam::333333333333:role/ccf-audit", ExternalID: "global-external-id", Regions: []string{"eu-west-1"}},
				{ID: "444444444444", RoleARN: "arn:aws:iam::444444444444:role/path/ccf-audit", ExternalID: "global-external-id"},
			},
			wantSuffix: "ccf",
		},
		{
			name: "YAML is accepted and unquoted ids keep their digits",
			cfg: PluginConfig{
				AWSAccounts: `
- id: 012345678901
  name: legacy
  role_name: auditor
  regions: [us-east-1, us-east-1, " eu-west-2 "]
`,
				AWSSessionNameSuffix: "ccf-prod@team",
			},
			want: []AWSAccount{
				{ID: "012345678901", Name: "legacy", RoleARN: "arn:aws:iam::012345678901:role/auditor", Regions: []string{"us-east-1", "eu-west-2"}},
			},
			wantSuffix: "ccf-prod@team",
		},
		{
			name: "role_arn wins over role_name and aws_assume_role_name",
			cfg: PluginConfig{
				AWSAccounts:       `[{"id": "222222222222", "role_arn": "arn:aws:iam::222222222222:role/explicit", "role_name": "named"}]`,
				AWSAssumeRoleName: "default",
			},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/explicit"}},
			wantSuffix: "ccf",
		},
		{
			name: "role_name wins over aws_assume_role_name",
			cfg: PluginConfig{
				AWSAccounts:       `[{"id": "222222222222", "role_name": "named"}]`,
				AWSAssumeRoleName: "default",
			},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/named"}},
			wantSuffix: "ccf",
		},
		{
			name: "partition comes from aws_partition",
			cfg: PluginConfig{
				AWSAccounts:  `[{"id": "222222222222", "role_name": "auditor"}]`,
				AWSPartition: "aws-us-gov",
			},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws-us-gov:iam::222222222222:role/auditor"}},
			wantSuffix: "ccf",
		},
		{
			name: "partition is derived from aws_regions",
			cfg: PluginConfig{
				AWSAccounts: `[{"id": "222222222222", "role_name": "auditor"}]`,
				AWSRegions:  "cn-north-1,cn-northwest-1",
			},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws-cn:iam::222222222222:role/auditor"}},
			wantSuffix: "ccf",
		},
		{
			name: "partition is derived from the entry's regions before aws_regions",
			cfg: PluginConfig{
				AWSAccounts: `[{"id": "222222222222", "role_name": "auditor", "regions": ["us-gov-west-1"]}, {"id": "333333333333", "role_name": "auditor"}]`,
				AWSRegions:  "eu-west-1",
			},
			want: []AWSAccount{
				{ID: "222222222222", RoleARN: "arn:aws-us-gov:iam::222222222222:role/auditor", Regions: []string{"us-gov-west-1"}},
				{ID: "333333333333", RoleARN: "arn:aws:iam::333333333333:role/auditor"},
			},
			wantSuffix: "ccf",
		},
		{
			name: "values expanded from ${env:...} placeholders by the agent",
			cfg: PluginConfig{
				AWSAccounts:   `[{"id": "222222222222", "role_name": "ccf-audit", "external_id": "Zx9+=,.@:/-_from-env"}]`,
				AWSExternalID: "abc/DEF:ghi@jkl=mno+pqr,stu.vwx-yz_0123456789",
			},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/ccf-audit", ExternalID: "Zx9+=,.@:/-_from-env"}},
			wantSuffix: "ccf",
		},
		{
			name:       "external IDs of 2 and 1224 characters are accepted",
			cfg:        PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r", "external_id": "ab"}]`, AWSExternalID: strings.Repeat("x", 1224)},
			want:       []AWSAccount{{ID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/r", ExternalID: "ab"}},
			wantSuffix: "ccf",
		},
		{name: "invalid JSON", cfg: PluginConfig{AWSAccounts: `[{"id": "222222222222",]`}, wantErr: "could not parse aws_accounts"},
		{name: "unknown entry key", cfg: PluginConfig{AWSAccounts: `[{"id": "222222222222", "role": "x"}]`}, wantErr: "field role not found"},
		{name: "empty list", cfg: PluginConfig{AWSAccounts: `[]`}, wantErr: "at least one account"},
		{name: "id too short", cfg: PluginConfig{AWSAccounts: `[{"id": "12345", "role_name": "r"}]`}, wantErr: `id "12345" must be a 12-digit AWS account ID`},
		{name: "id not numeric", cfg: PluginConfig{AWSAccounts: `[{"id": "12345678901a", "role_name": "r"}]`}, wantErr: "12-digit"},
		{
			name:    "duplicate id",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}, {"id": " 222222222222 ", "role_name": "s"}]`},
			wantErr: "aws_accounts[1]: id 222222222222 is already listed at aws_accounts[0]",
		},
		{
			name:    "role_arn of another account",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_arn": "arn:aws:iam::333333333333:role/r"}]`},
			wantErr: "belongs to account 333333333333",
		},
		{
			name:    "role_arn that is not a role",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_arn": "arn:aws:iam::222222222222:user/r"}]`},
			wantErr: "is not an IAM role ARN",
		},
		{name: "invalid role_name", cfg: PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "bad name"}]`}, wantErr: "not a valid IAM role name"},
		{
			name:    "invalid aws_assume_role_name",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222"}]`, AWSAssumeRoleName: "arn:aws:iam::1:role/x"},
			wantErr: "aws_assume_role_name",
		},
		{name: "no role at any level", cfg: PluginConfig{AWSAccounts: `[{"id": "222222222222"}]`}, wantErr: "needs role_arn, role_name, aws_assume_role_name or use_ambient_credentials: true"},
		{
			name:    "ambient with a role",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r", "use_ambient_credentials": true}]`},
			wantErr: "cannot be combined with role_arn, role_name or external_id",
		},
		{
			name:          "ambient with an external ID",
			cfg:           PluginConfig{AWSAccounts: `[{"id": "222222222222", "external_id": "secret-value", "use_ambient_credentials": true}]`},
			wantErr:       "cannot be combined",
			errMustNotHas: "secret-value",
		},
		{
			name:    "two ambient accounts",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "use_ambient_credentials": true}, {"id": "333333333333", "use_ambient_credentials": true}]`},
			wantErr: "only one account may set use_ambient_credentials",
		},
		{
			name:          "external ID too short",
			cfg:           PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r", "external_id": "Q"}]`},
			wantErr:       "external_id must be 2 to 1224 characters long, got 1",
			errMustNotHas: `"Q"`,
		},
		{
			name:    "global external ID too long",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}]`, AWSExternalID: strings.Repeat("y", 1225)},
			wantErr: "aws_external_id must be 2 to 1224 characters long, got 1225",
		},
		{
			name:          "external ID with characters STS rejects",
			cfg:           PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r", "external_id": "has space secret"}]`},
			wantErr:       "may only contain",
			errMustNotHas: "has space secret",
		},
		{
			name:          "unresolved ${env:...} external ID",
			cfg:           PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}]`, AWSExternalID: "${env:CCF_EXTERNAL_ID}"},
			wantErr:       "unresolved ${env:...} placeholder",
			errMustNotHas: "CCF_EXTERNAL_ID",
		},
		{
			name:    "regions in several partitions",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r", "regions": ["us-east-1", "cn-north-1"]}]`},
			wantErr: "span the partitions aws,aws-cn",
		},
		{name: "invalid aws_partition", cfg: PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}]`, AWSPartition: "azure"}, wantErr: "aws_partition"},
		{
			name:    "session suffix with invalid characters",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}]`, AWSSessionNameSuffix: "ccf/agent"},
			wantErr: "aws_session_name_suffix",
		},
		{
			name:    "session suffix too long",
			cfg:     PluginConfig{AWSAccounts: `[{"id": "222222222222", "role_name": "r"}]`, AWSSessionNameSuffix: strings.Repeat("s", 50)},
			wantErr: "exceeds 64 characters",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseAccountsConfig(t, tc.cfg)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
				}
				if tc.errMustNotHas != "" && strings.Contains(err.Error(), tc.errMustNotHas) {
					t.Fatalf("error must not contain %q: %q", tc.errMustNotHas, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(parsed.AWSAccounts, tc.want) {
				t.Fatalf("accounts mismatch\n got: %#v\nwant: %#v", parsed.AWSAccounts, tc.want)
			}
			if parsed.AWSSessionNameSuffix != tc.wantSuffix {
				t.Fatalf("expected session suffix %q, got %q", tc.wantSuffix, parsed.AWSSessionNameSuffix)
			}
		})
	}
}

func TestAWSAccountLabel(t *testing.T) {
	if got := (AWSAccount{ID: "222222222222", Name: "prod"}).Label(); got != "222222222222 (prod)" {
		t.Fatalf("unexpected label %q", got)
	}
	if got := (AWSAccount{ID: "222222222222"}).Label(); got != "222222222222" {
		t.Fatalf("unexpected label %q", got)
	}
}

func TestConfigureAWSAccounts(t *testing.T) {
	stubLookPath(t, func(binary string) (string, error) {
		return "/usr/local/bin/" + binary, nil
	})
	policies := "policies:\n  - name: s3-check\n    resource: aws.s3"

	t.Run("returns validation errors and never logs external IDs", func(t *testing.T) {
		var logs bytes.Buffer
		plugin := &CloudCustodianPlugin{Logger: hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Trace})}
		_, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
			"policies_yaml": policies,
			"aws_accounts":  `[{"id": "222222222222", "role_name": "r", "external_id": "x"}]`,
		}})
		if err == nil || !strings.Contains(err.Error(), "aws_accounts[0]") {
			t.Fatalf("expected aws_accounts error from Configure, got %v", err)
		}

		logs.Reset()
		_, err = plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
			"policies_yaml":   policies,
			"aws_accounts":    `[{"id": "222222222222", "role_name": "r", "external_id": "entry-external-secret"}]`,
			"aws_external_id": "global-external-secret",
		}})
		if err != nil {
			t.Fatalf("unexpected configure error: %v", err)
		}
		if len(plugin.parsedConfig.AWSAccounts) != 1 {
			t.Fatalf("expected one account, got %d", len(plugin.parsedConfig.AWSAccounts))
		}
		if strings.Contains(logs.String(), "external-secret") {
			t.Fatalf("logs contain an external ID:\n%s", logs.String())
		}
		if !strings.Contains(logs.String(), "has_external_id") {
			t.Fatalf("expected the account summary in the configuration log:\n%s", logs.String())
		}
	})

	t.Run("warns about account keys set without aws_accounts", func(t *testing.T) {
		var logs bytes.Buffer
		plugin := &CloudCustodianPlugin{Logger: hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})}
		_, err := plugin.Configure(&proto.ConfigureRequest{Config: map[string]string{
			"policies_yaml":        policies,
			"aws_assume_role_name": "ccf-audit",
			"aws_external_id":      "ignored-secret",
		}})
		if err != nil {
			t.Fatalf("unexpected configure error: %v", err)
		}
		if plugin.parsedConfig.AWSAccounts != nil {
			t.Fatalf("expected no accounts, got %v", plugin.parsedConfig.AWSAccounts)
		}
		out := logs.String()
		if !strings.Contains(out, "no effect without aws_accounts") || !strings.Contains(out, "aws_assume_role_name") {
			t.Fatalf("expected a warning naming the ignored keys, got:\n%s", out)
		}
		if strings.Contains(out, "ignored-secret") {
			t.Fatalf("warning must not contain the external ID:\n%s", out)
		}
	})
}
