package main

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// identityCase is a representative Cloud Custodian 0.9.49 record for one AWS
// resource type (the fields its describe/list call returns) and the id the
// plugin must derive from it.
type identityCase struct {
	resourceType string
	record       map[string]interface{}
	wantID       string
}

func awsIdentityCases() []identityCase {
	return []identityCase{
		{"aws.app-elb", map[string]interface{}{
			"LoadBalancerArn":  "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188",
			"LoadBalancerName": "web",
			"DNSName":          "web-1234.us-east-1.elb.amazonaws.com",
		}, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188"},
		{"aws.backup-plan", map[string]interface{}{
			"BackupPlanArn":  "arn:aws:backup:us-east-1:123456789012:backup-plan:8f1c2b3a-1111-2222-3333-444455556666",
			"BackupPlanId":   "8f1c2b3a-1111-2222-3333-444455556666",
			"BackupPlanName": "daily",
			"VersionId":      "v1",
		}, "arn:aws:backup:us-east-1:123456789012:backup-plan:8f1c2b3a-1111-2222-3333-444455556666"},
		{"aws.backup-vault", map[string]interface{}{
			"BackupVaultArn":  "arn:aws:backup:us-east-1:123456789012:backup-vault:Default",
			"BackupVaultName": "Default",
		}, "arn:aws:backup:us-east-1:123456789012:backup-vault:Default"},
		{"aws.cache-cluster", map[string]interface{}{
			"ARN":            "arn:aws:elasticache:us-east-1:123456789012:cluster:cache-1",
			"CacheClusterId": "cache-1",
		}, "arn:aws:elasticache:us-east-1:123456789012:cluster:cache-1"},
		{"aws.distribution", map[string]interface{}{
			"ARN":        "arn:aws:cloudfront::123456789012:distribution/E2QWRUHEXAMPLE",
			"Id":         "E2QWRUHEXAMPLE",
			"DomainName": "d111111abcdef8.cloudfront.net",
		}, "arn:aws:cloudfront::123456789012:distribution/E2QWRUHEXAMPLE"},
		{"aws.dynamodb-table", map[string]interface{}{
			"TableArn":  "arn:aws:dynamodb:us-east-1:123456789012:table/orders",
			"TableName": "orders",
			"TableId":   "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
		}, "arn:aws:dynamodb:us-east-1:123456789012:table/orders"},
		{"aws.ebs", map[string]interface{}{
			"VolumeId":         "vol-049df61146c4d7901",
			"AvailabilityZone": "us-east-1a",
			"Encrypted":        false,
		}, "vol-049df61146c4d7901"},
		{"aws.ec2", map[string]interface{}{
			"InstanceId":    "i-1234567890abcdef0",
			"PublicDnsName": "ec2-198-51-100-1.compute-1.amazonaws.com",
		}, "i-1234567890abcdef0"},
		{"aws.ecs-service", map[string]interface{}{
			"serviceArn":  "arn:aws:ecs:us-east-1:123456789012:service/prod/web",
			"serviceName": "web",
			"clusterArn":  "arn:aws:ecs:us-east-1:123456789012:cluster/prod",
		}, "arn:aws:ecs:us-east-1:123456789012:service/prod/web"},
		{"aws.efs", map[string]interface{}{
			"FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567",
			"FileSystemId":  "fs-01234567",
			"Name":          "shared",
		}, "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567"},
		{"aws.eks", map[string]interface{}{
			"arn":  "arn:aws:eks:us-east-1:123456789012:cluster/prod",
			"name": "prod",
		}, "arn:aws:eks:us-east-1:123456789012:cluster/prod"},
		{"aws.firewall", map[string]interface{}{
			"FirewallArn":  "arn:aws:network-firewall:us-east-1:123456789012:firewall/edge",
			"FirewallName": "edge",
		}, "arn:aws:network-firewall:us-east-1:123456789012:firewall/edge"},
		{"aws.hostedzone", map[string]interface{}{
			"Id":   "/hostedzone/Z1D633PJN98FT9",
			"Name": "example.com.",
		}, "arn:aws:route53:::hostedzone/Z1D633PJN98FT9"},
		{"aws.iam-group", map[string]interface{}{
			"Arn":       "arn:aws:iam::123456789012:group/admins",
			"GroupName": "admins",
			"GroupId":   "AGPAEXAMPLE",
		}, "arn:aws:iam::123456789012:group/admins"},
		{"aws.iam-policy", map[string]interface{}{
			"Arn":        "arn:aws:iam::123456789012:policy/read-only",
			"PolicyId":   "ANPAEXAMPLE",
			"PolicyName": "read-only",
		}, "arn:aws:iam::123456789012:policy/read-only"},
		{"aws.iam-role", map[string]interface{}{
			"Arn":      "arn:aws:iam::123456789012:role/deploy",
			"RoleName": "deploy",
			"RoleId":   "AROAEXAMPLE",
		}, "arn:aws:iam::123456789012:role/deploy"},
		{"aws.iam-user", map[string]interface{}{
			"Arn":      "arn:aws:iam::123456789012:user/alice",
			"UserName": "alice",
			"UserId":   "AIDAEXAMPLE",
		}, "arn:aws:iam::123456789012:user/alice"},
		{"aws.kms-key", map[string]interface{}{
			"Arn":   "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			"KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
		}, "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
		{"aws.lambda", map[string]interface{}{
			"FunctionArn":  "arn:aws:lambda:us-east-1:123456789012:function:resize",
			"FunctionName": "resize",
			"Runtime":      "python3.12",
		}, "arn:aws:lambda:us-east-1:123456789012:function:resize"},
		{"aws.log-group", map[string]interface{}{
			"arn":          "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/resize:*",
			"logGroupName": "/aws/lambda/resize",
		}, "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/resize:*"},
		{"aws.rds", map[string]interface{}{
			"DBInstanceArn":        "arn:aws:rds:us-east-1:123456789012:db:orders-db",
			"DBInstanceIdentifier": "orders-db",
			"Endpoint":             map[string]interface{}{"Address": "orders-db.abc.us-east-1.rds.amazonaws.com"},
		}, "arn:aws:rds:us-east-1:123456789012:db:orders-db"},
		{"aws.rds-cluster", map[string]interface{}{
			"DBClusterArn":        "arn:aws:rds:us-east-1:123456789012:cluster:orders",
			"DBClusterIdentifier": "orders",
		}, "arn:aws:rds:us-east-1:123456789012:cluster:orders"},
		{"aws.s3", map[string]interface{}{
			"Name":         "example-bucket",
			"CreationDate": "2024-01-01T00:00:00+00:00",
		}, "example-bucket"},
		{"aws.secrets-manager", map[string]interface{}{
			"ARN":  "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pass-AbCdEf",
			"Name": "db-pass",
		}, "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-pass-AbCdEf"},
		{"aws.sns", map[string]interface{}{
			"TopicArn":    "arn:aws:sns:us-east-1:123456789012:alerts",
			"DisplayName": "alerts",
		}, "arn:aws:sns:us-east-1:123456789012:alerts"},
		{"aws.sqs", map[string]interface{}{
			"QueueArn": "arn:aws:sqs:us-east-1:123456789012:jobs",
			"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/jobs",
		}, "arn:aws:sqs:us-east-1:123456789012:jobs"},
		{"aws.transfer-server", map[string]interface{}{
			"Arn":      "arn:aws:transfer:us-east-1:123456789012:server/s-01234567890abcdef",
			"ServerId": "s-01234567890abcdef",
		}, "arn:aws:transfer:us-east-1:123456789012:server/s-01234567890abcdef"},
		{"aws.wafv2", map[string]interface{}{
			"ARN":  "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/edge/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
			"Id":   "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
			"Name": "edge",
		}, "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/edge/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"},
	}
}

// withC7nAnnotations returns a copy of record with the keys c7n adds when a
// filter matches, as found in a check's resources.json but not in the
// inventory baseline's.
func withC7nAnnotations(record map[string]interface{}) map[string]interface{} {
	annotated := maps.Clone(record)
	annotated["c7n:MatchedFilters"] = []interface{}{"Encrypted", "tag:Owner"}
	annotated["c7n:annotations"] = map[string]interface{}{"reason": "unencrypted"}
	annotated["c7n:ListItemMatches"] = []interface{}{map[string]interface{}{"Key": "Owner"}}
	return annotated
}

func TestAWSIdentityTableCoversEveryKnownResourceType(t *testing.T) {
	tableTypes := slices.Sorted(maps.Keys(awsResourceIdentityFields))
	serviceTypes := slices.Sorted(maps.Keys(awsResourceServices))
	if !slices.Equal(tableTypes, serviceTypes) {
		t.Fatalf("identity table types %v differ from awsResourceServices types %v", tableTypes, serviceTypes)
	}

	caseTypes := make([]string, 0)
	for _, tc := range awsIdentityCases() {
		caseTypes = append(caseTypes, tc.resourceType)
	}
	slices.Sort(caseTypes)
	wantCaseTypes := make([]string, 0, len(serviceTypes))
	for _, resourceType := range serviceTypes {
		wantCaseTypes = append(wantCaseTypes, "aws."+resourceType)
	}
	if !slices.Equal(caseTypes, wantCaseTypes) {
		t.Fatalf("identity cases cover %v, want every known type %v", caseTypes, wantCaseTypes)
	}
}

// TestREADMEIdentityTableMatchesCode keeps the README's Resource Identity
// table equal to awsResourceIdentityFields.
func TestREADMEIdentityTableMatchesCode(t *testing.T) {
	content, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	row := regexp.MustCompile("^\\| `aws\\.([a-z0-9-]+)` \\| (.+) \\|$")
	field := regexp.MustCompile("`([^`]+)`")
	documented := map[string][]string{}
	for _, line := range strings.Split(string(content), "\n") {
		match := row.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		fields := []string{}
		for _, f := range field.FindAllStringSubmatch(match[2], -1) {
			fields = append(fields, f[1])
		}
		documented[match[1]] = fields
	}
	if !maps.EqualFunc(documented, awsResourceIdentityFields, slices.Equal[[]string]) {
		t.Fatalf("README identity table %v differs from awsResourceIdentityFields %v", documented, awsResourceIdentityFields)
	}
}

func TestBuildResourceRecordUsesStableAWSIdentity(t *testing.T) {
	plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
	for _, tc := range awsIdentityCases() {
		t.Run(tc.resourceType, func(t *testing.T) {
			record := plugin.buildResourceRecord(tc.resourceType, tc.record)
			if record.ID != tc.wantID {
				t.Fatalf("id = %q, want %q", record.ID, tc.wantID)
			}
			if _, hashed := record.IdentityFields["resource_hash"]; hashed {
				t.Fatalf("expected a field-based id, got a resource hash")
			}

			annotated := plugin.buildResourceRecord(tc.resourceType, withC7nAnnotations(tc.record))
			if annotated.ID != record.ID {
				t.Fatalf("c7n annotations changed the id: %q vs %q", annotated.ID, record.ID)
			}
		})
	}
}

func TestIdentityFieldPrecedence(t *testing.T) {
	t.Run("configured fields win over the table", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{
			ResourceIdentityFields: map[string][]string{"aws.lambda": {"FunctionName"}},
		}}
		record := plugin.buildResourceRecord("aws.lambda", map[string]interface{}{
			"FunctionArn":  "arn:aws:lambda:us-east-1:123456789012:function:resize",
			"FunctionName": "resize",
		})
		if record.ID != "resize" {
			t.Fatalf("id = %q, want the configured FunctionName", record.ID)
		}
	})

	t.Run("the table wins over the generic fields", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
		// "Name" is a generic field and used to win for tagged file systems.
		record := plugin.buildResourceRecord("aws.efs", map[string]interface{}{
			"FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567",
			"FileSystemId":  "fs-01234567",
			"Name":          "shared",
		})
		if record.ID != "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567" {
			t.Fatalf("id = %q, want the file system ARN", record.ID)
		}
	})

	t.Run("the natural id is used when the ARN is missing", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
		record := plugin.buildResourceRecord("aws.dynamodb-table", map[string]interface{}{"TableName": "orders"})
		if record.ID != "orders" {
			t.Fatalf("id = %q, want the table name", record.ID)
		}
	})

	t.Run("types outside the table keep the generic fields", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
		record := plugin.buildResourceRecord("aws.vpc", map[string]interface{}{"VpcId": "vpc-1", "Id": "generic-id"})
		if record.ID != "generic-id" {
			t.Fatalf("id = %q, want the generic Id field", record.ID)
		}
	})

	t.Run("the hash is the last resort", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
		resource := map[string]interface{}{"Runtime": "python3.12"}
		record := plugin.buildResourceRecord("aws.lambda", resource)
		if record.ID != hashResource(resource) || record.IdentityFields["resource_hash"] != record.ID {
			t.Fatalf("id = %q, want the resource hash", record.ID)
		}
	})

	t.Run("an unprefixed AWS type uses the table", func(t *testing.T) {
		plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
		record := plugin.buildResourceRecord("sns", map[string]interface{}{"TopicArn": "arn:aws:sns:us-east-1:123456789012:alerts"})
		if record.ID != "arn:aws:sns:us-east-1:123456789012:alerts" {
			t.Fatalf("id = %q, want the topic ARN", record.ID)
		}
	})
}

// TestMatchedResourceJoinsItsBaselineRecord checks the effect on a check: a
// matched resource carries c7n annotations the baseline record doesn't, and
// must still be the same resource (one non_compliant payload from the
// baseline), for every type.
func TestMatchedResourceJoinsItsBaselineRecord(t *testing.T) {
	plugin := &CloudCustodianPlugin{Logger: hclog.NewNullLogger(), parsedConfig: &ParsedConfig{}}
	for _, tc := range awsIdentityCases() {
		t.Run(tc.resourceType, func(t *testing.T) {
			check := CustodianCheck{Name: "check", Resource: tc.resourceType, Provider: "aws"}
			baseline := &InventoryBaseline{
				Records:      plugin.buildExecutionRecords(tc.resourceType, CustodianExecutionResult{Resources: []interface{}{tc.record}}),
				ResourceType: tc.resourceType,
				Provider:     "aws",
			}
			payloads := plugin.buildResourcePayloadsForCheck(check, CustodianExecutionResult{
				Resources: []interface{}{withC7nAnnotations(tc.record)},
			}, baseline)
			if len(payloads) != 1 {
				t.Fatalf("expected one payload, got %d", len(payloads))
			}
			payload := payloads[0]
			if payload.Resource.ID != tc.wantID || payload.Assessment.Status != "non_compliant" || payload.Assessment.InventoryStatus != "baseline" {
				t.Fatalf("payload = {id %q, status %q, inventory %q}, want {%q, non_compliant, baseline}",
					payload.Resource.ID, payload.Assessment.Status, payload.Assessment.InventoryStatus, tc.wantID)
			}
		})
	}
}
