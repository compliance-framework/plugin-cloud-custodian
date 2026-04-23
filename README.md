# Compliance Framework - Cloud Custodian Plugin

The **Cloud Custodian Plugin** runs Cloud Custodian policies in dry-run mode,
builds a full inventory baseline for each configured resource type, converts
each resource/policy pair into a standardized per-resource payload, and then
executes CCF OPA bundles against those payloads to generate evidence.

## Behavior Overview

1. Load Cloud Custodian policy YAML from config.
2. Parse top-level `policies` and iterate one policy entry per check.
3. Register runtime-derived subject templates for each configured resource type during runner-v2 `Init`.
4. Run one unfiltered inventory collection for each unique resource type.
5. Run each configured check with:

```bash
custodian run --dryrun -s <output-dir> <single-policy-file>
```

6. Compare each check's matched resources with the inventory baseline.
7. Build one standardized payload per resource per check. Matched resources are marked `non_compliant`; baseline resources not matched by that check are marked `compliant`.
8. Evaluate each OPA policy bundle path from agent `EvalRequest.policyPaths`.
9. Send evidence via the plugin gRPC helper (`CreateEvidence`).

## Safety Model

This plugin always enforces read-only Cloud Custodian execution:

- `--dryrun` is always used.
- Mutating actions are not applied.
- For AWS checks, the plugin runs with `--region all` to evaluate across all AWS regions by default.

## Configuration

All plugin config fields are strings (agent gRPC `map<string,string>` contract).

| Key | Required | Description |
| --- | --- | --- |
| `policies_yaml` | Conditionally | Inline Cloud Custodian policy YAML. Preferred over `policies_path` when both are set. |
| `policies_path` | Conditionally | Local path, `file://`, `http://`, or `https://` location for policy YAML. Used when `policies_yaml` is empty. |
| `custodian_binary` | No | Path/name of Cloud Custodian executable. Default: `custodian`. |
| `check_timeout_seconds` | No | Per-check timeout in seconds. Default: `300`. |
| `policy_labels` | No | JSON map of labels merged into generated evidence labels. |
| `resource_identity_fields` | No | JSON object mapping Cloud Custodian resource types to ordered identity field paths. Built-in defaults are used after configured fields. Example: `{"aws.ec2":["InstanceId","Arn"]}`. |
| `debug_dump_payloads` | No | Boolean (`true`/`false`) toggle to write standardized resource payload JSON files for troubleshooting. Default: `false`. |
| `debug_payload_output_dir` | No | Directory where debug payload JSON files are written. If set, debug dumping is auto-enabled. Default when enabled without explicit path: `debug-standardized-payloads`. |

Validation rules:

- At least one of `policies_yaml` or `policies_path` must be provided.
- `custodian_binary` must resolve on PATH (or as explicit executable path).
- `check_timeout_seconds` must be a positive integer.
- `resource_identity_fields`, when set, must be valid JSON and each resource type must include at least one field path.
- Policy YAML must include top-level `policies` array.

## Example Agent Config (Inline YAML)

```yaml
plugins:
  cloud_custodian:
    source: ./dist/plugin
    policies:
      - ./policy-bundle
    config:
      policies_yaml: |
        policies:
          - name: ec2-public-ip-check
            resource: aws.ec2
            filters:
              - type: value
                key: PublicIpAddress
                op: not-null
      custodian_binary: custodian
      check_timeout_seconds: "300"
      policy_labels: '{"team":"cloud-security","environment":"prod"}'
```

## Example Agent Config (Path/URL Fallback)

```yaml
plugins:
  cloud_custodian:
    source: ./dist/plugin
    policies:
      - ./policy-bundle
    config:
      policies_path: file:///etc/ccf/cloud-custodian.yaml
      custodian_binary: /usr/local/bin/custodian
```

## Standardized Per-Resource OPA Input

Each resource/check iteration produces one payload with this shape:

```json
{
  "schema_version": "v2",
  "source": "cloud-custodian",
  "check": {
    "name": "ec2-public-ip-check",
    "resource": "aws.ec2",
    "provider": "aws",
    "index": 0,
    "metadata": {}
  },
  "resource": {
    "id": "i-1234567890abcdef0",
    "type": "aws.ec2",
    "provider": "aws",
    "account_id": "123456789012",
    "region": "us-east-1",
    "identity_fields": {
      "InstanceId": "i-1234567890abcdef0"
    },
    "data": {"...": "..."}
  },
  "assessment": {
    "status": "non_compliant",
    "matched": true,
    "inventory_status": "baseline",
    "matched_resource_count": 3,
    "artifact_path": "/tmp/ccf-cloud-custodian-123/001-ec2-public-ip-check",
    "resources_path": "/tmp/ccf-cloud-custodian-123/001-ec2-public-ip-check/ec2-public-ip-check/resources.json"
  },
  "execution": {
    "status": "success",
    "dry_run": true,
    "exit_code": 0,
    "started_at": "2026-03-06T12:00:00Z",
    "ended_at": "2026-03-06T12:00:01Z",
    "duration_ms": 1000,
    "stdout": "...",
    "stderr": "",
    "error": "",
    "errors": []
  },
  "raw_policy": {
    "name": "ec2-public-ip-check",
    "resource": "aws.ec2",
    "filters": []
  }
}
```

`assessment.inventory_status` is `baseline` for resources found in the unfiltered
inventory run. If a policy returns a resource that is not present in the baseline,
the plugin still evaluates it as `non_compliant` and sets
`inventory_status` to `missing_from_baseline`.

`provider` extraction rule:

- `aws.s3` -> `aws`
- non `<provider>.<resource>` formats -> `unknown`

## Operational Prerequisites

- Cloud Custodian CLI must be installed and executable.
- Cloud/provider credentials must be available in the plugin process environment
  (ambient credentials/profile/env vars).

## Testing

Run:

```bash
go test ./...
```
