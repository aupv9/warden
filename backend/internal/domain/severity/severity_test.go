package severity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckovTableParses(t *testing.T) {
	f, table, err := parseCheckovTable(checkovJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(table) < 1000 || len(table) != len(checkovTable) {
		t.Fatalf("%d checks", len(table))
	}
	for _, s := range All {
		if strings.TrimSpace(f.Rubric[string(s)]) == "" {
			t.Errorf("rubric has no %s entry", s)
		}
	}
	for id, s := range table {
		if !checkovIDPattern.MatchString(id) || Rank(s) == len(All) {
			t.Errorf("%s: %q", id, s)
		}
	}
	// encoding/json keeps the last of two equal keys: a duplicate id would
	// silently drop a reviewed entry.
	dec := json.NewDecoder(bytes.NewReader(checkovJSON))
	seen := map[string]bool{}
	inChecks := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if s, ok := tok.(string); ok {
			if s == "checks" && !inChecks {
				inChecks = true
				continue
			}
			if inChecks && checkovIDPattern.MatchString(s) {
				if seen[s] {
					t.Errorf("duplicate id %s", s)
				}
				seen[s] = true
			}
		}
	}
	if len(seen) != len(table) {
		t.Fatalf("token walk saw %d ids, table has %d", len(seen), len(table))
	}
}

// The table rates the checks of one Checkov release: bumping the pinned image
// means reviewing the new release's checks and regenerating the table.
func TestCheckovTableMatchesPinnedVersion(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scanners", "images.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Checkov struct {
			Version string `json:"version"`
		} `json:"checkov"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		t.Fatal(err)
	}
	f, _, _ := parseCheckovTable(checkovJSON)
	if lock.Checkov.Version == "" || f.Version != lock.Checkov.Version {
		t.Fatalf("table is for Checkov %q, images.lock.json pins %q", f.Version, lock.Checkov.Version)
	}
}

func TestCheckovTableCoversDefaultFrameworks(t *testing.T) {
	counts := map[string]int{}
	for id := range checkovTable {
		_, rest, _ := strings.Cut(id, "_")
		family, _, _ := strings.Cut(rest, "_")
		counts[family]++
	}
	// Terraform/CloudFormation (AWS, AZURE, GCP), Kubernetes and Helm (K8S),
	// Dockerfile (DOCKER), GitHub Actions (GHA).
	for family, want := range map[string]int{"AWS": 300, "AZURE": 200, "GCP": 100, "K8S": 100, "DOCKER": 20, "GHA": 5} {
		if counts[family] < want {
			t.Errorf("%s: %d checks, want at least %d", family, counts[family], want)
		}
	}
}

// One or two checks per rubric clause, so a regenerated table that drifts
// from the rubric fails here.
func TestCheckovRubricSpotChecks(t *testing.T) {
	for id, want := range map[string]Severity{
		// critical: public data, admin ports to the internet, hardcoded credentials, anonymous admin
		"CKV_AWS_20":   Critical, // S3 READ to everyone
		"CKV_AWS_57":   Critical, // S3 WRITE to everyone
		"CKV_GCP_28":   Critical, // bucket anonymously or publicly accessible
		"CKV_AZURE_34": Critical, // blob container public access level
		"CKV_AWS_24":   Critical, // 0.0.0.0/0 to port 22
		"CKV_AWS_25":   Critical, // 0.0.0.0/0 to port 3389
		"CKV_AZURE_10": Critical, // SSH from the internet
		"CKV_GCP_2":    Critical, // unrestricted SSH
		"CKV_AWS_41":   Critical, // hardcoded AWS keys in the provider
		"CKV_AWS_46":   Critical, // secrets in EC2 user data
		"CKV_K8S_68":   Critical, // apiserver --anonymous-auth
		"CKV_AWS_358":  Critical, // GitHub OIDC trust any repository can assume
		// high: no encryption, privilege escalation, broad IAM, public databases
		"CKV_AWS_19":    High, // S3 not encrypted at rest
		"CKV_AWS_16":    High, // RDS not encrypted at rest
		"CKV_AZURE_3":   High, // storage account accepts HTTP
		"CKV_K8S_16":    High, // privileged container
		"CKV_K8S_17":    High, // host PID
		"CKV_K8S_19":    High, // host network
		"CKV_K8S_20":    High, // allowPrivilegeEscalation
		"CKV_K8S_23":    High, // root containers
		"CKV_K8S_27":    High, // docker socket
		"CKV_DOCKER_8":  High, // last USER is root
		"CKV_AWS_1":     High, // "*:*" admin policy
		"CKV_AWS_110":   High, // IAM privilege escalation
		"CKV_AWS_17":    High, // RDS publicly accessible
		"CKV2_GHA_1":    High, // write-all workflow token
		"CKV_GHA_2":     High, // shell injection
		"CKV2_DOCKER_8": High, // apt-get --allow-unauthenticated
		// medium: logging, monitoring, hardening
		"CKV_AWS_18":    Medium, // S3 access logging
		"CKV_AWS_67":    Medium, // CloudTrail in all regions
		"CKV_AWS_119":   Medium, // DynamoDB CMK (encrypted already)
		"CKV_AWS_103":   Medium, // TLS 1.2 floor
		"CKV_K8S_22":    Medium, // read-only root filesystem
		"CKV_AZURE_113": Medium, // SQL public network access (firewall still denies)
		// low: availability and hygiene
		"CKV_K8S_8":    Low, // liveness probe
		"CKV_K8S_11":   Low, // CPU limits
		"CKV_K8S_14":   Low, // image tag latest
		"CKV_AWS_21":   Low, // S3 versioning
		"CKV_DOCKER_2": Low, // HEALTHCHECK
		"CKV_DOCKER_7": Low, // base image tag latest
		// info: labels and descriptions
		"CKV_AWS_23":   Info, // security group rule description
		"CKV_DOCKER_6": Info, // MAINTAINER
	} {
		if got := Checkov(id, checkovTable); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
}

func TestCheckovUnknownIsMedium(t *testing.T) {
	if Checkov("CKV_AWS_999999", CheckovTable()) != Medium || Checkov("CKV2_CUSTOM_1", nil) != Medium {
		t.Fatal("an unknown check must stay medium")
	}
}

func TestCheckovTableIsACopy(t *testing.T) {
	c := CheckovTable()
	c["CKV_K8S_16"] = Info
	if checkovTable["CKV_K8S_16"] != High || CheckovTable()["CKV_K8S_16"] != High {
		t.Fatal("CheckovTable leaked the shared map")
	}
}

func TestParseCheckovTableRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":         `{`,
		"unknown field":    `{"version":"1","checks":{"CKV_AWS_1":"high"},"extra":1}`,
		"no version":       `{"checks":{"CKV_AWS_1":"high"}}`,
		"no checks":        `{"version":"1","checks":{}}`,
		"bad id":           `{"version":"1","checks":{"aws-1":"high"}}`,
		"lower-case id":    `{"version":"1","checks":{"ckv_aws_1":"high"}}`,
		"id with suffix":   `{"version":"1","checks":{"CKV_AWS_1x":"high"}}`,
		"unknown severity": `{"version":"1","checks":{"CKV_AWS_1":"urgent"}}`,
		"upper-case value": `{"version":"1","checks":{"CKV_AWS_1":"HIGH"}}`,
		"empty value":      `{"version":"1","checks":{"CKV_AWS_1":""}}`,
	} {
		if _, _, err := parseCheckovTable([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, table, err := parseCheckovTable([]byte(`{"version":"1","checks":{"CKV2_K8S_1":"high","CKV_GHA_7":"low"}}`)); err != nil ||
		table["CKV2_K8S_1"] != High || table["CKV_GHA_7"] != Low {
		t.Fatal(table, err)
	}
}
