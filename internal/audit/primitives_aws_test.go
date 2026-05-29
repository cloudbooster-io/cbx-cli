package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// knownUnmappedTF lists Terraform resource types that appear in the
// surveyed fixtures (e2e/fixtures + platform-smoke-infra) but have NO
// authored CB primitive today. These are the content-gap signals the
// platform-app knowledge team should action.
//
// New unmapped types fail the test — adding to this list is a deliberate
// "yes, CB doesn't author this yet" acknowledgement, not a default escape.
var knownUnmappedTF = map[string]string{
	"aws_budgets_budget": "no CB primitive — billing/budget out of scope for IaC audit",
	"aws_iam_user":       "absent from KB (survey 2026-05-11 §1) — IAM users are anti-pattern at CB",
	"aws_iam_access_key": "follows aws_iam_user — same gap",
}

// resourceLine matches `resource "aws_<type>" "<name>" {` lines in HCL.
var resourceLine = regexp.MustCompile(`(?m)^\s*resource\s+"(aws_[a-z0-9_]+)"\s+"[^"]*"\s*{`)

// pulumiResourceType matches the `"type": "aws:..."` field in Pulumi state.
var pulumiTypeLine = regexp.MustCompile(`"type"\s*:\s*"(aws:[^"]+)"`)

// collectTFTypesFromHCL walks dir for *.tf files and returns the unique set
// of aws_* resource types referenced.
func collectTFTypesFromHCL(t *testing.T, dir string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range resourceLine.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// collectTFTypesFromState pulls aws_* types out of a Terraform-state JSON
// fixture. Uses a tolerant JSON walk so the test isn't coupled to schema
// version (`resources[].type` for tfstate v4, also handles values nested
// under `values.root_module.resources`).
func collectTFTypesFromState(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]struct{}{}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	var walk func(n any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			if tv, ok := x["type"].(string); ok && strings.HasPrefix(tv, "aws_") {
				out[tv] = struct{}{}
			}
			for _, v := range x {
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(v)
	return out
}

// collectPulumiTypesFromState pulls aws:* type tokens out of a Pulumi-state
// JSON fixture by regex (sufficient for the survey set; the runtime parser
// in adapter.go is the source of truth, this just feeds the coverage check).
func collectPulumiTypesFromState(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]struct{}{}
	for _, m := range pulumiTypeLine.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

func TestPrimitiveMap_CoversFixtures(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	// Terraform HCL fixtures shipped in the repo.
	tfTypes := map[string]struct{}{}
	for k := range collectTFTypesFromHCL(t, filepath.Join(repoRoot, "e2e", "fixtures", "terraform-sample-source")) {
		tfTypes[k] = struct{}{}
	}
	// Terraform state fixture (tfstate-shaped JSON).
	for k := range collectTFTypesFromState(t, filepath.Join(repoRoot, "e2e", "fixtures", "terraform-sample-state.json")) {
		tfTypes[k] = struct{}{}
	}

	// platform-smoke-infra lives outside this repo. Skip if absent (CI
	// runners without the sibling checkout).
	smokeInfra := filepath.Join(repoRoot, "..", "platform-smoke-infra", "terraform")
	if _, err := os.Stat(smokeInfra); err == nil {
		for k := range collectTFTypesFromHCL(t, smokeInfra) {
			tfTypes[k] = struct{}{}
		}
	} else {
		t.Logf("platform-smoke-infra not present at %s — skipping that coverage axis", smokeInfra)
	}

	// Pulumi state fixture.
	pulumiTypes := collectPulumiTypesFromState(t, filepath.Join(repoRoot, "e2e", "fixtures", "pulumi-sample-state.json"))

	// --- TF coverage ---
	var mapped, unmapped, expected []string
	for tfType := range tfTypes {
		cbID, ok := tfTypeToCBPrimitive[tfType]
		if ok {
			if _, authored := authoredCBPrimitives[cbID]; !authored {
				t.Errorf("tfTypeToCBPrimitive[%q] = %q but that id is NOT in authoredCBPrimitives (generator drift)", tfType, cbID)
			}
			mapped = append(mapped, tfType)
			continue
		}
		if _, ok := knownUnmappedTF[tfType]; ok {
			expected = append(expected, tfType)
			continue
		}
		// Engine-split db types are deliberately not in the map.
		if tfType == "aws_db_instance" || tfType == "aws_rds_cluster" {
			expected = append(expected, tfType)
			continue
		}
		unmapped = append(unmapped, tfType)
	}
	sort.Strings(mapped)
	sort.Strings(unmapped)
	sort.Strings(expected)
	if len(unmapped) > 0 {
		t.Errorf("Terraform types observed in fixtures but unmapped (add to aliasTable in tools/genprimitives, OR document as content gap in knownUnmappedTF): %v", unmapped)
	}
	t.Logf("TF coverage: %d mapped, %d known-unmapped (content gap), %d total observed", len(mapped), len(expected), len(tfTypes))

	// --- Pulumi coverage ---
	var puMapped, puUnmapped []string
	for puType := range pulumiTypes {
		if _, ok := pulumiTypeToCBPrimitive[puType]; ok {
			puMapped = append(puMapped, puType)
			continue
		}
		puUnmapped = append(puUnmapped, puType)
	}
	sort.Strings(puMapped)
	sort.Strings(puUnmapped)
	if len(puUnmapped) > 0 {
		t.Errorf("Pulumi type tokens observed in fixtures but unmapped: %v", puUnmapped)
	}
	t.Logf("Pulumi coverage: %d mapped, %d total observed", len(puMapped), len(pulumiTypes))
}

func TestPrimitiveMap_AuthoredSetMatchesValues(t *testing.T) {
	for tfType, cbID := range tfTypeToCBPrimitive {
		if _, ok := authoredCBPrimitives[cbID]; !ok {
			t.Errorf("tfTypeToCBPrimitive[%q] = %q not in authoredCBPrimitives", tfType, cbID)
		}
	}
	for puType, cbID := range pulumiTypeToCBPrimitive {
		if _, ok := authoredCBPrimitives[cbID]; !ok {
			t.Errorf("pulumiTypeToCBPrimitive[%q] = %q not in authoredCBPrimitives", puType, cbID)
		}
	}
}

func TestRDSPrimitiveFor(t *testing.T) {
	cases := map[string]string{
		"postgres":          "aws:db/postgres@v1",
		"postgresql":        "aws:db/postgres@v1",
		"mysql":             "aws:db/mysql@v1",
		"mariadb":           "aws:db/mariadb@v1",
		"aurora-postgresql": "aws:db/aurora-postgres@v1",
		"aurora-mysql":      "aws:db/aurora-mysql@v1",
		"":                  "",
		"oracle-ee":         "",
		"sqlserver-ex":      "",
	}
	for engine, want := range cases {
		if got := rdsPrimitiveFor(engine); got != want {
			t.Errorf("rdsPrimitiveFor(%q) = %q, want %q", engine, got, want)
		}
		if want != "" {
			if _, ok := authoredCBPrimitives[want]; !ok {
				t.Errorf("rdsPrimitiveFor(%q) → %q not in authoredCBPrimitives", engine, want)
			}
		}
	}
}
