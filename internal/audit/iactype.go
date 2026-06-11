package audit

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// detectIaCType inspects dir for IaC files and returns one of the IaCType*
// constants, or "" when no IaC files are detected. The walk stops as soon as
// a flavor is identified — this is "first-match-wins" by detection order
// (terraform → cloudformation → k8s → helm). Mixed-flavor dirs are not an
// error; whichever flavor's marker is encountered first wins.
//
// Detection cheatsheet:
//   - terraform:      *.tf, *.tf.json
//   - helm:           any file named Chart.yaml (anywhere under dir)
//   - cloudformation: *.yaml/*.yml/*.json containing AWSTemplateFormatVersion
//     or a top-level "Resources:" with an AWS:: type
//   - k8s:            *.yaml/*.yml with apiVersion: + kind:
//
// Helm is checked before generic YAML so a chart's templates/*.yaml don't
// accidentally classify the dir as plain k8s.
func detectIaCType(dir string) string {
	var (
		sawTerraform      bool
		sawHelm           bool
		sawCloudFormation bool
		sawK8s            bool
	)

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable subtrees rather than aborting the whole walk.
			return nil
		}
		if d.IsDir() {
			// Skip common noise that would slow the walk and never holds IaC.
			name := d.Name()
			if path != dir && (name == ".git" || name == ".terraform" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		lower := strings.ToLower(name)

		switch {
		case strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json"):
			sawTerraform = true
			return filepath.SkipAll // first-match-wins: terraform short-circuits
		case name == "Chart.yaml":
			sawHelm = true
		case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json"):
			data, readErr := os.ReadFile(path)
			if readErr != nil || len(data) == 0 {
				return nil
			}
			if looksLikeCloudFormation(data) {
				sawCloudFormation = true
			} else if looksLikeKubernetes(data) {
				sawK8s = true
			}
		}
		return nil
	})

	if walkErr != nil {
		return ""
	}

	switch {
	case sawTerraform:
		return IaCTypeTerraform
	case sawCloudFormation:
		return IaCTypeCloudFormation
	case sawHelm:
		return IaCTypeHelm
	case sawK8s:
		return IaCTypeK8s
	default:
		return ""
	}
}

// looksLikeCloudFormation returns true when the file appears to be a CFN
// template. The cheap markers are AWSTemplateFormatVersion (canonical) or a
// top-level Resources: with an AWS:: typed entry beneath it.
func looksLikeCloudFormation(data []byte) bool {
	if bytes.Contains(data, []byte("AWSTemplateFormatVersion")) {
		return true
	}
	// JSON CFN: "Resources" object with "Type": "AWS::..."
	if bytes.Contains(data, []byte("\"AWS::")) {
		return true
	}
	// YAML CFN with no AWSTemplateFormatVersion line: look for "Type: AWS::"
	// inside a Resources block. Cheap heuristic — both substrings present.
	if bytes.Contains(data, []byte("Resources:")) && bytes.Contains(data, []byte("Type: AWS::")) {
		return true
	}
	return false
}

// looksLikeKubernetes returns true for manifests that carry the canonical
// apiVersion + kind pair. Both must be present at the start of a line so we
// don't trip on YAML keys nested deep in unrelated files.
func looksLikeKubernetes(data []byte) bool {
	hasAPIVersion := bytes.Contains(data, []byte("\napiVersion:")) || bytes.HasPrefix(data, []byte("apiVersion:"))
	hasKind := bytes.Contains(data, []byte("\nkind:")) || bytes.HasPrefix(data, []byte("kind:"))
	return hasAPIVersion && hasKind
}
