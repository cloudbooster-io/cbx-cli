package parsers

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// ParseTerraformSource walks dir, parses every *.tf / *.tf.json under it,
// and returns one DiscoveredResource per `resource "<type>" "<name>"` block.
//
// Phase 4 T1 fidelity: only attributes whose expression is a self-contained
// literal (no var.x / local.y / module.* / function calls) end up in Inputs.
// Non-literal attributes are silently skipped — the resource itself is still
// emitted, just with a partial Inputs map. Provider regions declared as
// literal strings are attached to matching resources. `count` / `for_each`
// are NOT expanded; the unexpanded resource is emitted once and the meta
// attribute is preserved in Inputs verbatim.
//
// Errors are best-effort: per-file parse failures are appended to the
// returned error via errors.Join, but a single bad file does not abort the
// whole walk.
func ParseTerraformSource(dir string) ([]DiscoveredResource, error) {
	files, walkErr := listTerraformFiles(dir)
	if walkErr != nil {
		return nil, walkErr
	}

	parser := hclparse.NewParser()
	regionByProvider := map[string]string{}
	type pendingResource struct {
		Type, Name, ProviderRef string
		Body                    *hclsyntax.Body
	}
	var pending []pendingResource
	var diags hcl.Diagnostics

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "read file",
				Detail:   fmt.Sprintf("%s: %v", path, err),
			})
			continue
		}
		var (
			file       *hcl.File
			parseDiags hcl.Diagnostics
		)
		if strings.HasSuffix(path, ".tf.json") {
			file, parseDiags = parser.ParseJSON(src, path)
		} else {
			file, parseDiags = parser.ParseHCL(src, path)
		}
		diags = append(diags, parseDiags...)
		if file == nil {
			continue
		}

		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			// JSON-parsed bodies aren't hclsyntax.Body; skip the walk over
			// blocks here (gohcl.DecodeBody still works downstream, but the
			// T1 path is HCL-syntax-first; JSON support is a follow-up).
			continue
		}

		for _, block := range body.Blocks {
			switch block.Type {
			case "provider":
				if len(block.Labels) < 1 {
					continue
				}
				if region, found := literalStringAttr(block.Body, "region"); found {
					regionByProvider[block.Labels[0]] = region
				}
			case "resource":
				if len(block.Labels) < 2 {
					continue
				}
				rtype, rname := block.Labels[0], block.Labels[1]
				provRef := providerFromType(rtype)
				if explicit, found := literalStringAttr(block.Body, "provider"); found {
					provRef = explicit
				}
				pending = append(pending, pendingResource{
					Type:        rtype,
					Name:        rname,
					ProviderRef: provRef,
					Body:        block.Body,
				})
			}
		}
	}

	resources := make([]DiscoveredResource, 0, len(pending))
	for _, p := range pending {
		inputs := lowerLiteralAttributes(p.Body)
		tags := stringMap(inputs, "tags")
		resources = append(resources, DiscoveredResource{
			Type:   p.Type,
			URN:    p.Type + "." + p.Name,
			Region: regionByProvider[p.ProviderRef],
			Tags:   tags,
			Inputs: inputs,
		})
	}

	// Sort for determinism — fixtures + cross-mode invariants depend on
	// stable iteration order.
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].URN < resources[j].URN
	})

	if diags.HasErrors() {
		return resources, fmt.Errorf("parse diagnostics: %s", diags.Error())
	}
	return resources, nil
}

// listTerraformFiles returns every *.tf / *.tf.json file under dir, skipping
// the same noise dirs as the IaC-type detector (.git / .terraform /
// node_modules). Sorted for determinism.
func listTerraformFiles(dir string) ([]string, error) {
	var paths []string
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != dir && (name == ".git" || name == ".terraform" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json") {
			paths = append(paths, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(paths)
	return paths, nil
}

// literalStringAttr returns the string value of a top-level attribute when
// the expression is a self-contained literal (no var/local/function refs).
func literalStringAttr(body *hclsyntax.Body, name string) (string, bool) {
	attr, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || val.IsNull() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}

// lowerLiteralAttributes evaluates every top-level attribute whose
// expression is literal-only and returns the lowered Go-native value map.
// Non-literal attributes (var.x / local.y / function calls) are skipped so
// the partial Inputs reflects "what we could resolve without an init step."
func lowerLiteralAttributes(body *hclsyntax.Body) map[string]any {
	out := map[string]any{}
	for name, attr := range body.Attributes {
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}
		out[name] = ctyToGo(val)
	}
	return out
}

// ctyToGo recursively converts cty.Value into Go-native scalars/slices/maps
// matching the shape that the state-mode parsers produce. Numbers become
// float64 to align with encoding/json's default; strings, bools, nulls are
// passed through; lists/tuples become []any; objects/maps become
// map[string]any.
func ctyToGo(v cty.Value) any {
	if !v.IsKnown() || v.IsNull() {
		return nil
	}
	t := v.Type()
	switch t {
	case cty.String:
		return v.AsString()
	case cty.Bool:
		return v.True()
	case cty.Number:
		f, _ := v.AsBigFloat().Float64()
		return f
	}
	if t.IsListType() || t.IsTupleType() || t.IsSetType() {
		out := make([]any, 0, v.LengthInt())
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			out = append(out, ctyToGo(ev))
		}
		return out
	}
	if t.IsMapType() || t.IsObjectType() {
		out := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, ev := it.Element()
			out[k.AsString()] = ctyToGo(ev)
		}
		return out
	}
	return nil
}

// providerFromType derives the provider key from a Terraform resource type
// ("aws_s3_bucket" → "aws"). Used as the default lookup into
// regionByProvider when the resource has no explicit `provider = …` ref.
func providerFromType(rtype string) string {
	idx := strings.Index(rtype, "_")
	if idx <= 0 {
		return rtype
	}
	return rtype[:idx]
}
