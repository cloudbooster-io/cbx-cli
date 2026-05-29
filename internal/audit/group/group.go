// Package group runs the post-discovery component-grouping pass for
// `cbx audit aws`. It takes the flat []DiscoveredResource the discovery
// layer emits and projects it through two lenses (tag-based and
// CB-primitive-match) so the audit can talk about "frontend" or
// "cb:static-site:my-marketing-site" instead of just a list of URNs.
//
// Each lens is independent: a resource may belong to a tag-named component
// AND a primitive-named component AND neither. v1 ships two lenses;
// network-topology (v2) and reference-graph (v3) get their own packages.
package group

import (
	"sort"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// Component is one named grouping of resources. The grouping is the
// audit's way of saying "these N resources together represent one
// logical thing." Name is the human-readable label, Kind disambiguates
// the lens that produced it, Source carries the (tag-name, value) or
// (primitive-id) that justified the grouping, and Resources holds the
// member URNs (not full objects, for cheap JSON round-trip).
type Component struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"` // "tag" | "cb-primitive"
	Resources []string          `json:"resources"`
	Source    map[string]string `json:"source,omitempty"`
}

// PrimitiveLookup returns the CB primitive id for a given CFN type name,
// or "" when the type isn't authored. Callers pass a closure over
// audit.CFNTypeToCBPrimitive — keeps the audit package out of this
// package's import set so there's no cycle.
type PrimitiveLookup func(cfnType string) string

// Options governs which grouping lenses to run and any per-lens knobs.
type Options struct {
	// TagPriority lists tag keys in descending priority order. The first
	// non-empty tag on each resource wins. Resources with no matching tag
	// go into the "<unassigned>" component. Default if nil/empty:
	// ["Application", "Service", "Component", "Project"].
	TagPriority []string

	// LookupPrimitive resolves a CFN type → CB primitive id. When nil,
	// the CB-primitive lens is skipped entirely.
	LookupPrimitive PrimitiveLookup
}

// Group runs both lenses and returns the combined component list.
// Returns nil when there are no resources (not an error — the audit
// just found nothing).
func Group(resources []parsers.DiscoveredResource, opts Options) []Component {
	if len(resources) == 0 {
		return nil
	}

	tagKeys := opts.TagPriority
	if len(tagKeys) == 0 {
		tagKeys = defaultTagPriority
	}

	var out []Component
	out = append(out, groupByTags(resources, tagKeys)...)
	if opts.LookupPrimitive != nil {
		out = append(out, groupByCBPrimitive(resources, opts.LookupPrimitive)...)
	}

	// Stable order: kind first, then name. Makes diffs and snapshot tests sane.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// defaultTagPriority is the canonical CB tag-naming convention. Match
// the order users have established in their tooling rather than picking
// alphabetically.
var defaultTagPriority = []string{"Application", "Service", "Component", "Project"}
