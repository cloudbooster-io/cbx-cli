package group

import (
	"sort"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// groupByTags assigns each resource to the component named after its
// first non-empty tag in tagKeys priority order. Resources without any
// of those tags fall into the "<unassigned>" component. The unassigned
// bucket is only emitted when at least one resource lands in it — silent
// when every resource matches.
func groupByTags(resources []parsers.DiscoveredResource, tagKeys []string) []Component {
	// componentName → ordered URN list
	groups := map[string][]string{}
	// componentName → source metadata (the tag that won)
	sources := map[string]map[string]string{}

	for _, r := range resources {
		name, sourceKey := assignTag(r.Tags, tagKeys)
		groups[name] = append(groups[name], r.URN)
		if _, seen := sources[name]; !seen {
			sources[name] = sourceKey
		}
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]Component, 0, len(names))
	for _, n := range names {
		out = append(out, Component{
			Name:      n,
			Kind:      "tag",
			Resources: groups[n],
			Source:    sources[n],
		})
	}
	return out
}

// assignTag walks tagKeys in order and returns the first matching tag's
// value as the component name, plus a {tag.<key>: value} source map.
// Returns ("<unassigned>", nil) when nothing matched.
func assignTag(tags map[string]string, tagKeys []string) (string, map[string]string) {
	for _, k := range tagKeys {
		if v, ok := tags[k]; ok && v != "" {
			return v, map[string]string{"tag." + k: v}
		}
	}
	return "<unassigned>", nil
}
