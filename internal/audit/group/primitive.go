package group

import (
	"sort"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// groupByCBPrimitive emits one component per resource that maps to a
// known CB primitive via lookup. In v1 these are component-of-one
// groupings — the v3 reference-graph pass will cluster transitively
// connected primitives into multi-resource components. Until then,
// "cb:<primitive>:<resource-id>" is a precise enough handle for the
// renderer and the grounded analyzer to talk about a specific resource
// by its CB-knowledge identity.
//
// Resources whose CFN type doesn't map to an authored primitive are
// silently skipped. The caller already knows it ran the lens; no need
// to emit a "<no-primitive>" bucket that would dilute the signal.
//
// A per-resource override at r.Inputs["cb_describer_primitive_resolved"]
// wins over the static CFN→primitive lookup. This is the path for
// engine-split databases (AWS::RDS::DBInstance can resolve to any of
// aws:db/postgres@v1, aws:db/mysql@v1, aws:db/mariadb@v1 — the static
// map can't distinguish them since they share a CFN type); the RDS
// describer writes the resolved id into Inputs before this lens runs.
func groupByCBPrimitive(resources []parsers.DiscoveredResource, lookup PrimitiveLookup) []Component {
	type entry struct {
		urn       string
		primitive string
	}
	var entries []entry
	for _, r := range resources {
		pid := resolvedPrimitiveID(r.Inputs)
		if pid == "" {
			pid = lookup(r.Type)
		}
		if pid == "" {
			continue
		}
		entries = append(entries, entry{urn: r.URN, primitive: pid})
	}
	if len(entries) == 0 {
		return nil
	}

	// Stable order: primitive id, then URN, for snapshot-friendly output.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].primitive != entries[j].primitive {
			return entries[i].primitive < entries[j].primitive
		}
		return entries[i].urn < entries[j].urn
	})

	out := make([]Component, 0, len(entries))
	for _, e := range entries {
		out = append(out, Component{
			Name:      "cb:" + e.primitive + ":" + e.urn,
			Kind:      "cb-primitive",
			Resources: []string{e.urn},
			Source:    map[string]string{"primitive": e.primitive},
		})
	}
	return out
}

// resolvedPrimitiveID returns the per-resource primitive override
// (currently set only by the RDS describers for engine-split DBs), or
// "" when none is present. The key constant lives in the parsers
// package — see parsers.CBDescriberPrimitiveResolved for why that's
// the cycle-free home shared with discover/aws and audit.
func resolvedPrimitiveID(inputs map[string]any) string {
	if inputs == nil {
		return ""
	}
	s, _ := inputs[parsers.CBDescriberPrimitiveResolved].(string)
	return s
}
