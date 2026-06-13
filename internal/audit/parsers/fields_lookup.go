package parsers

import "sync"

var (
	describerFieldSetOnce sync.Once
	describerFieldSet     map[string]struct{}
)

// DescriberFieldKnown reports whether field is in the generated
// DescriberFieldManifest — i.e. whether this engine build can ever
// emit it. Used by the rulepack AHEAD handshake (internal/audit).
func DescriberFieldKnown(field string) bool {
	describerFieldSetOnce.Do(func() {
		describerFieldSet = make(map[string]struct{}, len(DescriberFieldManifest))
		for _, f := range DescriberFieldManifest {
			describerFieldSet[f] = struct{}{}
		}
	})
	_, ok := describerFieldSet[field]
	return ok
}
