package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/knowledge"
)

// GroundingBundle is the frozen, fully-fetched CB-knowledge context the
// LLM reasons over. It replaces the previous MCP-tool-call loop: the
// model receives this as plain text in the prompt and is forbidden from
// calling any tools, so the SET of findings becomes reproducible across
// runs against the same input resources.
//
// Stored in deterministic order (sorted slices, not maps) so the
// composed prompt is byte-identical for identical inputs — Go map
// iteration randomness would otherwise leak into the prompt and
// reintroduce drift.
type GroundingBundle struct {
	// Primitives: one entry per distinct CB primitive id present in
	// the audit's discovered resources. KBVersion/Chunks empty + Missing=true
	// means CB has no authored entry — the entry is still present so the
	// prompt's structure is stable across audits (advisor flag #3).
	Primitives []PrimitiveKnowledge
	// Practices: one entry per detected workload slug (from
	// ClassifyWorkloads). Same Missing convention as Primitives.
	Practices []WorkloadKnowledge
	// Composition: a single bulk lookup for the union of primitive
	// ids. Nil when no primitives were discovered or composition is
	// not authored — Missing tells them apart.
	Composition *CompositionKnowledge
}

// PrimitiveKnowledge bundles the CB lookup result for one primitive
// id alongside the id itself so the prompt builder can render a
// stable header. Missing=true means the backend 404'd this id; the
// prompt surfaces it as a placeholder so the LLM knows CB has no
// authored entry rather than thinking we skipped it.
type PrimitiveKnowledge struct {
	TypeID  string
	Missing bool
	Data    *knowledge.Response
}

// WorkloadKnowledge mirrors PrimitiveKnowledge for the practices
// endpoint.
type WorkloadKnowledge struct {
	Workload string
	Missing  bool
	Data     *knowledge.Response
}

// CompositionKnowledge wraps the composition response with the sorted
// type_ids that produced it, so the prompt header can show what the
// composition is in reference to.
type CompositionKnowledge struct {
	TypeIDs []string
	Missing bool
	Data    *knowledge.Response
}

// BuildGrounding fetches all CB knowledge needed to ground an audit
// over the provided resources. It is the deterministic replacement
// for the LLM-driven tool-call loop: every fetch is initiated from Go
// in a fixed, sorted order, and the result is a byte-stable bundle
// the prompt builder can inline.
//
// Bounded parallelism (concurrency) is used for the per-primitive and
// per-workload fetches; results are written into pre-sized slices in
// sorted key order, so the parallel fan-out doesn't affect output
// ordering. 404s collapse into Missing=true entries — knowledge gaps
// are normal and must be surfaced, not silently dropped.
//
// The first non-404 error from any fetch aborts the whole operation:
// a knowledge backend that's reachable for primitives but failing
// composition would otherwise produce a half-grounded audit, which
// is worse than failing loudly.
func BuildGrounding(
	ctx context.Context,
	client *knowledge.Client,
	resources []DiscoveredResource,
	workloads []string,
	concurrency int,
) (*GroundingBundle, []GroundingEvent, error) {
	if concurrency < 1 {
		concurrency = 6
	}

	primitiveIDs := uniqueSortedPrimitiveIDs(resources)
	workloadSlugs := append([]string(nil), workloads...)
	sort.Strings(workloadSlugs)

	bundle := &GroundingBundle{
		Primitives: make([]PrimitiveKnowledge, len(primitiveIDs)),
		Practices:  make([]WorkloadKnowledge, len(workloadSlugs)),
	}

	// Fan out primitive lookups in parallel but write to a fixed slot
	// per id, keeping the output slice's order tied to the sorted ids.
	if err := fanOut(ctx, len(primitiveIDs), concurrency, func(i int) error {
		typeID := primitiveIDs[i]
		resp, err := client.LookupPrimitive(ctx, typeID)
		if err != nil {
			if errors.Is(err, knowledge.ErrNotAuthored) {
				bundle.Primitives[i] = PrimitiveKnowledge{TypeID: typeID, Missing: true}
				return nil
			}
			return fmt.Errorf("lookup primitive %s: %w", typeID, err)
		}
		bundle.Primitives[i] = PrimitiveKnowledge{TypeID: typeID, Data: resp}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	if err := fanOut(ctx, len(workloadSlugs), concurrency, func(i int) error {
		slug := workloadSlugs[i]
		resp, err := client.BestPracticesFor(ctx, slug)
		if err != nil {
			if errors.Is(err, knowledge.ErrNotAuthored) {
				bundle.Practices[i] = WorkloadKnowledge{Workload: slug, Missing: true}
				return nil
			}
			return fmt.Errorf("best practices for %s: %w", slug, err)
		}
		bundle.Practices[i] = WorkloadKnowledge{Workload: slug, Data: resp}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	// Single bulk composition call against the full sorted set.
	// Composition for the empty set is meaningless — skip the request
	// rather than send `{"type_ids": []}` and 404.
	if len(primitiveIDs) > 0 {
		resp, err := client.CompositionFor(ctx, primitiveIDs)
		switch {
		case err == nil:
			bundle.Composition = &CompositionKnowledge{TypeIDs: primitiveIDs, Data: resp}
		case errors.Is(err, knowledge.ErrNotAuthored):
			bundle.Composition = &CompositionKnowledge{TypeIDs: primitiveIDs, Missing: true}
		default:
			return nil, nil, fmt.Errorf("composition: %w", err)
		}
	}

	return bundle, bundle.toEvents(), nil
}

// toEvents flattens the bundle into the existing GroundingEvent shape
// (defined in llm_grounded.go) so postProcessGrounded's snippet
// backfill keeps working unchanged. Order matches the bundle's sorted
// internal order — same determinism guarantee as the prompt itself.
func (b *GroundingBundle) toEvents() []GroundingEvent {
	if b == nil {
		return nil
	}
	out := make([]GroundingEvent, 0, len(b.Primitives)+len(b.Practices)+1)
	for _, p := range b.Primitives {
		ev := GroundingEvent{
			Tool:  "aws_lookup_primitive",
			Input: map[string]interface{}{"type_id": p.TypeID},
		}
		if p.Data != nil {
			ev.StructuredResult = chunksToStructured(p.Data)
			ev.TextResult = firstChunkText(p.Data)
		}
		out = append(out, ev)
	}
	for _, w := range b.Practices {
		ev := GroundingEvent{
			Tool:  "aws_best_practices_for",
			Input: map[string]interface{}{"workload": w.Workload},
		}
		if w.Data != nil {
			ev.StructuredResult = chunksToStructured(w.Data)
			ev.TextResult = firstChunkText(w.Data)
		}
		out = append(out, ev)
	}
	if b.Composition != nil {
		ev := GroundingEvent{
			Tool:  "aws_composition_for",
			Input: map[string]interface{}{"type_ids": b.Composition.TypeIDs},
		}
		if b.Composition.Data != nil {
			ev.StructuredResult = chunksToStructured(b.Composition.Data)
			ev.TextResult = firstChunkText(b.Composition.Data)
		}
		out = append(out, ev)
	}
	return out
}

// chunksToStructured packs a knowledge.Response into the shape
// snippetForCitation already knows how to walk: a structuredContent
// dict carrying a "chunks" array of {chunk_text, ...} entries.
func chunksToStructured(r *knowledge.Response) map[string]interface{} {
	if r == nil {
		return nil
	}
	chunks := make([]interface{}, 0, len(r.Chunks))
	for _, c := range r.Chunks {
		chunks = append(chunks, map[string]interface{}{
			"doc_path":    c.DocPath,
			"heading":     c.Heading,
			"chunk_text":  c.ChunkText,
			"chunk_index": c.ChunkIndex,
			"category":    c.Category,
		})
	}
	return map[string]interface{}{
		"kb_version": r.KBVersion,
		"chunks":     chunks,
	}
}

func firstChunkText(r *knowledge.Response) string {
	if r == nil || len(r.Chunks) == 0 {
		return ""
	}
	return r.Chunks[0].ChunkText
}

// uniqueSortedPrimitiveIDs returns the de-duplicated, sorted set of CB
// primitive ids derived from the resource list. Resources whose
// primitive doesn't resolve (e.g. an unknown type with no describer
// hint) are silently skipped here — they'd 404 anyway and the prompt
// renders the resource itself without a "→ primitive" arrow.
func uniqueSortedPrimitiveIDs(resources []DiscoveredResource) []string {
	seen := map[string]struct{}{}
	for _, r := range resources {
		pid := primitiveIDFor(r)
		if pid == "" {
			continue
		}
		seen[pid] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// fanOut runs work(i) for i in [0, n) with at most concurrency workers
// in flight, returning the first non-nil error. Cancels remaining
// work on the first error via ctx — every work() call sees the
// cancellation through the client's context-aware http.Do.
func fanOut(ctx context.Context, n, concurrency int, work func(int) error) error {
	if n == 0 {
		return nil
	}
	if concurrency > n {
		concurrency = n
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	errs := make(chan error, concurrency)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := work(i); err != nil {
					errs <- err
					cancel()
					// Drain remaining jobs without doing them, so the
					// producer's send doesn't deadlock on shutdown.
					for range jobs {
					}
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := 0; i < n; i++ {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// resolvedCBKnowledgeBaseURL is a small wrapper around the existing
// CB_API_URL resolution so callers outside llm_grounded.go don't need to
// know about the env var or default. Kept in this file (not the
// streamer's) because the streamer's wiring is about to be reworked and
// this helper survives that refactor.
func resolvedCBKnowledgeBaseURL() string {
	return strings.TrimRight(resolvedCBAPIURL(), "/")
}
