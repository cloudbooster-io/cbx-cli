package audit

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Defaults for LLM source-file gathering — plan §5.1 ("50 files, 64 KB each").
const (
	defaultLLMMaxFiles        = 50
	defaultLLMMaxBytesPerFile = 64 * 1024
)

// SourceFile is one file shipped to the LLM analyzer. Truncated == true when
// the read was capped at maxBytesPerFile; the analyzer surfaces that to the
// user so a partial-context finding can't be silently mistaken for the whole
// picture.
type SourceFile struct {
	Path      string
	Content   []byte
	Bytes     int
	Truncated bool
}

// collectSourceFiles walks dir and returns the IaC files that match iacType,
// honouring the same .git/.terraform/node_modules skips as iactype.go. Files
// are sorted by relative path for determinism. Per-file content is truncated
// at maxBytesPerFile (warned via SourceFile.Truncated) and the total file
// count is hard-capped at maxFiles.
func collectSourceFiles(dir, iacType string, maxFiles, maxBytesPerFile int) ([]SourceFile, error) {
	if maxFiles <= 0 {
		maxFiles = defaultLLMMaxFiles
	}
	if maxBytesPerFile <= 0 {
		maxBytesPerFile = defaultLLMMaxBytesPerFile
	}

	matcher := iacFileMatcher(iacType)

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
		if matcher(d.Name()) {
			paths = append(paths, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Strings(paths)
	if len(paths) > maxFiles {
		paths = paths[:maxFiles]
	}

	files := make([]SourceFile, 0, len(paths))
	for _, p := range paths {
		// Unreadable files (open or read failure) are skipped rather than
		// failing the whole collection — one bad file shouldn't void the
		// audit's LLM context.
		f, err := readCapped(p, maxBytesPerFile)
		if err != nil {
			continue
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			rel = p
		}
		f.Path = rel
		files = append(files, f)
	}
	return files, nil
}

// iacFileMatcher returns a function reporting whether a filename is relevant
// to the given iacType. An empty iacType matches every IaC flavor the CLI
// recognises (the LLM analyzer falls back to "send everything plausible").
func iacFileMatcher(iacType string) func(name string) bool {
	switch iacType {
	case IaCTypeTerraform:
		return func(name string) bool {
			lower := strings.ToLower(name)
			return strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json")
		}
	case IaCTypeCloudFormation, IaCTypeK8s, IaCTypeHelm:
		return func(name string) bool {
			lower := strings.ToLower(name)
			return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")
		}
	default:
		return func(name string) bool {
			lower := strings.ToLower(name)
			return strings.HasSuffix(lower, ".tf") ||
				strings.HasSuffix(lower, ".tf.json") ||
				strings.HasSuffix(lower, ".yaml") ||
				strings.HasSuffix(lower, ".yml") ||
				strings.HasSuffix(lower, ".json")
		}
	}
}

// readCapped reads up to maxBytes from path, returning a SourceFile with
// Truncated set when the on-disk size exceeded the cap. A read that fails
// mid-file returns the error rather than silently handing back a partial
// buffer — the caller skips the file the same way it skips open failures.
func readCapped(path string, maxBytes int) (SourceFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return SourceFile{}, err
	}
	size := info.Size()

	f, err := os.Open(path)
	if err != nil {
		return SourceFile{}, err
	}
	defer func() { _ = f.Close() }()

	limit := int64(maxBytes)
	buf := make([]byte, limit)
	// io.ReadFull loops over short reads; EOF / ErrUnexpectedEOF just mean
	// the file is smaller than the cap.
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return SourceFile{}, fmt.Errorf("reading %s: %w", path, err)
	}
	truncated := size > limit

	return SourceFile{
		Content:   buf[:n],
		Bytes:     n,
		Truncated: truncated,
	}, nil
}
