package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

const maxStateFileSize = 100 * 1024 * 1024 // 100 MB

// ParseState reads a state file and extracts normalized resources.
// It auto-detects the format based on the top-level JSON keys.
func ParseState(opts Options) ([]DiscoveredResource, error) {
	stateFile := opts.StateFile

	info, err := os.Stat(stateFile)
	if err != nil {
		return nil, parsers.ThreeLineError(
			"failed to read state file",
			fmt.Sprintf("%v", err),
			"verify the file path and permissions",
		)
	}

	if info.Size() > maxStateFileSize {
		if opts.Yes {
			// proceed without prompt
		} else if opts.NoTUI {
			return nil, parsers.ThreeLineError(
				"state file exceeds size limit",
				fmt.Sprintf("file is %.1f MB (max %d MB)", float64(info.Size())/(1024*1024), maxStateFileSize/(1024*1024)),
				"use --yes to proceed without prompt",
			)
		} else {
			fmt.Fprintf(os.Stderr, "State file is %.1f MB. Continue? [y/N] ", float64(info.Size())/(1024*1024))
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil {
				return nil, parsers.ThreeLineError(
					"failed to read confirmation",
					fmt.Sprintf("%v", err),
					"use --yes to proceed without prompt",
				)
			}
			line = strings.TrimSpace(strings.ToLower(line))
			if line != "y" && line != "yes" {
				return nil, parsers.ThreeLineError(
					"state file exceeds size limit",
					"user declined to parse large state file",
					"use --yes to proceed without prompt",
				)
			}
		}
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, parsers.ThreeLineError(
			"failed to read state file",
			fmt.Sprintf("%v", err),
			"verify the file path and permissions",
		)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, parsers.ThreeLineError(
			"failed to parse state file",
			fmt.Sprintf("%v", err),
			"verify the file is valid JSON",
		)
	}

	// Pulumi state has a "deployment" or "version" key at the top level.
	// Terraform state has a "terraform_version" or "serial" key.
	if _, ok := state["deployment"]; ok {
		return parsers.ParsePulumiState(state)
	}
	if _, ok := state["terraform_version"]; ok {
		return parsers.ParseTerraformState(state)
	}
	if _, ok := state["version"]; ok {
		// Pulumi v3 states have a "version" key; fallback to Pulumi parsing.
		return parsers.ParsePulumiState(state)
	}

	return nil, parsers.ThreeLineError(
		"failed to parse state file",
		"unrecognized state file format",
		"verify the file is a valid Pulumi or Terraform state export",
	)
}
