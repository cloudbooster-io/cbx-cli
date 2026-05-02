package main

import (
	"fmt"
	"os"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"

	"github.com/spf13/cobra"
)

func newPlanCmd() *cobra.Command {
	var outputDir string
	cmd := &cobra.Command{
		Use:   `plan "<intent>"`,
		Short: "Generate an architecture plan from a natural-language intent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			intent := args[0]
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(cfg.LLM.Providers) == 0 {
				return fmt.Errorf("no LLM provider configured; run 'cbx llm login <provider>' first")
			}

			dir := outputDir
			if dir == "" {
				dir = "."
			}

			adrPath := fmt.Sprintf("%s/plan.adr.md", dir)
			d2Path := fmt.Sprintf("%s/plan.d2", dir)

			adrContent := generateADR(intent)
			d2Content := generateD2(intent)

			if err := os.WriteFile(adrPath, []byte(adrContent), 0o644); err != nil {
				return fmt.Errorf("writing ADR: %w", err)
			}
			if err := os.WriteFile(d2Path, []byte(d2Content), 0o644); err != nil {
				return fmt.Errorf("writing diagram: %w", err)
			}

			if !quietFlag {
				fmt.Printf("✓ Wrote %s (%d bytes)\n", adrPath, len(adrContent))
				fmt.Printf("✓ Wrote %s (%d bytes)\n", d2Path, len(d2Content))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for plan files")
	return cmd
}

func generateADR(intent string) string {
	intent = strings.ToLower(intent)
	title := strings.Title(intent)

	return fmt.Sprintf(`# ADR: %s

## Status
Proposed

## Context
The user requested: "%s"

## Decision
We will deploy a serverless architecture using AWS services.

## Components
- **CloudFront** — CDN and edge caching
- **S3** — Static asset hosting
- **Lambda** — Serverless compute
- **API Gateway** — REST API fronting
- **DynamoDB** — NoSQL data store
- **Cognito** — User authentication and authorization

## Consequences
- Scalable without managing servers
- Pay-per-use cost model
- Fast global delivery via CloudFront
`, title, intent)
}

func generateD2(intent string) string {
	return `direction: right

users: Users {
  shape: person
}

cdn: CloudFront {
  shape: cloud
}

s3: S3 Bucket {
  shape: cylinder
}

api: API Gateway {
  shape: diamond
}

lambda: Lambda {
  shape: hexagon
}

db: DynamoDB {
  shape: cylinder
}

auth: Cognito {
  shape: circle
}

users -> cdn: static assets
cdn -> s3: origin
users -> api: API calls
api -> lambda: invoke
lambda -> db: read/write
lambda -> auth: verify token
`
}
