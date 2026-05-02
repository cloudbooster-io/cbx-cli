package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of cbx",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonFlag {
				out := map[string]string{
					"version": version,
					"commit":  commit,
					"date":    date,
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			fmt.Printf("cbx version %s (commit: %s, built: %s)\n", version, commit, date)
			return nil
		},
	}
}
