package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func newKnowledgeCmd() *cobra.Command {
	knowledge := &cobra.Command{
		Use:   "knowledge",
		Short: "Search and manage the CloudBooster knowledge base",
	}
	knowledge.AddCommand(
		newKnowledgeSearchCmd(),
		newKnowledgePrimitiveCmd(),
	)
	return knowledge
}

func newKnowledgeSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search the CloudBooster knowledge base",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}

func newKnowledgePrimitiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "primitive <name>",
		Short: "Get details about a primitive in the knowledge base",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}
