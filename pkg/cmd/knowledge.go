package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func newKnowledgeCmd() *cobra.Command {
	knowledge := &cobra.Command{
		Use:   "knowledge",
		Short: "Search and manage the CloudBooster knowledge base",
		// Hidden until the API surface ships; the RunE stubs return
		// "not implemented" and pollute --help for first-time users.
		Hidden: true,
	}
	knowledge.AddCommand(
		newKnowledgeSearchCmd(),
		newKnowledgePrimitiveCmd(),
	)
	return knowledge
}

func newKnowledgeSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "search <query>",
		Short:  "Search the CloudBooster knowledge base",
		Hidden: true,
		Args:   RequireExactlyOneArg("query", "cbx knowledge search <query>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}

func newKnowledgePrimitiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "primitive <name>",
		Short:  "Get details about a primitive in the knowledge base",
		Hidden: true,
		Args:   RequireExactlyOneArg("name", "cbx knowledge primitive <name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}
