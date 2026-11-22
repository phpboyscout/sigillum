package main

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/sigillum/internal/version"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/root"
)

// A go/mcp bump that adds a subcommand fails here until someone decides
// whether it serves over a network and needs refusing like stream.
func TestMCPSubcommandsArePinned(t *testing.T) {
	rootCmd, _, err := root.NewCmdRoot(version.Get())
	require.NoError(t, err)

	mcpCmd, _, err := rootCmd.Find([]string{"mcp"})
	require.NoError(t, err)
	require.Equal(t, "mcp", mcpCmd.Name())

	var names []string
	for _, sub := range mcpCmd.Commands() {
		names = append(names, sub.Name())
	}

	slices.Sort(names)
	require.Equal(t, []string{"claude", "cursor", "start", "stream", "tools", "vscode"}, names)
}
