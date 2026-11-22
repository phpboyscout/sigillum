package main

// Withholds `mcp stream`, which listens on every interface with no
// authentication by default (go/mcp#9). sigillum serves MCP over stdio only,
// as spec 0003 scopes it, until stream defaults to loopback.

import (
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
	"gitlab.com/phpboyscout/go/errors"
)

// ErrMCPStreamWithheld is returned when `mcp stream` is run.
var ErrMCPStreamWithheld = errors.NewSentinel("sigillum.mcp.stream_withheld",
	"mcp stream is withheld: it would serve sigillum's tools over HTTP without authentication; use mcp start")

func init() {
	setup.RegisterGlobalMiddleware(refuseMCPStream)
}

func refuseMCPStream(next setup.RunE) setup.RunE {
	return func(cmd *cobra.Command, args []string) error {
		if cmd.Name() == "stream" && cmd.HasParent() && cmd.Parent().Name() == "mcp" {
			return ErrMCPStreamWithheld
		}

		return next(cmd, args)
	}
}
