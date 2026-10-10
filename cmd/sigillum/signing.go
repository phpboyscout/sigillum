package main

// Side-effect imports: register the signing backends compiled into the
// sigillum binary. sigillum's whole purpose is signing/verification, so it
// ships the full backend set (AWS KMS + local PEM). Mirrors gtb's
// cmd/gtb/signing.go on/off pattern; a regulated build drops a blank import
// and rebuilds, and linker dead-code elimination keeps that SDK out.
import (
	_ "gitlab.com/phpboyscout/go/signing-aws-kms"
	_ "gitlab.com/phpboyscout/go/signing/local"

	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"

	"gitlab.com/phpboyscout/sigillum/internal/signguard"
)

// The sign command is attached by generated wiring, so the key-file check
// rides in as middleware rather than as an edit the generator would undo.
func init() {
	setup.RegisterGlobalMiddleware(signguard.Middleware)
}
