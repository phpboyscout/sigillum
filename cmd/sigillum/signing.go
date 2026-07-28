package main

// Side-effect imports: register the signing backends compiled into the
// sigillum binary. sigillum's whole purpose is signing/verification, so it
// ships the full backend set (AWS KMS + local PEM). Mirrors gtb's
// cmd/gtb/signing.go on/off pattern; a regulated build drops a blank import
// and rebuilds, and linker dead-code elimination keeps that SDK out.
import (
	_ "gitlab.com/phpboyscout/go/signing-aws-kms"
	_ "gitlab.com/phpboyscout/go/signing/local"
)
