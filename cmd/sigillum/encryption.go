package main

// Side-effect import: registers the AWS KMS key service so `decrypt` and
// `certificate` can resolve `--backend aws-kms`.
//
// Blank-imported rather than referenced directly, for the same reason the
// signing backends are: a consumer that wires one provider should not compile
// in the cloud SDKs of every other. sigillum ships the AWS one because that is
// what its security contact address uses.
import (
	// The production path. The private half never leaves the key service, which
	// is the premise the decrypt command is built on.
	_ "gitlab.com/phpboyscout/go/encryption-aws-kms"

	// On-disk PEM keys, for a developer without cloud credentials, for the
	// tutorial path, and — the reason it is here rather than only in tests —
	// so that the behaviour suite can decrypt a real report through the built
	// binary. Every decrypt scenario was a refusal before this, so the wiring
	// from the command through the key service to the plaintext had no
	// end-to-end test at all.
	//
	// It also settles an inconsistency: `sign --backend local` worked and
	// `decrypt --backend local` did not, which its own package doc predicted
	// users would trip over.
	_ "gitlab.com/phpboyscout/go/encryption/local"
)
