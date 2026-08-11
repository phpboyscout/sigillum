package main

// Side-effect import: registers the AWS KMS key service so `decrypt` and
// `certificate` can resolve `--backend aws-kms`.
//
// Blank-imported rather than referenced directly, for the same reason the
// signing backends are: a consumer that wires one provider should not compile
// in the cloud SDKs of every other. sigillum ships the AWS one because that is
// what its security contact address uses.
import _ "gitlab.com/phpboyscout/go/encryption-aws-kms"
