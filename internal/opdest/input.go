package opdest

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrOutputOverInput means --output names a file the run is reading.
//
// Every command here stages its output and renames it into place at the end, so
// the read finishes long before the write lands. That is what makes this
// destructive rather than merely wrong: the run reports success, and the input
// is gone.
//
// What is lost differs by command and both are bad. decrypt replaces the
// certificate correspondents encrypt to, or replaces the encrypted report with
// its own plaintext so a second run has nothing to decrypt. certificate is
// worse: the local backend's key identifiers are filesystem paths, so --output
// naming --encrypt-key overwrites an ECDH private key that exists nowhere else,
// and every report already encrypted to the published certificate becomes
// undecryptable at the same moment.
//
// It lives here rather than in either command because it was written for one of
// them and the other went without it for a release. A guard that has to be
// remembered separately per command is a guard that will be missing from the
// next one.
var ErrOutputOverInput = errors.New("--output names a file this command is reading")

// Input is a file a command reads, named by the flag that supplied it.
//
// Flag is what the operator typed rather than a description, because the
// remedy is to change that flag and they need to know which.
type Input struct {
	Flag string
	Path string
}

// CheckNotInput refuses an output that names one of the inputs.
//
// Inputs are taken in order and every collision is reported, for the same
// reason checkFlags names every missing flag: an operator who has aimed
// --output at two of their own inputs should learn that once, not once per
// re-run. The order is the caller's slice order, so the message is determined —
// an earlier version of this ranged over a map and Go randomises that, which
// made the error text change between identical runs and any test asserting it
// flaky by construction.
//
// Comparison is on cleaned paths, so "security.asc" and "./security.asc" are
// recognised as the same file. It is deliberately NOT resolved through the
// filesystem: a symbolic or hard link can make two different names the same
// file, and catching those needs a stat of a destination that may not exist
// yet. This catches the slip operators actually make. The narrowness is
// documented in the CLI reference rather than left for someone to discover.
//
// Standard output is not a file and cannot collide, and neither can an input
// coming from stdin.
func CheckNotInput(output string, inputs ...Input) error {
	if output == "" || output == "-" {
		return nil
	}

	out := filepath.Clean(output)

	var hit []string

	for _, in := range inputs {
		if in.Path == "" || in.Path == "-" {
			continue
		}

		if filepath.Clean(in.Path) == out {
			hit = append(hit, in.Flag)
		}
	}

	if len(hit) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s is also %s", ErrOutputOverInput, output, strings.Join(hit, " and "))
}
