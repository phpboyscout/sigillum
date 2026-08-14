// Package oprun holds the parts of a command's spine that every command shares:
// resolving the key-service backend, and refusing the arguments that cannot
// produce a result.
//
// It exists because the two commands drifted. lookupBackend was duplicated
// verbatim between them, ErrMissingFlag and ErrNoBackends were declared twice
// with identical text, and the two disagreed on how they reported a missing
// flag — one named every omission, the other named the first and stopped. Each
// is a sibling-drift defect, and the cure is not to reconcile the copies but to
// delete the second: a command names its inputs here, and the next command added
// to the tool inherits the same guards rather than re-implementing them slightly
// differently.
package oprun

import (
	"errors"
	"fmt"
	"strings"

	"gitlab.com/phpboyscout/go/encryption"
)

// ErrMissingFlag reports a required flag that was not supplied.
var ErrMissingFlag = errors.New("required flag not set")

// ErrNoBackends means the binary was built with no key service compiled in.
var ErrNoBackends = errors.New("no key service backends are compiled into this binary")

// Flag is a required flag and the value supplied for it.
type Flag struct {
	// Name is what the operator types, e.g. "--certificate". Used verbatim in
	// the error.
	Name string

	// Value is what they supplied; empty means missing.
	Value string

	// Why, when set, is appended to the error if this flag is the one missing —
	// for a flag whose absence needs more than its name to act on, like
	// --created explaining that its value is hashed into the fingerprint.
	Why string
}

// RequireFlags refuses when any named flag is missing, naming every one of them.
//
// Every omission in one message, in the order given, so three missing flags
// cost one round trip rather than three — the operator fixes them together
// instead of discovering the next only after supplying the last. One command
// named every missing flag and the other named the first and returned; this is
// the former, shared, so they cannot disagree again.
func RequireFlags(flags ...Flag) error {
	var (
		missing []string
		whys    []string
	)

	for _, f := range flags {
		if f.Value == "" {
			missing = append(missing, f.Name)

			if f.Why != "" {
				whys = append(whys, f.Why)
			}
		}
	}

	if len(missing) == 0 {
		return nil
	}

	msg := strings.Join(missing, ", ")
	if len(whys) > 0 {
		msg += ". " + strings.Join(whys, " ")
	}

	return fmt.Errorf("%w: %s", ErrMissingFlag, msg)
}

// LookupBackend resolves the --backend flag to a key service, defaulting when
// exactly one is compiled in.
//
// The single copy. name empty means the operator did not choose: with one
// backend there is nothing to choose and it is used, with none the binary
// cannot do the job, and with several the choice cannot be guessed and is
// required. A named backend is looked up directly, and the core's error already
// lists what is registered, so this adds only the flag that supplied the name.
func LookupBackend(name string) (encryption.KeyService, error) {
	if name != "" {
		service, err := encryption.LookupKeyService(name)
		if err != nil {
			return nil, fmt.Errorf("--backend: %w", err)
		}

		return service, nil
	}

	available := encryption.KeyServiceNames()

	switch len(available) {
	case 0:
		return nil, ErrNoBackends
	case 1:
		return encryption.LookupKeyService(available[0])
	default:
		return nil, fmt.Errorf("%w: --backend (available: %s)",
			ErrMissingFlag, strings.Join(available, ", "))
	}
}
