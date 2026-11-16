package signcmd

import (
	"context"
	"crypto"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing"
)

const (
	flagBackend = "backend"
	flagKeyID   = "key-id"

	keyIDUsage = "Backend-specific key identifier (required). For aws-kms: a KMS key ID, ARN, or alias. For local: a PEM file path."
)

// instanceNameRe and maxInstanceNameLen mirror go/signing's rule for a name an
// error may quote. Anything else may be a credential pasted into the selector.
var instanceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

const maxInstanceNameLen = 24

// AddBackendFlags adds the required --backend and --key-id flags, then one flag
// per setting of each linked backend.
func AddBackendFlags(cmd *cobra.Command, selector, keyID *string) {
	fs := cmd.Flags()

	fs.StringVar(selector, flagBackend, "", fmt.Sprintf(
		"Signing backend: <type> or <type>:<instance>[?k=v] (required). Compiled-in types: %s",
		strings.Join(signing.Names(), ", ")))
	fs.StringVar(keyID, flagKeyID, "", keyIDUsage)

	_ = cmd.MarkFlagRequired(flagBackend)
	_ = cmd.MarkFlagRequired(flagKeyID)

	addSettingFlags(fs)
}

func addSettingFlags(fs *pflag.FlagSet) {
	for _, name := range signing.Names() {
		b, err := signing.Get(name)
		if err != nil {
			continue
		}

		// Unreachable: signing.Register refuses a malformed settings struct.
		settings, err := signing.SettingsOf(b)
		if err != nil {
			continue
		}

		for _, s := range settings {
			f := fs.VarPF(s, s.Key(), "", s.Usage())
			if s.IsBoolFlag() {
				f.NoOptDefVal = "true"
			}
		}
	}
}

// ResolveBackend turns a --backend selector into a configured backend and its
// canonical identity, which is safe to log where the selector is not. flags is
// the set AddBackendFlags populated: a bare type takes its settings from there,
// and a named instance refuses any that were set. flags may be nil.
func ResolveBackend(selector string, flags *pflag.FlagSet) (signing.Backend, string, error) {
	if err := refuseTopLevelSettings(selector, flags); err != nil {
		return nil, "", err
	}

	b, canonical, err := signing.Resolve(selector)
	if err != nil {
		return nil, "", err //nolint:wrapcheck // already worded for the user, and a wrap would precede the backend's name
	}

	if strings.Contains(canonical, ":") {
		return b, canonical, nil
	}

	if err := signing.ValidateSettings(b); err != nil {
		return nil, "", errors.Wrapf(err, "backend %q", canonical)
	}

	return b, canonical, nil
}

// refuseTopLevelSettings refuses a backend flag set beside a named instance. The
// flag would configure the registered default, not the instance, so honouring the
// command line as written would silently ignore it (go/signing-cli#7).
func refuseTopLevelSettings(selector string, flags *pflag.FlagSet) error {
	if flags == nil {
		return nil
	}

	head, _, _ := strings.Cut(selector, "?")

	typ, instance, named := strings.Cut(head, ":")
	if !named || len(instance) > maxInstanceNameLen || !instanceNameRe.MatchString(instance) {
		return nil
	}

	// A throwaway instance, only to learn the setting keys. Any failure here is
	// signing.Resolve's to word.
	probe, err := signing.NewInstance(typ, instance)
	if err != nil {
		return nil //nolint:nilerr // see above
	}

	settings, err := signing.SettingsOf(probe)
	if err != nil {
		return nil //nolint:nilerr // see above
	}

	canonical := typ + ":" + instance

	for _, s := range settings {
		if f := flags.Lookup(s.Key()); f != nil && f.Changed {
			// The flag is named, never its value.
			return errors.Newf(
				"--%s configures the default %q backend, not the named instance %q; pass it as a selector setting instead: --backend '%s?%s=…'",
				s.Key(), typ, canonical, canonical, s.Key())
		}
	}

	return nil
}

// ResolveSigner resolves a --backend selector and constructs its signer for
// keyID. The returned string identifies the backend in log lines.
func ResolveSigner(ctx context.Context, flags *pflag.FlagSet, selector, keyID string) (crypto.Signer, string, error) {
	b, canonical, err := ResolveBackend(selector, flags)
	if err != nil {
		return nil, "", err
	}

	signer, err := b.NewSigner(ctx, keyID)
	if err != nil {
		return nil, "", errors.Wrap(err, "constructing signer")
	}

	return signer, canonical, nil
}
