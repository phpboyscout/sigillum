package image

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	sigstore "gitlab.com/phpboyscout/go/signing-sigstore"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

const (
	flagRegistryUsername      = "registry-username"
	flagRegistryPasswordStdin = "registry-password-stdin"
)

// ErrRegistryCredentials is returned when only one of --registry-username and
// --registry-password-stdin is given, or the password read is empty.
var ErrRegistryCredentials = errors.NewSentinel("sigillum.registry_credentials",
	"--"+flagRegistryUsername+" and --"+flagRegistryPasswordStdin+" go together")

// RunImage signs the image named by digest in args[0] and prints where the two
// signatures were pushed. Credentials are settled first, so a mistake in them
// costs no call to the key service.
func RunImage(cmd *cobra.Command, p *props.Props, opts *ImageOptions, args []string) error {
	auth, err := registryAuth(cmd.InOrStdin(), opts)
	if err != nil {
		return err
	}

	signer, backend, err := signcmd.ResolveSigner(cmd.Context(), cmd.Flags(), opts.Backend, opts.KeyID)
	if err != nil {
		return err //nolint:wrapcheck // names the backend and the fault
	}

	sig, err := sigstore.SignImage(cmd.Context(), args[0], signer, auth)
	if err != nil {
		return errors.Wrap(err, "signing image")
	}

	p.GetLogger().Info("Signed image", "image", sig.Image, "backend", backend)

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "signature: %s\nbundle: %s\n", sig.SignatureTag, sig.Bundle)

	return errors.Wrap(err, "printing the signature locations")
}

// registryAuth returns the given username and the password on stdin, or the
// Docker config when neither flag is set. The password is never put in an error.
func registryAuth(stdin io.Reader, opts *ImageOptions) (sigstore.Option, error) {
	if (opts.RegistryUsername != "") != opts.RegistryPasswordStdin {
		return nil, ErrRegistryCredentials
	}

	if opts.RegistryUsername == "" {
		return sigstore.WithKeychain(authn.DefaultKeychain), nil
	}

	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.Wrap(err, "reading the registry password from stdin")
	}

	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return nil, errors.Wrap(ErrRegistryCredentials, "--"+flagRegistryPasswordStdin+" read an empty password")
	}

	return sigstore.WithAuthenticator(&authn.Basic{Username: opts.RegistryUsername, Password: password}), nil
}
