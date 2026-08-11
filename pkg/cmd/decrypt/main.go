package decrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"

	"gitlab.com/phpboyscout/go/encryption"

	"gitlab.com/phpboyscout/sigillum/internal/openpgp"
)

// Errors this command reports.
var (
	// ErrMissingFlag reports a required flag that was not supplied.
	ErrMissingFlag = errors.New("required flag not set")

	// ErrNoBackends means the binary was built with no key service compiled
	// in, so there is nothing to decrypt or sign with.
	ErrNoBackends = errors.New("no key service backends are compiled into this binary")
)

// RunDecrypt reads an encrypted report and writes its plaintext out.
//
// Exactly one operation needs the private key — the ECDH agreement, performed
// by the key service. Everything else happens here: the key derivation, the
// AES key unwrap, and opening the encrypted-data packet.
func RunDecrypt(ctx context.Context, p *props.Props, opts *DecryptOptions, args []string) error {
	if opts.Certificate == "" {
		return fmt.Errorf("%w: --certificate", ErrMissingFlag)
	}

	if opts.Key == "" {
		return fmt.Errorf("%w: --key", ErrMissingFlag)
	}

	service, err := lookupBackend(opts.Backend)
	if err != nil {
		return err
	}

	certificate, closeCert, err := openInput(opts.Certificate)
	if err != nil {
		return fmt.Errorf("reading the certificate: %w", err)
	}

	defer closeCert()

	// The certificate is the source of truth for the KDF parameters: the
	// derivation binds the subkey's fingerprint, so values that did not come
	// from the certificate the sender used cannot recover anything.
	recipient, err := openpgp.ReadRecipient(certificate)
	if err != nil {
		return err
	}

	message, closeMsg, err := openMessage(args)
	if err != nil {
		return err
	}

	defer closeMsg()

	out, closeOut, err := openOutput(opts.Output)
	if err != nil {
		return err
	}

	defer closeOut()

	// Wired lazily, and that matters. Decrypt refuses a message addressed to
	// another certificate before it asks for a shared secret, so building the
	// key service up front would spend an API call — and require credentials —
	// to reject something we already knew was not ours.
	deriver := &lazyDeriver{service: service, keyID: opts.Key, log: p.GetLogger()}

	if err := openpgp.Decrypt(ctx, deriver, recipient, message, out); err != nil {
		return err
	}

	p.GetLogger().Debug("report decrypted")

	return nil
}

// lazyDeriver defers wiring the key service until a secret is actually needed.
//
// It exists to preserve, at the command layer, the property the library
// provides: a message for someone else costs nothing. Constructing the AWS
// deriver eagerly issues a GetPublicKey call, so an eager command would reach
// the network to reject a message it could reject from the certificate alone.
type lazyDeriver struct {
	service encryption.KeyService
	keyID   string
	log     interface {
		Debug(string, ...any)
	}

	deriver encryption.Deriver
}

func (d *lazyDeriver) wire(ctx context.Context) (encryption.Deriver, error) {
	if d.deriver != nil {
		return d.deriver, nil
	}

	d.log.Debug("wiring the key service", "backend", d.service.Name(), "key", d.keyID)

	deriver, err := d.service.Deriver(ctx, d.keyID)
	if err != nil {
		return nil, fmt.Errorf("wiring the key service: %w", err)
	}

	d.deriver = deriver

	return deriver, nil
}

func (d *lazyDeriver) DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error) {
	deriver, err := d.wire(ctx)
	if err != nil {
		return nil, err
	}

	return deriver.DeriveSharedSecret(ctx, peerPoint) //nolint:wrapcheck // the provider's error is the useful one.
}

// CoordinateBytes is asked for after a secret has been derived, so the key
// service is already wired by the time this is reached. If it is not, the
// curve is unknowable and zero is the honest answer — SessionKey rejects it.
func (d *lazyDeriver) CoordinateBytes() int {
	if d.deriver == nil {
		return 0
	}

	return d.deriver.CoordinateBytes()
}

// lookupBackend resolves --backend, defaulting when exactly one is compiled in.
//
// Defaulting only when the choice is unambiguous is deliberate: a tool built
// with one backend should not make its user name it, and a tool built with
// several must not guess which key service to send a request to.
func lookupBackend(name string) (encryption.KeyService, error) {
	if name != "" {
		// The core's error already names what is registered, so it is returned
		// as-is rather than decorated with the same list twice.
		return encryption.LookupKeyService(name) //nolint:wrapcheck // already descriptive.
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

// openMessage returns the encrypted report, from a path argument or stdin.
func openMessage(args []string) (io.Reader, func(), error) {
	if len(args) == 0 || args[0] == "-" {
		return os.Stdin, func() {}, nil
	}

	return openInput(args[0])
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}

	f, err := os.Open(path) //nolint:gosec // the path is the operator's own argument.
	if err != nil {
		return nil, nil, err
	}

	return f, func() { _ = f.Close() }, nil
}

// openOutput writes plaintext to a file or stdout.
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}

	// Owner-only: a decrypted vulnerability report is the most sensitive thing
	// this tool handles, and leaving it group-readable would undo the point of
	// having encrypted it.
	const plaintextMode = 0o600

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, plaintextMode) //nolint:gosec // operator's own path.
	if err != nil {
		return nil, nil, err
	}

	return f, func() { _ = f.Close() }, nil
}
