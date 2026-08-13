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

	"gitlab.com/phpboyscout/sigillum/internal/opdest"
	"gitlab.com/phpboyscout/sigillum/internal/openpgp"
	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

// Errors this command reports.
var (
	// ErrMissingFlag reports a required flag that was not supplied.
	ErrMissingFlag = errors.New("required flag not set")

	// ErrNoBackends means the binary was built with no key service compiled
	// in, so there is nothing to decrypt or sign with.
	ErrNoBackends = errors.New("no key service backends are compiled into this binary")

	// ErrStdinTwice means both the certificate and the message were asked for
	// from stdin, which cannot work: reading the first drains it.
	ErrStdinTwice = errors.New("the certificate and the message cannot both come from stdin")

	// ErrTooManyArguments means more than one message was named.
	//
	// Only the first was ever read and the rest were discarded without a word,
	// so an operator who ran the command over a directory of reports was shown
	// one success and told nothing about the others. Refusing is the only
	// honest answer: there is one --output, so decrypting several in one run
	// was never something this could do.
	ErrTooManyArguments = errors.New("only one message can be decrypted at a time")
)

// RunDecrypt reads an encrypted report and writes its plaintext out.
//
// Exactly one operation needs the private key — the ECDH agreement, performed
// by the key service. Everything else happens here: the key derivation, the
// AES key unwrap, and opening the encrypted-data packet.
func RunDecrypt(ctx context.Context, p *props.Props, opts *DecryptOptions, args []string) error {
	if err := checkFlags(opts, args); err != nil {
		return err
	}

	service, err := lookupBackend(opts.Backend)
	if err != nil {
		return err
	}

	certificate, closeCert, err := openInput(opfileafero.Wrap(p.GetFS()), opts.Certificate)
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

	message, closeMsg, err := openMessage(opfileafero.Wrap(p.GetFS()), args)
	if err != nil {
		return err
	}

	defer closeMsg()

	// Owner-only: a decrypted vulnerability report is the most sensitive
	// thing this tool handles, and leaving it group-readable would undo the
	// point of having encrypted it.
	const plaintextMode = 0o600

	out, err := opdest.Open(opfileafero.Wrap(p.GetFS()), opts.Output, plaintextMode, opts.FollowSymlinks)
	if err != nil {
		return err
	}

	// Unconditional, and safe after a commit. Without it a failed run leaves
	// its temporary file behind, and the common failures here are routine — a
	// message addressed to another key, a truncated paste — so they accumulate,
	// owner-readable, sometimes holding part of a report.
	defer out.Abandon()

	// Wired lazily, and that matters. Decrypt refuses a message addressed to
	// another certificate before it asks for a shared secret, so building the
	// key service up front would spend an API call — and require credentials —
	// to reject something we already knew was not ours.
	deriver := &lazyDeriver{service: service, keyID: opts.Key, log: p.GetLogger()}

	if err := openpgp.Decrypt(ctx, deriver, recipient, message, out.Writer); err != nil {
		return err
	}

	// Only now is the destination replaced. A failure above leaves whatever
	// was there untouched — which matters because the common failures are
	// routine: a message addressed to another key, or a truncated paste.
	if err := out.Commit(); err != nil {
		return err
	}

	// Info rather than Debug when the destination resolved elsewhere, because
	// that is the one case worth surfacing without --verbose: the operator
	// asked to follow a link and the plaintext is not where they typed.
	if out.Resolved() {
		p.GetLogger().Info("report decrypted", "path", out.Path(), "requested", out.Requested())
	} else {
		p.GetLogger().Debug("report decrypted", "path", out.Path())
	}

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

	secret, err := deriver.DeriveSharedSecret(ctx, peerPoint)
	if err != nil {
		return nil, fmt.Errorf("deriving the shared secret: %w", err)
	}

	return secret, nil
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
		// The core's error already names what is registered, so this adds the
		// flag that supplied the name rather than repeating the list.
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

// openMessage returns the encrypted report, from a path argument or stdin.
func openMessage(fsys opfile.FS, args []string) (io.Reader, func(), error) {
	if len(args) == 0 || args[0] == "-" {
		return os.Stdin, func() {}, nil
	}

	return openInput(fsys, args[0])
}

func openInput(fsys opfile.FS, path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}

	f, err := opfile.Open(fsys, path)
	if err != nil {
		return nil, nil, err
	}

	return f, func() { _ = f.Close() }, nil
}

// destination is where plaintext goes and both ways of finishing with it.
//
// Carrying abandon alongside commit is the point. An earlier shape returned the
// writer and its commit and dropped the writer itself, which left no caller
// able to reach Abandon at all — so every failed run leaked its temporary file.
// checkFlags refuses the arguments that cannot produce a plaintext.
//
// The stdin pair is the one worth explaining. The certificate and the message
// can each be read from stdin, and the reference documents both — but not that
// they are mutually exclusive. The certificate is read first, and reading it
// drains stdin to EOF, so the message is then empty and the run fails with
// "malformed message: message is empty", pointing the operator at the report
// rather than at the flags.
//
// Refused here rather than left to fail, because the failure names the wrong
// thing and there is no arrangement of the two that works.
func checkFlags(opts *DecryptOptions, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("%w: %d were named (%s)", ErrTooManyArguments, len(args), strings.Join(args, ", "))
	}

	if opts.Certificate == "" {
		return fmt.Errorf("%w: --certificate", ErrMissingFlag)
	}

	if opts.Key == "" {
		return fmt.Errorf("%w: --key", ErrMissingFlag)
	}

	messageFromStdin := len(args) == 0 || args[0] == "-"

	if opts.Certificate == "-" && messageFromStdin {
		return fmt.Errorf(
			"%w: --certificate - reads the certificate from stdin, which leaves nothing for the message;"+
				" give the certificate or the message as a file", ErrStdinTwice)
	}

	return nil
}
