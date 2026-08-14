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

	// Wrapped once. The certificate, the message and the output all go through
	// the same filesystem, and building three adapters over it left that fact
	// to be inferred by checking three call sites — and would let them diverge
	// silently if Wrap ever carried state.
	fsys := opfileafero.Wrap(p.GetFS())

	certificate, closeCert, err := openInput(fsys, opts.Certificate)
	if err != nil {
		return fmt.Errorf("reading the certificate: %w", err)
	}

	defer closeCert()

	// The certificate is the source of truth for the KDF parameters: the
	// derivation binds the subkey's fingerprint, so values that did not come
	// from the certificate the sender used cannot recover anything.
	recipient, findings, err := openpgp.ReadRecipient(certificate)

	// Reported before the error is checked, so a certificate that failed to
	// yield a usable subkey still surfaces what the parser noticed on the way —
	// an unevaluable revocation is exactly the finding that matters most when
	// there is no subkey to fall back to.
	reportNotes(p.GetLogger(), findings)

	if err != nil {
		return err
	}

	message, closeMsg, err := openMessage(fsys, args)
	if err != nil {
		return err
	}

	defer closeMsg()

	// Owner-only: a decrypted vulnerability report is the most sensitive
	// thing this tool handles, and leaving it group-readable would undo the
	// point of having encrypted it.
	const plaintextMode = 0o600

	out, err := opdest.Open(fsys, opts.Output, plaintextMode, opts.FollowSymlinks)
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

	// Narrower than asked for rather than broader, so this is not a
	// confidentiality problem — but a report the operator expected at 0600 and
	// got at 0400 is worth a line.
	if note := out.ModeNote(); note != "" {
		p.GetLogger().Info("the output file's mode is not what was asked for", "note", note)
	}

	reportDestination(p.GetLogger(), out)

	return nil
}

// reportDestination tells the operator where the plaintext went, and whether
// the file mode is what was asked for.
//
// Info rather than Debug when the destination resolved elsewhere, because that
// is the one case worth surfacing without --verbose: the operator asked to
// follow a link and the plaintext is not where they typed.
func reportDestination(log interface {
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
}, out opdest.Destination,
) {
	if out.Resolved() {
		log.Info("report decrypted", "path", out.Path(), "requested", out.Requested())
	} else {
		log.Debug("report decrypted", "path", out.Path())
	}

	// Narrower than asked for rather than broader, so not a confidentiality
	// problem — but a report the operator expected at 0600 and got at 0400 is
	// worth a line.
	if note := out.ModeNote(); note != "" {
		log.Info("the output file's mode is not what was asked for", "note", note)
	}
}

// warner is the sliver of the logger this needs.
//
// Narrowed so the reporting can be tested without standing up a logger, which
// is the difference between this having a test and not.
type warner interface {
	Warn(msg string, args ...any)
}

// reportNotes tells the operator what the parser found and could not decide.
//
// Warnings, not Debug, and not swallowed. certificate.Parse reports a
// revocation it cannot evaluate, and a certificate that did not parse to its
// end, as notes rather than refusals — refusing the first would let anyone
// retire a published encryption key by appending a packet, and refusing the
// second would make a stray trailing octet fatal. Neither is a decision the
// library can make, and the operator is who can: they may hold the revoker's
// key, or know the certificate was truncated in transit.
//
// A note nobody reads is the same silence this was changed to break, which is
// why it is a function with a test rather than a loop inside a long one.
//
// It takes the findings directly rather than reading them off the Recipient,
// because the parser now returns them as their own value — and reports them
// even when parsing failed, so a certificate with no usable subkey but a
// revocation nobody could evaluate still tells the operator what was seen.
func reportNotes(log warner, findings openpgp.Findings) {
	for _, note := range findings {
		log.Warn("the certificate carries something worth checking", "note", note)
	}
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

	// wired records that construction has been attempted, so a failure is as
	// final as a success for the life of this run.
	wired bool
	err   error
}

func (d *lazyDeriver) wire(ctx context.Context) (encryption.Deriver, error) {
	// The FAILURE is remembered too, not only the success.
	//
	// Caching success alone meant a key service that could not be constructed
	// was rebuilt for every distinct ephemeral point the message carried, up to
	// the derivation ceiling — and for the AWS backend each attempt is a full
	// SDK config load plus a billed kms:GetPublicKey. A message a stranger
	// composed turned one misconfiguration into sixteen of them, and showed the
	// operator the same error sixteen times so they could not tell whether it
	// was one problem or several.
	//
	// Scoped to a single Decrypt, so nothing is remembered across runs and a
	// transient failure is not turned into a permanent verdict.
	if d.wired {
		return d.deriver, d.err
	}

	d.wired = true

	d.log.Debug("wiring the key service", "backend", d.service.Name(), "key", d.keyID)

	deriver, err := d.service.Deriver(ctx, d.keyID)
	if err != nil {
		d.err = fmt.Errorf("wiring the key service: %w", err)

		return nil, d.err
	}

	d.deriver = deriver

	return deriver, nil
}

func (d *lazyDeriver) DeriveSharedSecret(ctx context.Context, peerPoint []byte) ([]byte, error) {
	deriver, err := d.wire(ctx)
	if err != nil {
		return nil, err
	}

	// Returned unwrapped. internal/openpgp's unwrap already prefixes this with
	// "deriving the shared secret", so wrapping it again produced the phrase
	// twice in one line — and the second copy carried no information the first
	// did not, only the impression that two different things had gone wrong.
	return deriver.DeriveSharedSecret(ctx, peerPoint)
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

// openMessage opens the message named by the positional argument, or standard
// input when there is none.
//
// The "-" sentinel is decided in openInput and only there. This used to test
// for it too, one line before delegating to the function that tests for it
// again — so the rule lived in two places and could have drifted in either.
func openMessage(fsys opfile.FS, args []string) (io.Reader, func(), error) {
	if len(args) == 0 {
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

// ErrOutputOverInput means --output names a file this run is reading.
//
// Re-exported from opdest, which owns both the guard and the destination it
// protects. It used to be declared here, and the certificate command declared
// its own copy of nothing at all: that command staged its output over an input
// with no check for a whole release, because a guard written into one command
// has to be remembered separately for the next.
var ErrOutputOverInput = opdest.ErrOutputOverInput

// checkOutput refuses an --output that names a file this run reads.
//
// The inputs are passed in a fixed order. This function used to build a map and
// range over it, and Go randomises map iteration order, so with both the
// certificate and the message colliding the error named a different one on each
// run — the same defect checkFlags was fixed for, reintroduced two hundred lines
// below the test that guards against it.
func checkOutput(opts *DecryptOptions, args []string) error {
	// --key is an input. Under the local backend it is a PEM path — the e2e
	// suite passes one — so an --output naming it replaced the private key with
	// the decrypted report in a run that exited 0: round 8's top finding,
	// reproduced in this command one day after its sibling was fixed
	// (design-review N2). Under aws-kms the flag carries an alias and the
	// cleaned-string comparison almost never fires; when it does, refusing a
	// file literally named like the alias is the cheap side of the trade.
	//
	// The D4 spine makes this list declarative with a completeness test; until
	// then it is maintained by hand, which is exactly how the omission
	// happened.
	inputs := []opdest.Input{
		{Flag: "--certificate", Path: opts.Certificate},
		{Flag: "--key", Path: opts.Key},
	}
	if len(args) == 1 {
		inputs = append(inputs, opdest.Input{Flag: "the message", Path: args[0]})
	}

	return opdest.CheckNotInput(opts.Output, inputs...)
}

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
	if err := checkOutput(opts, args); err != nil {
		return err
	}

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
