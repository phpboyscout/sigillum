package certificate

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"

	"gitlab.com/phpboyscout/go/encryption"
	"gitlab.com/phpboyscout/go/encryption/certificate"

	"gitlab.com/phpboyscout/sigillum/internal/opdest"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
)

var (
	// ErrMissingFlag reports a required flag that was not supplied.
	ErrMissingFlag = errors.New("required flag not set")

	// ErrUnsupportedCurve reports a key on a curve OpenPGP algorithm 18 does
	// not admit.
	ErrUnsupportedCurve = errors.New("unsupported curve")

	// ErrNoBackends means the binary was built with no key service compiled in.
	ErrNoBackends = errors.New("no key service backends are compiled into this binary")

	// ErrNoPublicKey means the chosen backend cannot expose the encryption
	// key's public half, which a certificate must carry as its subkey.
	ErrNoPublicKey = errors.New("backend cannot expose the encryption key's public half")
)

// ErrOutputOverInput means --output names a key file this run is reading.
//
// Re-exported from opdest so `errors.Is(err, certificate.ErrOutputOverInput)`
// works for a caller holding this package, and so it is the SAME sentinel the
// decrypt command uses. Two independently declared errors with identical text
// is how the guard came to exist in one command and not the other.
var ErrOutputOverInput = opdest.ErrOutputOverInput

// RunCertificate assembles a publishable OpenPGP certificate whose primary and
// encryption subkey are both held by a key service.
//
// Both signatures are made remotely. No private key material exists in this
// process at any point.
func RunCertificate(ctx context.Context, p *props.Props, opts *CertificateOptions, _ []string) error {
	created, err := checkFlags(opts)
	if err != nil {
		return err
	}

	service, err := lookupBackend(opts.Backend)
	if err != nil {
		return err
	}

	signer, err := service.Signer(ctx, opts.CertifyKey)
	if err != nil {
		return fmt.Errorf("wiring the certification key: %w", err)
	}

	deriver, err := service.Deriver(ctx, opts.EncryptKey)
	if err != nil {
		return fmt.Errorf("wiring the encryption key: %w", err)
	}

	subkey, err := subkeyFor(service, deriver, created)
	if err != nil {
		return err
	}

	p.GetLogger().Debug("assembling", "backend", service.Name(), "created", created)

	der, err := certificate.Certificate{
		UserID:  opts.UserId,
		Created: created,
		Subkey:  subkey,
	}.Assemble(signer)
	if err != nil {
		return err
	}

	// World-readable on purpose: a certificate is public, and is meant to
	// be published.
	const certificateMode = 0o644

	out, err := opdest.Open(opfileafero.Wrap(p.GetFS()), opts.Output, certificateMode, opts.FollowSymlinks)
	if err != nil {
		return err
	}

	// Unconditional, and safe after a commit. Without it a failed run leaves
	// its temporary file beside the destination.
	defer out.Abandon()

	if err := write(out.Writer, der, opts.Armor); err != nil {
		return err
	}

	// Info rather than Debug: the operator asked to follow a link, so the
	// one thing worth surfacing without --verbose is that the certificate is
	// not where they typed.
	return commitAndReport(out, p.GetLogger())
}

// commitAndReport puts the certificate in place and then says where it went.
//
// In that order. Announcing first meant a failed commit still told the operator
// the certificate had been written — and the one case this line exists for, a
// certificate that landed somewhere other than they typed, is exactly the case
// where they would go and act on it.
func commitAndReport(out opdest.Destination, log interface {
	Info(msg string, args ...any)
},
) error {
	if err := out.Commit(); err != nil {
		return err
	}

	if out.Resolved() {
		log.Info("certificate written", "path", out.Path(), "requested", out.Requested())
	}

	// A published certificate the web server cannot read is a certificate
	// nobody can encrypt to, and this is the only place that says so.
	if note := out.ModeNote(); note != "" {
		log.Info("the certificate's file mode is not what was asked for", "note", note)
	}

	return nil
}

// checkFlags refuses the arguments that cannot produce a certificate, and
// returns the creation time the rest of the run needs.
//
// Every missing flag is named, in a fixed order.
//
// A map literal was ranged over before, and Go randomises map iteration order,
// so with more than one flag missing the operator was told about a different
// one on each run. That makes support reproducible only by luck, and any test
// asserting a message flaky by construction rather than by accident.
//
// Reporting all of them rather than the first is the same argument taken one
// step further: three omissions should cost one round trip, not three.
func checkFlags(opts *CertificateOptions) (time.Time, error) {
	required := []struct {
		name  string
		value string
	}{
		{"--user-id", opts.UserId},
		{"--certify-key", opts.CertifyKey},
		{"--encrypt-key", opts.EncryptKey},
	}

	var missing []string

	for _, flag := range required {
		if flag.value == "" {
			missing = append(missing, flag.name)
		}
	}

	// --created is checked here rather than only by creationTime below, because
	// creationTime ran after this function had already returned. The doc above
	// promises "three omissions should cost one round trip, not three" and
	// --created was the one omission that always cost its own: an operator who
	// left out --user-id and --created was told about --user-id, fixed it, and
	// was then told about --created.
	//
	// Only its absence is reported here. Whether a supplied value parses, and
	// whether it predates the signature that will cover it, is creationTime's
	// question and needs the value it is complaining about.
	if opts.Created == "" {
		missing = append(missing, "--created")
	}

	// --created keeps its explanation when it is one of the missing flags.
	//
	// Folding it into the plain list cost that, and an e2e scenario caught it:
	// "--created is not set" tells an operator to pass a date, but not that
	// passing a DIFFERENT date next time produces a different certificate that
	// nothing already encrypted will open. That is the whole reason the flag has
	// no default, so it is the one thing the message must carry.
	if opts.Created == "" {
		return time.Time{}, fmt.Errorf(
			"%w: %s. --created (RFC 3339) is hashed into the certificate's fingerprint, "+
				"so it must be the same on every run or the certificate changes identity",
			ErrMissingFlag, strings.Join(missing, ", "))
	}

	if len(missing) > 0 {
		return time.Time{}, fmt.Errorf("%w: %s", ErrMissingFlag, strings.Join(missing, ", "))
	}

	// Before the key service is reached and before anything is staged. With the
	// local backend these two flags name PEM files on disk, so this is the check
	// that stands between a mistyped --output and an unrecoverable private key.
	if err := opdest.CheckNotInput(opts.Output,
		opdest.Input{Flag: "--certify-key", Path: opts.CertifyKey},
		opdest.Input{Flag: "--encrypt-key", Path: opts.EncryptKey},
	); err != nil {
		return time.Time{}, err
	}

	return creationTime(opts.Created)
}

// creationTime parses --created, which is required rather than defaulted.
//
// The creation time is hashed into both fingerprints, and the key derivation
// binds the subkey's. Defaulting to time.Now() would mean every run produced a
// different certificate, and nothing encrypted to yesterday's copy would open.
// Making the operator state it is what makes a certificate reproducible.
func creationTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf(
			"%w: --created (RFC 3339). It is hashed into the certificate's fingerprint, "+
				"so it must be the same on every run or the certificate changes identity",
			ErrMissingFlag)
	}

	created, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing --created: %w", err)
	}

	return created.UTC(), nil
}

// subkeyFor reads the encryption key's public half and shapes it into the
// material an OpenPGP public-key packet carries.
func subkeyFor(
	service encryption.KeyService,
	deriver encryption.Deriver,
	created time.Time,
) (certificate.ECDHPublicKey, error) {
	// Not every key service can expose the encryption key's public half, and a
	// certificate cannot be built without it.
	//
	// encryption.PublicDeriver rather than an anonymous interface written here.
	// The contract was declared in neither backend, so a backend could be
	// complete for decryption and silently unusable for assembly — which is
	// what the local one was, and nothing said so until a certificate failed to
	// build with it. Both backends now assert the named interface at compile
	// time.
	reader, ok := deriver.(encryption.PublicDeriver)
	if !ok {
		return certificate.ECDHPublicKey{}, fmt.Errorf("%w: %q", ErrNoPublicKey, service.Name())
	}

	pub, err := reader.PublicKey()
	if err != nil {
		return certificate.ECDHPublicKey{}, fmt.Errorf("reading the encryption key: %w", err)
	}

	oid, err := curveOID(reader.Curve())
	if err != nil {
		return certificate.ECDHPublicKey{}, err
	}

	// elliptic.Marshal is deprecated; (*ecdsa.PublicKey).ECDH gives the same
	// uncompressed encoding through crypto/ecdh, and refuses a point that is
	// not on the curve — so a key service returning something malformed fails
	// here rather than in a certificate somebody has already published.
	agreement, err := pub.ECDH()
	if err != nil {
		return certificate.ECDHPublicKey{}, fmt.Errorf(
			"the encryption key is not a usable %s point: %w", reader.Curve().Params().Name, err)
	}

	point := agreement.Bytes()

	// The KDF parameters this certificate advertises, paired to the curve as
	// RFC 6637 §12.1 requires.
	//
	// Not a preference: a sender derives the key-encryption key exactly as the
	// packet says, so hardcoding SHA-256/AES-128 would wrap every report to a
	// P-521 key under a 128-bit KEK — valid OpenPGP, honoured by every sender,
	// and invisible.
	hashID, kekAlgID, err := certificate.RecommendedKDF(oid)
	if err != nil {
		return certificate.ECDHPublicKey{}, err
	}

	return certificate.ECDHPublicKey{
		Created:  created,
		CurveOID: oid,
		Point:    point,
		HashID:   hashID,
		KEKAlgID: kekAlgID,
	}, nil
}

// curveOID maps a curve to the object identifier a packet carries, with its
// leading length octet.
func curveOID(c elliptic.Curve) ([]byte, error) {
	// Asked of the core rather than written out here. This was a fourth copy of
	// the same three OIDs — internal/algorithm/curve.go exists because there
	// were two, and hand-writing them again is how a table with one source
	// acquires a second.
	oid, known := encryption.CurveOID(c)
	if !known {
		return nil, fmt.Errorf("%w: %s has no OpenPGP algorithm 18 identifier",
			ErrUnsupportedCurve, c.Params().Name)
	}

	return oid, nil
}

// lookupBackend resolves --backend, defaulting when exactly one is compiled in.
func lookupBackend(name string) (encryption.KeyService, error) {
	if name != "" {
		// The core's error already names what is registered, so it is returned
		// as-is rather than decorated with the same list twice.
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

// write emits the certificate, armoured or binary.
func write(out io.Writer, der []byte, armoured bool) error {
	if !armoured {
		if _, err := out.Write(der); err != nil {
			return fmt.Errorf("writing the certificate: %w", err)
		}

		return nil
	}

	w, err := armor.Encode(out, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("armouring: %w", err)
	}

	if _, err := w.Write(der); err != nil {
		return fmt.Errorf("armouring: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("armouring: %w", err)
	}

	return nil
}
