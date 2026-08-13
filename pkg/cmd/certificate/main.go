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

	if len(missing) > 0 {
		return time.Time{}, fmt.Errorf("%w: %s", ErrMissingFlag, strings.Join(missing, ", "))
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
	switch c {
	case elliptic.P256():
		return []byte{0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, nil
	case elliptic.P384():
		return []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}, nil
	case elliptic.P521():
		return []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}, nil
	default:
		return nil, fmt.Errorf("%w: %s has no OpenPGP algorithm 18 identifier", ErrUnsupportedCurve, c.Params().Name)
	}
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
