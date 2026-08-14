package certificate

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"

	"gitlab.com/phpboyscout/go/encryption"
	"gitlab.com/phpboyscout/go/encryption/certificate"

	"gitlab.com/phpboyscout/sigillum/internal/opdest"
	"gitlab.com/phpboyscout/sigillum/internal/opfile"
	"gitlab.com/phpboyscout/sigillum/internal/opfile/opfileafero"
	"gitlab.com/phpboyscout/sigillum/internal/oprun"
)

var (
	// ErrMissingFlag and ErrNoBackends are the spine's, re-exported so the two
	// commands share one declaration rather than a copy each.
	ErrMissingFlag = oprun.ErrMissingFlag
	ErrNoBackends  = oprun.ErrNoBackends

	// ErrUnsupportedCurve reports a key on a curve OpenPGP algorithm 18 does
	// not admit.
	ErrUnsupportedCurve = errors.New("unsupported curve")

	// ErrReproducibleNeedsTime means --reproducible was set without --signed-at.
	ErrReproducibleNeedsTime = errors.New("--reproducible requires --signed-at")
)

// ErrNoPublicKey means the chosen backend cannot expose the encryption key's
// public half, which a certificate must carry as its subkey.
//
// The core's sentinel, re-exported, so this command wraps the same error a
// backend returns rather than declaring a parallel one with the same meaning —
// the drift the design review flagged as a class. errors.Is against either the
// core value or this one matches.
var ErrNoPublicKey = encryption.ErrNoPublicKey

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

	service, err := oprun.LookupBackend(opts.Backend)
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

	der, err := assemble(opts, created, subkey, signer, p.GetLogger())
	if err != nil {
		return err
	}

	out, err := openCertificateOutput(opfileafero.Wrap(p.GetFS()), opts)
	if err != nil {
		return err
	}

	// Unconditional, and safe after a commit. Without it a failed run leaves
	// its temporary file beside the destination.
	defer out.Abandon()

	if err := write(out.Writer, der, opts.Armor); err != nil {
		return err
	}

	// Committed before it is announced: announcing first meant a failed commit
	// still told the operator the certificate had been written. Where it landed
	// and whether its mode is exact are said once, by opdest.Report.
	if err := out.Commit(); err != nil {
		return err
	}

	out.Report(p.GetLogger(), "certificate written")

	return nil
}

// assemble builds the certificate, applying the reproducibility options the
// operator asked for.
func assemble(
	opts *CertificateOptions,
	created time.Time,
	subkey certificate.ECDHPublicKey,
	signer crypto.Signer,
	log interface {
		Info(msg string, args ...any)
	},
) ([]byte, error) {
	assembleOpts, err := reproducibilityOptions(opts, log)
	if err != nil {
		return nil, err
	}

	return certificate.Certificate{
		UserID:  opts.UserId,
		Created: created,
		Subkey:  subkey,
	}.Assemble(signer, assembleOpts...)
}

// reproducibilityOptions turns --signed-at and --reproducible into the assembly
// options that make output deterministic, or leaves assembly stamping the
// current time.
//
// This is where the certificate command makes good on what its docs promise.
// Assemble was called with no options, so both signatures were stamped with the
// clock and carried a random salt — every run produced different bytes, while
// --created's help said it "must not change between runs" and creationTime's
// error called that the thing "that makes a certificate reproducible" (#19).
// --created fixes the certificate's IDENTITY, the fingerprint; it does not fix
// the bytes, and never could while the signature time and salt varied.
//
// --signed-at pins the signature time. --reproducible additionally drops the
// salt, and REQUIRES --signed-at rather than defaulting the signature time to
// now: defaulting it would reintroduce the rotation ambiguity WithSignatureTime
// exists to avoid — two assemblies at the same instant produce bindings a reader
// cannot order — so the operator states the instant explicitly. The chosen time
// is logged so a later reproduction can supply the same one.
func reproducibilityOptions(opts *CertificateOptions, log interface {
	Info(msg string, args ...any)
},
) ([]certificate.AssembleOption, error) {
	if opts.Reproducible && opts.SignedAt == "" {
		return nil, ErrReproducibleNeedsTime
	}

	var out []certificate.AssembleOption

	if opts.SignedAt != "" {
		signedAt, err := time.Parse(time.RFC3339, opts.SignedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing --signed-at: %w", err)
		}

		out = append(out, certificate.WithSignatureTime(signedAt.UTC()))
		log.Info("signing at the given time", "signed-at", signedAt.UTC().Format(time.RFC3339))
	}

	if opts.Reproducible {
		out = append(out, certificate.WithoutSignatureSalt())
	}

	return out, nil
}

// checkFlags refuses the arguments that cannot produce a certificate, and
// returns the creation time the rest of the run needs.
//
// The missing-flag collection and the ordering guarantee live in
// oprun.RequireFlags now, shared with the decrypt command; this states which
// flags this command requires and adds the checks that are its own.
func checkFlags(opts *CertificateOptions) (time.Time, error) {
	// Every missing flag named at once, through the shared collector — and
	// --created checked here rather than only by creationTime below, which ran
	// after this had returned so an operator missing --user-id and --created was
	// told about one, then the other. Its Why carries the fingerprint sentence
	// an e2e scenario pins: --created has no default because its value is hashed
	// into the certificate's identity.
	if err := oprun.RequireFlags(
		oprun.Flag{Name: "--user-id", Value: opts.UserId},
		oprun.Flag{Name: "--certify-key", Value: opts.CertifyKey},
		oprun.Flag{Name: "--encrypt-key", Value: opts.EncryptKey},
		oprun.Flag{
			Name:  "--created",
			Value: opts.Created,
			Why: "--created (RFC 3339) is hashed into the certificate's fingerprint, " +
				"so it must be the same on every run or the certificate changes identity",
		},
	); err != nil {
		return time.Time{}, err
	}

	// Before the key service is reached and before anything is staged. With the
	// local backend these two flags name PEM files on disk, so this is the check
	// that stands between a mistyped --output and an unrecoverable private key.
	if err := opdest.CheckNotInput(opts.Output, certificateInputs(opts)...); err != nil {
		return time.Time{}, err
	}

	return creationTime(opts.Created)
}

// certificateInputs is every file this run reads, named by the flag that
// supplied it. Shared by the lexical preflight and the post-resolution identity
// check so the two agree on what an input is.
func certificateInputs(opts *CertificateOptions) []opdest.Input {
	return []opdest.Input{
		{Flag: "--certify-key", Path: opts.CertifyKey},
		{Flag: "--encrypt-key", Path: opts.EncryptKey},
	}
}

// openCertificateOutput stages the destination and refuses one whose resolved
// path is a key file this run reads.
//
// The preflight in checkFlags compared the typed path; this catches a followed
// symbolic link whose resolved destination is one of the key files, before the
// certificate is written over a private key. On refusal the staged file is
// discarded, since the caller never receives the destination to defer Abandon.
func openCertificateOutput(fsys opfile.FS, opts *CertificateOptions) (opdest.Destination, error) {
	// World-readable on purpose: a certificate is public, and is meant to be
	// published.
	const certificateMode = 0o644

	out, err := opdest.Open(fsys, opts.Output, certificateMode, opts.FollowSymlinks)
	if err != nil {
		return opdest.Destination{}, err
	}

	if err := opdest.CheckResolvedNotInput(fsys, out.Path(), certificateInputs(opts)...); err != nil {
		out.Abandon()

		return opdest.Destination{}, err
	}

	return out, nil
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
	// Asked by CALLING PublicKey, not by a type assertion. Whether a key service
	// can hand back its public half is a property of the value — the local
	// backend held a nil half for an X25519 key while satisfying the old
	// optional interface at the type level, so the assertion passed and the
	// assembly path panicked. PublicKey is a mandatory method now: a service
	// that cannot answer returns encryption.ErrNoPublicKey, and that is the
	// question, asked the one way it is answerable.
	pub, err := deriver.PublicKey()
	if err != nil {
		if errors.Is(err, encryption.ErrNoPublicKey) {
			return certificate.ECDHPublicKey{}, fmt.Errorf("%w: %q", ErrNoPublicKey, service.Name())
		}

		return certificate.ECDHPublicKey{}, fmt.Errorf("reading the encryption key: %w", err)
	}

	// The curve rides on the returned key rather than a separate accessor: there
	// is no errorless Curve() to dereference a nil public half through.
	oid, err := curveOID(pub.Curve)
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
			"the encryption key is not a usable %s point: %w", pub.Curve.Params().Name, err)
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
