package steps_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/cucumber/godog"

	"gitlab.com/phpboyscout/go/encryption/certificate"
)

// Steps for the decrypt and certificate commands.
//
// These drive the built binary, like the signing steps, because what is under
// test is the command surface: the flags it demands, the errors it gives, and
// what it decides before reaching for a key service. The cryptography itself is
// covered by unit tests in internal/openpgp and by the provider's integration
// suite.

// --- Given ---

// aPublishedCertificate writes a certificate whose encryption subkey we hold,
// standing in for one published at a security contact address.
func (w *world) aPublishedCertificate() error {
	der, _, err := newTestCertificate()
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(w.dir, "certificate.pgp"), der, 0o600)
}

// aSigningOnlyCertificate writes a certificate with no encryption subkey at
// all, which parses perfectly and can receive nothing.
//
// The subkeys are dropped explicitly, and that is the point of this function
// rather than an incidental detail. It used to serialise pgp.NewEntity's result
// unchanged and call the result signing-only; NewEntity with a nil config adds
// an RSA encryption subkey, so the certificate had one and the scenario
// exercised the opposite of what it said. It passed because the refusal names
// ECDH specifically and an RSA subkey is not ECDH — the right answer reached
// through a case nobody meant to write.
//
// Both cases are worth covering, so the other one is now
// [world.aCertificateWithAnRSAEncryptionSubkey] and this one is what its name
// says.
func (w *world) aSigningOnlyCertificate() error {
	entity, err := pgp.NewEntity("signing only", "", "sign@example.invalid", nil)
	if err != nil {
		return err
	}

	entity.Subkeys = nil

	return w.writeCertificate(entity, false)
}

// aCertificateWithAnRSAEncryptionSubkey writes a certificate that can receive
// mail, but not from us.
//
// This module implements the RFC 6637 ECDH construction, so an RSA encryption
// subkey is a certificate we cannot encrypt to even though it is perfectly
// valid and other implementations can. Distinct from having no subkey at all,
// and reached by a different branch.
func (w *world) aCertificateWithAnRSAEncryptionSubkey() error {
	entity, err := pgp.NewEntity("rsa recipient", "", "rsa@example.invalid", nil)
	if err != nil {
		return err
	}

	return w.writeCertificate(entity, true)
}

// writeCertificate serialises an entity and checks it carries the encryption
// subkey the caller expected, because both fixtures above are defined by what
// they do or do not have and neither test can see it.
func (w *world) writeCertificate(entity *pgp.Entity, wantEncryptionSubkey bool) error {
	if _, ok := entity.EncryptionKey(entity.PrimaryKey.CreationTime); ok != wantEncryptionSubkey {
		return fmt.Errorf("the fixture has an encryption subkey = %t, want %t", ok, wantEncryptionSubkey)
	}

	var buf bytes.Buffer
	if err := entity.Serialize(&buf); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(w.dir, "certificate.pgp"), buf.Bytes(), 0o600)
}

// aReportForSomebodyElse encrypts to a different certificate entirely, which is
// the ordinary situation when several are in play.
func (w *world) aReportForSomebodyElse() error {
	der, _, err := newTestCertificate()
	if err != nil {
		return err
	}

	entities, err := pgp.ReadKeyRing(bytes.NewReader(der))
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	out, err := pgp.Encrypt(&buf, entities, nil, nil, nil)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(out, "not your vulnerability"); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(w.dir, "report.pgp"), buf.Bytes(), 0o600)
}

func (w *world) aReportThatIsNotOpenPGP() error {
	return os.WriteFile(filepath.Join(w.dir, "report.pgp"),
		[]byte("there is a bug on your website\n"), 0o600)
}

// --- When ---

func (w *world) decryptTheReport() error {
	return w.decryptWithBackend("")
}

func (w *world) decryptWithBackend(backend string) error {
	args := []string{
		"decrypt",
		"--certificate", filepath.Join(w.dir, "certificate.pgp"),
		"--key", encryptAlias,
	}

	if backend != "" {
		args = append(args, "--backend", backend)
	}

	args = append(args, filepath.Join(w.dir, "report.pgp"))

	// run records the command's exit status on the world and returns only a
	// harness failure — the binary not building, say. The exit status is what
	// these scenarios assert on, so it stays on the world; the harness failure
	// is returned, because a scenario that could not run has not passed.
	return w.run(args...)
}

// Key identifiers used by the scenarios that never reach a key service.
//
// Hoisted rather than inlined beside their flags: gitleaks' generic-api-key
// rule reads `"--encrypt-key", "…"` as a credential assignment. These are KMS
// aliases that protect nothing and refer to nothing, so the fix is to stop
// tripping the scanner rather than to allowlist a path.
const (
	certifyAlias = "alias/certify"
	encryptAlias = "alias/encrypt"
)

func (w *world) decryptWithoutACertificate() error {
	return w.run("decrypt", "--key", encryptAlias)
}

func (w *world) assembleWithoutACreationTime() error {
	return w.run("certificate",
		"--user-id", "Security <security@example.invalid>",
		"--certify-key", certifyAlias,
		"--encrypt-key", encryptAlias)
}

// --- Then ---

func (w *world) failsSaying(fragment string) error {
	if w.exitErr == nil {
		return fmt.Errorf("the command succeeded; stdout was %q", w.stdout)
	}

	if !strings.Contains(w.stderr, fragment) {
		return fmt.Errorf("stderr does not mention %q; it was: %s", fragment, w.stderr)
	}

	return nil
}

func (w *world) failsAddressedElsewhere() error {
	return w.failsSaying("addressed to")
}

func (w *world) failsMalformed() error {
	return w.failsSaying("malformed message")
}

func (w *world) failsNoEncryptionSubkey() error {
	return w.failsSaying("no ECDH encryption subkey")
}

func (w *world) failsNamingFlag(flag string) error {
	if err := w.failsSaying("required flag not set"); err != nil {
		return err
	}

	return w.failsSaying(flag)
}

func (w *world) failsListingBackend(name string) error {
	return w.failsSaying(name)
}

func (w *world) explainsTheTimeIsIdentity() error {
	return w.failsSaying("fingerprint")
}

// noKeyServiceWasContacted is the point of the lazy wiring.
//
// The AWS deriver reads its key at construction, so any contact would need
// credentials and a region. The suite runs with neither, which means a command
// that reached the key service could not produce the clean "addressed
// elsewhere" refusal being asserted — it would fail on configuration instead.
func (w *world) noKeyServiceWasContacted() error {
	for _, leak := range []string{"AWS", "credential", "region", "kms:"} {
		if strings.Contains(w.stderr, leak) {
			return fmt.Errorf("the key service was reached before the recipient check: %s", w.stderr)
		}
	}

	return nil
}

// registerDecryptSteps binds the decrypt and certificate steps.
func registerDecryptSteps(ctx *godog.ScenarioContext, w *world) {
	ctx.Given(`^a published certificate$`, w.aPublishedCertificate)
	ctx.Given(`^a signing-only certificate$`, w.aSigningOnlyCertificate)
	ctx.Given(`^a certificate whose encryption subkey is RSA$`, w.aCertificateWithAnRSAEncryptionSubkey)
	ctx.Given(`^a report encrypted to somebody else's certificate$`, w.aReportForSomebodyElse)
	ctx.Given(`^a report that is not an OpenPGP message$`, w.aReportThatIsNotOpenPGP)

	ctx.When(`^I decrypt the report$`, w.decryptTheReport)
	ctx.When(`^I decrypt the report with backend "([^"]*)"$`, w.decryptWithBackend)
	ctx.When(`^I decrypt a report without naming a certificate$`, w.decryptWithoutACertificate)
	ctx.When(`^I assemble a certificate without a creation time$`, w.assembleWithoutACreationTime)

	ctx.Then(`^it fails saying the message is addressed elsewhere$`, w.failsAddressedElsewhere)
	ctx.Then(`^it fails saying the message is malformed$`, w.failsMalformed)
	ctx.Then(`^it fails saying there is no encryption subkey$`, w.failsNoEncryptionSubkey)
	ctx.Then(`^it fails naming the missing flag "([^"]*)"$`, w.failsNamingFlag)
	ctx.Then(`^it fails listing "([^"]*)" as available$`, w.failsListingBackend)
	ctx.Then(`^no key service was contacted$`, w.noKeyServiceWasContacted)
	ctx.Then(`^it explains that the time is part of the certificate's identity$`, w.explainsTheTimeIsIdentity)
}

// --- fixtures ---

type testSigner struct{ key *rsa.PrivateKey }

func (s testSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s testSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, s.key, opts.HashFunc(), digest)
}

// newTestCertificate assembles a certificate through the core, so the scenarios
// exercise the same packets a real one carries.
func newTestCertificate() ([]byte, *ecdh.PrivateKey, error) {
	created := time.Unix(1_700_000_000, 0).UTC()

	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	agreement, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	der, err := certificate.Certificate{
		UserID:  "Security <security@example.invalid>",
		Created: created,
		Subkey: certificate.ECDHPublicKey{
			Created:  created,
			CurveOID: []byte{0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
			Point:    agreement.PublicKey().Bytes(),
			HashID:   8, // SHA-256
			KEKAlgID: 7, // AES-128
		},
	}.Assemble(testSigner{key: signing})
	if err != nil {
		return nil, nil, err
	}

	return der, agreement, nil
}
