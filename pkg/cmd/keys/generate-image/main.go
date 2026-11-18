package generate_image

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

const (
	flagOutput        = "output"
	flagPrivateOutput = "private-output"

	privateKeyBlock = "PRIVATE KEY"
	publicKeyBlock  = "PUBLIC KEY"
)

// ErrSameOutput is returned when --output and --private-output name one file,
// which would leave the public key written over the private one.
var ErrSameOutput = errors.NewSentinel("sigillum.key_file_same_output",
	"--"+flagOutput+" and --"+flagPrivateOutput+" name the same file")

// RunGenerateImage makes an ECDSA P-256 keypair and writes both halves, or
// neither.
func RunGenerateImage(_ context.Context, p *props.Props, opts *GenerateImageOptions, _ []string) error {
	private, public, err := generatePair()
	if err != nil {
		return err
	}

	err = signcmd.WriteKeyPair(
		keyfile.Half{Path: opts.PrivateOutput, Data: private},
		keyfile.Half{Path: opts.Output, Data: public},
		opts.Force,
	)
	if signcmd.IsSameOutput(err) {
		return errors.Wrapf(ErrSameOutput, "%q and %q", opts.Output, opts.PrivateOutput)
	}

	if err != nil {
		return err //nolint:wrapcheck // names the path and the fault
	}

	p.GetLogger().Info("Generated image-signing keypair", "public", opts.Output, "private", opts.PrivateOutput)

	return nil
}

// generatePair returns a new key as PKCS#8 and PKIX PEM, the forms the local
// backend and cosign read.
func generatePair() (private, public []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ECDSA P-256 key")
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "encoding the private key")
	}

	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, errors.Wrap(err, "encoding the public key")
	}

	return pem.EncodeToMemory(&pem.Block{Type: privateKeyBlock, Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: publicKeyBlock, Bytes: publicDER}),
		nil
}
