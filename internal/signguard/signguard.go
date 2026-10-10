// Package signguard refuses a sign request whose local key file is an armored
// OpenPGP secret key. Without it go/signing reports "no PEM block found" about
// a file `keys generate` wrote, which reads as a broken key rather than the
// wrong lane (sigillum#9).
package signguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/setup"
)

const (
	signCommand    = "sign"
	localBackend   = "local"
	formatMinisign = "minisign"
)

// ErrUnsupportedKeyType is returned when the local backend is pointed at an
// armored OpenPGP secret key, which neither sign format reads.
var ErrUnsupportedKeyType = errors.New("unsupported key type")

// Middleware runs CheckKeyFile ahead of the sign command and passes every
// other command straight through.
func Middleware(next setup.RunE) setup.RunE {
	return func(cmd *cobra.Command, args []string) error {
		if cmd.Name() != signCommand {
			return next(cmd, args)
		}

		backend, _ := cmd.Flags().GetString("backend")
		keyID, _ := cmd.Flags().GetString("key-id")
		format, _ := cmd.Flags().GetString("format")

		if err := CheckKeyFile(backend, keyID, format); err != nil {
			return err
		}

		return next(cmd, args)
	}
}

// CheckKeyFile returns ErrUnsupportedKeyType, naming the lane that does take
// the key, when backend is the local backend and keyID is an armored OpenPGP
// secret key. A file it cannot read is left for the backend to report.
func CheckKeyFile(backend, keyID, format string) error {
	if backendType(backend) != localBackend || keyID == "" {
		return nil
	}

	data, ok := readArmoredSecretKey(keyID)
	if !ok {
		return nil
	}

	algorithm := secretKeyAlgorithm(data)

	if format == formatMinisign {
		return fmt.Errorf("%w for --backend local: %s is an armored OpenPGP %s secret key, "+
			"and the local backend reads PEM only; regenerate it with "+
			"keys generate --algorithm ed25519 --private-format pem",
			ErrUnsupportedKeyType, keyID, algorithm)
	}

	return fmt.Errorf("%w for --format openpgp: %s is an armored OpenPGP %s secret key, "+
		"and OpenPGP signing takes an RSA PEM key only (keys generate --algorithm rsa); "+
		"an Ed25519 key signs with --format minisign, from a private half written with --private-format pem",
		ErrUnsupportedKeyType, keyID, algorithm)
}

func backendType(selector string) string {
	if i := strings.IndexAny(selector, ":?"); i >= 0 {
		return selector[:i]
	}

	return selector
}

func readArmoredSecretKey(path string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil || block.Type != openpgp.PrivateKeyType {
		return nil, false
	}

	return data, true
}

func secretKeyAlgorithm(armored []byte) string {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil || len(entities) == 0 || entities[0].PrimaryKey == nil {
		return "(unparseable)"
	}

	algo := entities[0].PrimaryKey.PubKeyAlgo
	if algo == packet.PubKeyAlgoEdDSA || algo == packet.PubKeyAlgoEd25519 {
		return "Ed25519"
	}

	if algo == packet.PubKeyAlgoRSA || algo == packet.PubKeyAlgoRSASignOnly {
		return "RSA"
	}

	return fmt.Sprintf("algorithm %d", algo)
}
