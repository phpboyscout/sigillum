package signguard_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/sigillum/internal/signguard"
)

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func wantRefusal(t *testing.T, err error, mentions ...string) {
	t.Helper()

	if !errors.Is(err, signguard.ErrUnsupportedKeyType) {
		t.Fatalf("got %v, want ErrUnsupportedKeyType", err)
	}

	for _, m := range mentions {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("error %q does not mention %q", err, m)
		}
	}
}

func writeOpenPGPSecretKey(t *testing.T) string {
	t.Helper()

	entity, err := openpgp.NewEntity("t", "", "t@example.org", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	must(t, err)

	var buf bytes.Buffer

	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	must(t, err)
	must(t, entity.SerializePrivate(w, nil))
	must(t, w.Close())

	path := filepath.Join(t.TempDir(), "ed.priv.asc")
	must(t, os.WriteFile(path, buf.Bytes(), 0o600))

	return path
}

func writeEd25519PEM(t *testing.T) string {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(t, err)

	path := filepath.Join(t.TempDir(), "ed.pem")
	must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	return path
}

func TestCheckKeyFile_OpenPGPLaneNamesTheKeyTypeAndTheLaneThatTakesIt(t *testing.T) {
	t.Parallel()

	err := signguard.CheckKeyFile("local", writeOpenPGPSecretKey(t), "openpgp")

	wantRefusal(t, err, "--format openpgp", "Ed25519", "--format minisign")
}

func TestCheckKeyFile_MinisignLaneNamesThePrivateFormatItNeeds(t *testing.T) {
	t.Parallel()

	err := signguard.CheckKeyFile("local", writeOpenPGPSecretKey(t), "minisign")

	wantRefusal(t, err, "Ed25519", "--private-format pem")
}

func TestCheckKeyFile_NamedLocalInstanceIsChecked(t *testing.T) {
	t.Parallel()

	err := signguard.CheckKeyFile("local:staging?x=y", writeOpenPGPSecretKey(t), "openpgp")

	wantRefusal(t, err)
}

func TestCheckKeyFile_LeavesEverythingElseToTheBackend(t *testing.T) {
	t.Parallel()

	armored := writeOpenPGPSecretKey(t)

	cases := map[string]struct{ backend, keyID string }{
		"a PEM key":                      {"local", writeEd25519PEM(t)},
		"a missing file":                 {"local", filepath.Join(t.TempDir(), "absent.pem")},
		"no key id":                      {"local", ""},
		"a non-local backend":            {"aws-kms", armored},
		"a backend whose name has local": {"localish", armored},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := signguard.CheckKeyFile(tc.backend, tc.keyID, "openpgp"); err != nil {
				t.Errorf("got %v, want the file left to the backend", err)
			}
		})
	}
}

func TestMiddleware_ChecksOnlyTheSignCommand(t *testing.T) {
	t.Parallel()

	armored := writeOpenPGPSecretKey(t)

	newCmd := func(name string) *cobra.Command {
		cmd := &cobra.Command{Use: name}
		cmd.Flags().String("backend", "local", "")
		cmd.Flags().String("key-id", armored, "")
		cmd.Flags().String("format", "openpgp", "")

		return cmd
	}

	called := false
	next := func(*cobra.Command, []string) error {
		called = true

		return nil
	}

	wantRefusal(t, signguard.Middleware(next)(newCmd("sign"), nil))

	if called {
		t.Fatal("sign ran after its key file was refused")
	}

	must(t, signguard.Middleware(next)(newCmd("mint"), nil))

	if !called {
		t.Fatal("a command other than sign was not passed through")
	}
}
