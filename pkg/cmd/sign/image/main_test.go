package image_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	sigstore "gitlab.com/phpboyscout/go/signing-sigstore"
	"gitlab.com/phpboyscout/go/signing/local"

	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	generate_image "gitlab.com/phpboyscout/sigillum/pkg/cmd/keys/generate-image"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/sign/image"
)

const (
	registryUser     = "ci-user"
	registryPassword = "ci-registry-password"

	signatureAnnotation = "dev.cosignproject.cosign/signature"
)

// localBackend reads key files as the local backend does, and records the key
// IDs it was asked for.
type localBackend struct{ keyIDs []string }

func (b *localBackend) Name() string { return "local" }

func (b *localBackend) NewSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	b.keyIDs = append(b.keyIDs, keyID)

	return local.NewSigner(ctx, keyID)
}

func registryAuth() remote.Option {
	return remote.WithAuth(&authn.Basic{Username: registryUser, Password: registryPassword})
}

// newRegistry serves an in-process registry that demands Basic credentials,
// so a test can prove which credentials reached it.
func newRegistry(t *testing.T) string {
	t.Helper()

	handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if user, pass, ok := req.BasicAuth(); !ok || user != registryUser || pass != registryPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		handler.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

func pushImage(t *testing.T, host string) name.Digest {
	t.Helper()

	img, err := random.Image(64, 1)
	require.NoError(t, err)

	tag, err := name.NewTag(host + "/estate/app:v1")
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img, registryAuth()))

	h, err := img.Digest()
	require.NoError(t, err)

	return tag.Digest(h.String())
}

// generateKey runs keys generate-image, so sign image is tested with the key
// that command writes.
func generateKey(t *testing.T) (publicPath, privatePath string) {
	t.Helper()

	dir := t.TempDir()
	publicPath = filepath.Join(dir, "image.pub")
	privatePath = filepath.Join(dir, "image.key")

	require.NoError(t, signtest.Execute(t, generate_image.NewCmdGenerateImage(signtest.Props()).Command,
		"--output", publicPath, "--private-output", privatePath))

	return publicPath, privatePath
}

// fixture is a registry holding one image, a generated key, and the local
// backend registered to sign with it.
type fixture struct {
	image      name.Digest
	publicPath string
	keyPath    string
	backend    *localBackend
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	backend := &localBackend{}
	signtest.Register(t, backend)

	publicPath, keyPath := generateKey(t)

	return fixture{
		image:      pushImage(t, newRegistry(t)),
		publicPath: publicPath,
		keyPath:    keyPath,
		backend:    backend,
	}
}

func (f fixture) withCredentials(reference string) []string {
	return []string{
		"--backend", "local", "--key-id", f.keyPath,
		"--registry-username", registryUser, "--registry-password-stdin", reference,
	}
}

func (f fixture) tags(t *testing.T) []string {
	t.Helper()

	tags, err := remote.List(f.image.Repository, registryAuth())
	require.NoError(t, err)

	return tags
}

func (f fixture) signatureTag() name.Tag {
	return f.image.Tag(strings.Replace(f.image.DigestStr(), ":", "-", 1) + ".sig")
}

func run(t *testing.T, p *props.Props, stdin string, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer

	cmd := image.NewCmdImage(p).Command
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.ExecuteContext(context.Background())

	return out.String(), err
}

func assertLegacySignatureVerifies(t *testing.T, tag name.Tag, publicPath string) {
	t.Helper()

	raw, err := os.ReadFile(publicPath)
	require.NoError(t, err)

	block, _ := pem.Decode(raw)
	require.NotNil(t, block)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	img, err := remote.Image(tag, registryAuth())
	require.NoError(t, err)

	m, err := img.Manifest()
	require.NoError(t, err)
	require.Len(t, m.Layers, 1)

	layer, err := img.LayerByDigest(m.Layers[0].Digest)
	require.NoError(t, err)

	rc, err := layer.Compressed()
	require.NoError(t, err)

	defer func() { _ = rc.Close() }()

	payload, err := io.ReadAll(rc)
	require.NoError(t, err)

	sig, err := base64.StdEncoding.DecodeString(m.Layers[0].Annotations[signatureAnnotation])
	require.NoError(t, err)

	sum := sha256.Sum256(payload)
	assert.True(t, ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), sum[:], sig), "the pushed signature verifies against the public half")
}

func TestImage_SignsWithAGeneratedKey(t *testing.T) {
	f := newFixture(t)
	logs := logger.NewBuffer()

	out, err := run(t, &props.Props{Logger: logs}, registryPassword+"\n", f.withCredentials(f.image.String())...)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	require.Len(t, lines, 2, "stdout holds the two locations and nothing else")
	assert.Equal(t, "signature: "+f.signatureTag().String(), lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "bundle: "+f.image.Repository.String()+"@sha256:"), lines[1])

	assertLegacySignatureVerifies(t, f.signatureTag(), f.publicPath)

	entries := logs.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "Signed image", entries[0].Message)
	assert.Equal(t, []any{"image", f.image.String(), "backend", "local"}, entries[0].Keyvals)
}

func TestImage_ReadsOnlyTheFirstLineOfStdinAsThePassword(t *testing.T) {
	f := newFixture(t)

	for name, stdin := range map[string]string{
		"no line ending":      registryPassword,
		"a carriage return":   registryPassword + "\r\n",
		"more lines after it": registryPassword + "\nnot part of the password\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, signtest.Props(), stdin, f.withCredentials(f.image.String())...)
			require.NoError(t, err)
		})
	}
}

func TestImage_FallsBackToTheDockerConfig(t *testing.T) {
	f := newFixture(t)

	auth := base64.StdEncoding.EncodeToString([]byte(registryUser + ":" + registryPassword))
	config, err := json.Marshal(map[string]any{
		"auths": map[string]any{f.image.RegistryStr(): map[string]string{"auth": auth}},
	})
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), config, 0o600))
	t.Setenv("DOCKER_CONFIG", dir)

	_, err = run(t, signtest.Props(), "", "--backend", "local", "--key-id", f.keyPath, f.image.String())
	require.NoError(t, err)

	assert.Contains(t, f.tags(t), f.signatureTag().TagStr())
}

func TestImage_Refusals(t *testing.T) {
	f := newFixture(t)

	credentials := []string{"--registry-username", registryUser, "--registry-password-stdin"}

	for name, tc := range map[string]struct {
		stdin         string
		args          []string
		want          error
		says          string
		beforeBackend bool
	}{
		"a tag": {
			stdin: registryPassword + "\n",
			args:  append([]string{f.image.Tag("v1").String()}, credentials...),
			want:  sigstore.ErrNotDigest,
		},
		"a username without a password": {
			args:          []string{f.image.String(), "--registry-username", registryUser},
			want:          image.ErrRegistryCredentials,
			beforeBackend: true,
		},
		"a password without a username": {
			stdin:         registryPassword + "\n",
			args:          []string{f.image.String(), "--registry-password-stdin"},
			want:          image.ErrRegistryCredentials,
			beforeBackend: true,
		},
		"an empty password": {
			stdin:         "\n",
			args:          append([]string{f.image.String()}, credentials...),
			want:          image.ErrRegistryCredentials,
			says:          "--registry-password-stdin read an empty password",
			beforeBackend: true,
		},
		"the wrong password": {
			stdin: "not-the-password\n",
			args:  append([]string{f.image.String()}, credentials...),
			says:  "401 Unauthorized",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f.backend.keyIDs = nil

			args := append([]string{"--backend", "local", "--key-id", f.keyPath}, tc.args...)

			out, err := run(t, signtest.Props(), tc.stdin, args...)
			require.Error(t, err)

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}

			assert.Contains(t, err.Error(), tc.says)
			assert.Empty(t, out, "a refusal prints no location")
			assert.NotContains(t, err.Error(), registryPassword, "the registry's password never reaches an error")

			if supplied := strings.TrimSpace(tc.stdin); supplied != "" {
				assert.NotContains(t, err.Error(), supplied, "the password given never reaches an error")
			}

			if tc.beforeBackend {
				assert.Empty(t, f.backend.keyIDs, "refused before the backend is asked for a signer")
			}
		})
	}

	assert.Equal(t, []string{"v1"}, f.tags(t), "nothing was pushed")
}

func TestImage_ABackendFailureSignsNothing(t *testing.T) {
	f := newFixture(t)

	args := []string{
		"--backend", "local", "--key-id", filepath.Join(t.TempDir(), "absent.key"),
		"--registry-username", registryUser, "--registry-password-stdin", f.image.String(),
	}

	_, err := run(t, signtest.Props(), registryPassword+"\n", args...)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), registryPassword)
	assert.Equal(t, []string{"v1"}, f.tags(t), "nothing was pushed")
}

func TestImage_NeedsABackendAKeyAndOneReference(t *testing.T) {
	signtest.Register(t, &localBackend{})

	for name, args := range map[string][]string{
		"no backend":     {"--key-id", "image.key", "repo@sha256:0"},
		"no key":         {"--backend", "local", "repo@sha256:0"},
		"no reference":   {"--backend", "local", "--key-id", "image.key"},
		"two references": {"--backend", "local", "--key-id", "image.key", "a@sha256:0", "b@sha256:0"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, signtest.Props(), "", args...)
			require.Error(t, err)
		})
	}
}

func TestNewCmdImage_OffersEachBackendsSettings(t *testing.T) {
	signtest.RegisterAwsKms(t)

	assert.NotNil(t, image.NewCmdImage(signtest.Props()).Flags().Lookup("kms-region"))
}
