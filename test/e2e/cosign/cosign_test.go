// Package cosign_test checks that cosign accepts what the built sigillum binary
// pushes (sigillum spec 0007, Testing). It is gated on its own variable because
// the CI image has no cosign, and a skip there must not read as a pass.
package cosign_test

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gate = "INT_TEST_COSIGN"

type form string

const (
	legacyForm form = "legacy"
	bundleForm form = "bundle"
)

// hidingRegistry answers 404 for one signature form, because cosign falls back
// from the bundle to the legacy signature without saying so.
type hidingRegistry struct {
	host string
	hide atomic.Value
}

func (r *hidingRegistry) hides(path string) bool {
	hidden, _ := r.hide.Load().(form)

	switch hidden {
	case legacyForm:
		return strings.Contains(path, "/manifests/sha256-") && strings.HasSuffix(path, ".sig")
	case bundleForm:
		return strings.Contains(path, "/referrers/") ||
			(strings.Contains(path, "/manifests/sha256-") && !strings.HasSuffix(path, ".sig"))
	default:
		return false
	}
}

func newRegistry(t *testing.T) *hidingRegistry {
	t.Helper()

	r := &hidingRegistry{}
	handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.hides(req.URL.Path) {
			http.NotFound(w, req)

			return
		}

		handler.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)

	r.host = strings.TrimPrefix(srv.URL, "http://")

	return r
}

func (r *hidingRegistry) pushImage(t *testing.T) name.Digest {
	t.Helper()

	img, err := random.Image(64, 1)
	require.NoError(t, err)

	tag, err := name.NewTag(r.host + "/estate/app:v1")
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img))

	h, err := img.Digest()
	require.NoError(t, err)

	return tag.Digest(h.String())
}

func buildSigillum(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "sigillum")

	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/sigillum")
	cmd.Dir = "../../.."

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "building sigillum:\n%s", out)

	return bin
}

// sigillum runs the binary with an empty home and Docker config, so neither the
// developer's config nor their registry credentials reach it.
func sigillum(t *testing.T, bin, home string, args ...string) (string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := exec.Command(bin, append([]string{"--ci"}, args...)...) //nolint:gosec // test-controlled arguments
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home, "DOCKER_CONFIG="+home, "AWS_EC2_METADATA_DISABLED=true")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Run(), "sigillum %s\nstderr:\n%s", strings.Join(args, " "), stderr.String())

	return stdout.String(), stderr.String()
}

func cosignVerify(cosign, home, publicKey, image string, flags []string) ([]byte, error) {
	args := append([]string{"verify", "--key", publicKey, "--insecure-ignore-tlog", "--allow-http-registry"}, flags...)

	cmd := exec.Command(cosign, append(args, image)...) //nolint:gosec // test-controlled arguments
	cmd.Env = append(os.Environ(), "HOME="+home, "DOCKER_CONFIG="+home)

	return cmd.CombinedOutput()
}

func TestCosignVerifiesWhatSigillumSigns(t *testing.T) {
	if os.Getenv(gate) == "" {
		t.Skip("set " + gate + "=1, with cosign on PATH, to run the cosign interoperability check")
	}

	cosign, err := exec.LookPath("cosign")
	require.NoError(t, err, gate+" is set but cosign is not on PATH")

	bin := buildSigillum(t)
	home := t.TempDir()

	sigillum(t, bin, home, "keys", "generate-image", "--output", "image.pub", "--private-output", "image.key")
	sigillum(t, bin, home, "keys", "generate-image", "--output", "other.pub", "--private-output", "other.key")

	reg := newRegistry(t)
	image := reg.pushImage(t)

	stdout, _ := sigillum(t, bin, home, "sign", "image", "--backend", "local", "--key-id", "image.key", image.String())

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	require.Len(t, lines, 2, "stdout holds the two locations and nothing else:\n%s", stdout)
	assert.True(t, strings.HasPrefix(lines[0], "signature: "), lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "bundle: "), lines[1])

	forms := map[form]struct {
		flags  []string
		hidden form
	}{
		bundleForm: {hidden: legacyForm},
		legacyForm: {flags: []string{"--new-bundle-format=false"}, hidden: bundleForm},
	}

	for name, f := range forms {
		t.Run(string(name), func(t *testing.T) {
			reg.hide.Store(f.hidden)
			t.Cleanup(func() { reg.hide.Store(form("")) })

			out, err := cosignVerify(cosign, home, filepath.Join(home, "image.pub"), image.String(), f.flags)
			require.NoError(t, err, "cosign verify with the signing key:\n%s", out)

			out, err = cosignVerify(cosign, home, filepath.Join(home, "other.pub"), image.String(), f.flags)
			require.Error(t, err, "cosign verify with another key must fail:\n%s", out)
		})
	}
}
