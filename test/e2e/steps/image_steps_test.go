package steps_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"slices"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const ownerOnly = 0o600

// imageWorld carries the registry and image one image scenario signs.
type imageWorld struct {
	*world

	registry *httptest.Server
	image    name.Digest
}

func (w *imageWorld) generateImageKey() error {
	return w.run("keys", "generate-image", "--output", "image.pub", "--private-output", "image.key")
}

func (w *imageWorld) haveImageKey() error {
	if err := w.generateImageKey(); err != nil {
		return err
	}

	return w.commandSucceeds()
}

func (w *imageWorld) fileIsOwnerOnly(file string) error {
	info, err := os.Stat(w.path(file))
	if err != nil {
		return err
	}

	if perm := info.Mode().Perm(); perm != ownerOnly {
		return fmt.Errorf("%s has mode %o, want %o", file, perm, ownerOnly)
	}

	return nil
}

func (w *imageWorld) pushImage() error {
	w.registry = httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))

	img, err := random.Image(64, 1)
	if err != nil {
		return err
	}

	tag, err := name.NewTag(strings.TrimPrefix(w.registry.URL, "http://") + "/estate/app:v1")
	if err != nil {
		return err
	}

	if err := remote.Write(tag, img); err != nil {
		return err
	}

	h, err := img.Digest()
	if err != nil {
		return err
	}

	w.image = tag.Digest(h.String())

	return nil
}

func (w *imageWorld) signByDigest() error {
	return w.run("sign", "image", "--backend", "local", "--key-id", "image.key", w.image.String())
}

func (w *imageWorld) signByTag() error {
	return w.run("sign", "image", "--backend", "local", "--key-id", "image.key", w.image.Tag("v1").String())
}

func (w *imageWorld) signatureTag() name.Tag {
	return w.image.Tag(strings.Replace(w.image.DigestStr(), ":", "-", 1) + ".sig")
}

func (w *imageWorld) stdoutNamesSignatureAndBundle() error {
	lines := strings.Split(strings.TrimSuffix(w.stdout, "\n"), "\n")
	if len(lines) != 2 {
		return fmt.Errorf("stdout has %d lines, want 2:\n%s", len(lines), w.stdout)
	}

	if want := "signature: " + w.signatureTag().String(); lines[0] != want {
		return fmt.Errorf("first line %q, want %q", lines[0], want)
	}

	if prefix := "bundle: " + w.image.Repository.String() + "@sha256:"; !strings.HasPrefix(lines[1], prefix) {
		return fmt.Errorf("second line %q, want it to start %q", lines[1], prefix)
	}

	return nil
}

func (w *imageWorld) tags() ([]string, error) {
	return remote.List(w.image.Repository)
}

func (w *imageWorld) registryHoldsSignature() error {
	tags, err := w.tags()
	if err != nil {
		return err
	}

	if !slices.Contains(tags, w.signatureTag().TagStr()) {
		return fmt.Errorf("no %s among %v", w.signatureTag().TagStr(), tags)
	}

	return nil
}

func (w *imageWorld) registryHoldsNoSignature() error {
	tags, err := w.tags()
	if err != nil {
		return err
	}

	if !slices.Equal(tags, []string{"v1"}) {
		return fmt.Errorf("the registry holds %v, want only the image's own tag", tags)
	}

	return nil
}

func registerImageSteps(ctx *godog.ScenarioContext, base *world) {
	w := &imageWorld{world: base}

	ctx.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		*w = imageWorld{world: base}

		return ctx, nil
	})

	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.registry != nil {
			w.registry.Close()
		}

		return ctx, nil
	})

	ctx.Given(`^an image-signing key$`, w.haveImageKey)
	ctx.Given(`^an image pushed to a local registry$`, w.pushImage)

	ctx.When(`^I generate an image-signing key$`, w.generateImageKey)
	ctx.When(`^I sign that image by digest$`, w.signByDigest)
	ctx.When(`^I sign that image by its tag$`, w.signByTag)

	ctx.Then(`^the file "([^"]*)" is readable by its owner only$`, w.fileIsOwnerOnly)
	ctx.Then(`^stdout names the image's signature and bundle, and nothing else$`, w.stdoutNamesSignatureAndBundle)
	ctx.Then(`^the registry holds a signature for the image$`, w.registryHoldsSignature)
	ctx.Then(`^the registry holds no signature for the image$`, w.registryHoldsNoSignature)
}
