// Package signtest holds the fakes the sign and keys command tests share.
package signtest

import (
	"context"
	"crypto"
	"testing"
	"time"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/signing"
)

// FixtureKeyTime is a fixed creation time, so fixture keys keep their fingerprint.
var FixtureKeyTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Props returns props that log nowhere.
func Props() *props.Props {
	return &props.Props{Logger: logger.NewNoop()}
}

// Backend serves one known signer for any key ID, or fails with Err, and
// records the key IDs it was asked for.
type Backend struct {
	BackendName string
	Signer      crypto.Signer
	Err         error
	KeyIDs      []string
}

// Name implements signing.Backend.
func (b *Backend) Name() string { return b.BackendName }

// NewSigner implements signing.Backend.
func (b *Backend) NewSigner(_ context.Context, keyID string) (crypto.Signer, error) {
	b.KeyIDs = append(b.KeyIDs, keyID)

	return b.Signer, b.Err
}

// RegionSettings is a settings struct shaped like aws-kms's.
type RegionSettings struct {
	Region string `setting:"kms-region" usage:"AWS region the KMS key lives in"`
}

// RegionBackend is a backend with one string setting, defaulting to eu-west-2.
type RegionBackend struct {
	Backend

	Config RegionSettings
}

// NewRegionBackend returns a RegionBackend named name with the default region.
func NewRegionBackend(name string) *RegionBackend {
	return &RegionBackend{Backend: Backend{BackendName: name}, Config: RegionSettings{Region: "eu-west-2"}}
}

// Settings implements signing.Configurable.
func (b *RegionBackend) Settings() any { return &b.Config }

// Register replaces the process-wide backend registry with backends for the
// test. The registry is shared state, so a test calling this must not run in
// parallel.
func Register(t *testing.T, backends ...signing.Backend) {
	t.Helper()

	signing.ResetForTesting()
	t.Cleanup(signing.ResetForTesting)

	for _, b := range backends {
		signing.Register(b)
	}
}

// RegisterAwsKms registers a RegionBackend as the aws-kms default, with a
// factory for named instances, and returns the default. A named instance
// serves the signer the default holds when the instance is made.
func RegisterAwsKms(t *testing.T) *RegionBackend {
	t.Helper()

	def := NewRegionBackend("aws-kms")
	Register(t, def)

	signing.RegisterFactory("aws-kms", func(canonical string) (signing.Backend, error) {
		instance := NewRegionBackend(canonical)
		instance.Signer = def.Signer

		return instance, nil
	})

	return def
}
