package signcmd_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/phpboyscout/go/signing"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
	"gitlab.com/phpboyscout/sigillum/internal/signtest"
)

// Tests here touch the process-wide backend registry, so none runs in parallel.

func backendCmd() *cobra.Command {
	var selector, keyID string

	cmd := &cobra.Command{Use: "sign"}
	signcmd.AddBackendFlags(cmd, &selector, &keyID)

	return cmd
}

func TestAddBackendFlags_BindsEachSettingAsAFlag(t *testing.T) {
	def := signtest.RegisterAwsKms(t)

	cmd := backendCmd()

	f := cmd.Flags().Lookup("kms-region")
	require.NotNil(t, f, "the backend's setting must be a flag")
	assert.Equal(t, "eu-west-2", f.DefValue, "the setting's value at bind time is the flag's default")
	assert.Equal(t, "AWS region the KMS key lives in", f.Usage)
	assert.Equal(t, "string", f.Value.Type())

	require.NoError(t, cmd.Flags().Set("kms-region", "eu-west-1"))
	assert.Equal(t, "eu-west-1", def.Config.Region, "a set flag reaches the registered default")
}

func TestAddBackendFlags_HelpNamesTheLinkedTypes(t *testing.T) {
	signtest.RegisterAwsKms(t)

	usage := backendCmd().Flags().Lookup("backend").Usage
	assert.Equal(t, "Signing backend: <type> or <type>:<instance>[?k=v] (required). Compiled-in types: aws-kms", usage)
}

type switchSettings struct {
	Dry bool `setting:"dry-run" usage:"Sign nothing"`
}

type switchBackend struct {
	signtest.Backend

	config switchSettings
}

func (b *switchBackend) Settings() any { return &b.config }

func TestAddBackendFlags_ABoolSettingNeedsNoValue(t *testing.T) {
	b := &switchBackend{Backend: signtest.Backend{BackendName: "switch"}}
	signtest.Register(t, b)

	cmd := backendCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--dry-run"}))
	assert.True(t, b.config.Dry)
}

// A top-level backend flag configures the registered default only, so pairing it
// with a named instance would leave it silently inert (go/signing-cli#7).
func TestResolveBackend_NamedInstance_RefusesSetTopLevelBackendFlag(t *testing.T) {
	signtest.RegisterAwsKms(t)

	cmd := backendCmd()
	require.NoError(t, cmd.Flags().Set("kms-region", "eu-west-1"))

	_, _, err := signcmd.ResolveBackend("aws-kms:prod", cmd.Flags())
	require.EqualError(t, err, `--kms-region configures the default "aws-kms" backend, not the named instance "aws-kms:prod"; `+
		`pass it as a selector setting instead: --backend 'aws-kms:prod?kms-region=…'`)
	assert.NotContains(t, err.Error(), "eu-west-1", "the error must NOT leak a flag value")
}

func TestResolveBackend_NamedInstance_RefusalPrecedesTheSelectorsSettings(t *testing.T) {
	signtest.RegisterAwsKms(t)

	cmd := backendCmd()
	require.NoError(t, cmd.Flags().Set("kms-region", "eu-west-1"))

	_, _, err := signcmd.ResolveBackend("aws-kms:prod?nonsense=1", cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--kms-region configures the default")
}

func TestResolveBackend_NamedInstance_AcceptsUnsetTopLevelBackendFlag(t *testing.T) {
	signtest.RegisterAwsKms(t)

	b, id, err := signcmd.ResolveBackend("aws-kms:prod?kms-region=eu-west-1", backendCmd().Flags())
	require.NoError(t, err)
	assert.Equal(t, "aws-kms:prod", id)

	region, ok := b.(*signtest.RegionBackend)
	require.True(t, ok)
	assert.Equal(t, "eu-west-1", region.Config.Region)
}

func TestResolveBackend_BareType_StillTakesTopLevelBackendFlag(t *testing.T) {
	def := signtest.RegisterAwsKms(t)

	cmd := backendCmd()
	require.NoError(t, cmd.Flags().Set("kms-region", "eu-west-1"))

	b, id, err := signcmd.ResolveBackend("aws-kms", cmd.Flags())
	require.NoError(t, err)
	assert.Equal(t, "aws-kms", id)
	assert.Same(t, def, b)
	assert.Equal(t, "eu-west-1", def.Config.Region)
}

func TestResolveBackend_IllegalInstanceNameIsNeverQuoted(t *testing.T) {
	signtest.RegisterAwsKms(t)

	cmd := backendCmd()
	require.NoError(t, cmd.Flags().Set("kms-region", "eu-west-1"))

	_, _, err := signcmd.ResolveBackend("aws-kms:AKIA_pasted_SECRET", cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "illegal instance name")
	assert.NotContains(t, err.Error(), "AKIA_pasted_SECRET", "a rejected instance name must NOT be echoed")
}

func TestResolveBackend_NilFlagsRefuseNothing(t *testing.T) {
	signtest.RegisterAwsKms(t)

	_, id, err := signcmd.ResolveBackend("aws-kms:prod", nil)
	require.NoError(t, err)
	assert.Equal(t, "aws-kms:prod", id)
}

type strictSettings struct {
	Region string `setting:"region" usage:"Region"`
}

func (s *strictSettings) Validate() error {
	if s.Region == "" {
		return assert.AnError
	}

	return nil
}

type strictBackend struct {
	signtest.Backend

	config strictSettings
}

func (b *strictBackend) Settings() any { return &b.config }

func TestResolveBackend_BareType_ValidatesItsSettings(t *testing.T) {
	signtest.Register(t, &strictBackend{Backend: signtest.Backend{BackendName: "strict"}})

	_, _, err := signcmd.ResolveBackend("strict", backendCmd().Flags())
	require.ErrorIs(t, err, assert.AnError)
	assert.Contains(t, err.Error(), `backend "strict"`)
}

func TestResolveSigner_ResolvesThroughTheBackendRegistry(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	backend := &signtest.Backend{BackendName: "fake", Signer: priv}
	signtest.Register(t, backend)

	fs := backendCmd().Flags()

	signer, backendID, err := signcmd.ResolveSigner(context.Background(), fs, "fake", "k")
	require.NoError(t, err)
	assert.Equal(t, priv.Public(), signer.Public())
	assert.Equal(t, "fake", backendID)
	assert.Equal(t, []string{"k"}, backend.KeyIDs)

	_, _, err = signcmd.ResolveSigner(context.Background(), fs, "nope", "k")
	require.ErrorIs(t, err, signing.ErrUnknownBackend)
}
