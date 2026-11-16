package sign

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/logger"
	"gitlab.com/phpboyscout/go/signing/minisign"

	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

func signMinisign(cmd *cobra.Command, log logger.Logger, opts *SignOptions, input string) error {
	stamp, err := parseCreated(opts.Created)
	if err != nil {
		return err
	}

	if stamp.IsZero() {
		if stamp, err = minisign.SignatureTime(time.Time{}); err != nil {
			return err //nolint:wrapcheck // names SOURCE_DATE_EPOCH and its value already
		}
	}

	output := opts.Output
	if output == "" {
		// rtb-update picks its parser by extension, so .minisig is required.
		output = input + ".minisig"
	}

	if err := refuseSigningOverInput(output, input); err != nil {
		return err
	}

	signer, backendID, err := signcmd.ResolveSigner(cmd.Context(), cmd.Flags(), opts.Backend, opts.KeyID)
	if err != nil {
		return err
	}

	// Before signing, so a wrong key type fails naming the format it belongs to.
	key, err := signcmd.MinisignPublicKey(signer)
	if err != nil {
		return err
	}

	sig, err := minisign.SignFile(signer, input, minisign.Options{Time: stamp, Project: opts.Project})
	if err != nil {
		return err //nolint:wrapcheck // names the step already
	}

	if err := writeSignature(output, sig); err != nil {
		return err
	}

	log.Info("Signed artefact",
		"format", signcmd.FormatMinisign,
		"backend", backendID,
		"key_id", opts.KeyID,
		"minisign_key_id", fmt.Sprintf("%X", key.KeyID),
		"input", input,
		"output", output,
		"project", opts.Project,
		"trusted_comment_time", stamp.Format(time.RFC3339),
	)

	return nil
}
