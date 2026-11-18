package rotate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keyfile"
	"gitlab.com/phpboyscout/go/signing/verify"

	"gitlab.com/phpboyscout/sigillum/internal/rotate"
	"gitlab.com/phpboyscout/sigillum/internal/signcmd"
)

// RunRotate builds, signs and writes a rotation manifest (sigillum spec 0008).
func RunRotate(cmd *cobra.Command, p *props.Props, opts *RotateOptions, _ []string) error {
	req, err := request(opts, cmd.Flags().Changed(flagEpoch))
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(opts.OutputDir, verify.RotationManifestFile)
	signaturePath := filepath.Join(opts.OutputDir, verify.RotationSignatureFile)

	signer, backendID, err := signcmd.ResolveSigner(cmd.Context(), cmd.Flags(), opts.Backend, opts.KeyID)
	if err != nil {
		return err
	}

	authority, err := signcmd.MinisignPublicKey(signer)
	if err != nil {
		return errors.Wrap(err, "the rotation authority signs with minisign, so --key-id must be an Ed25519 key")
	}

	m, carried, err := rotate.Build(req, authority.Encode())
	if err != nil {
		return err //nolint:wrapcheck // Build's refusals name the flag to change
	}

	manifest, signature, err := verify.SignRotationManifest(signer, m)
	if err != nil {
		return err //nolint:wrapcheck // the library names the rule the manifest breaks
	}

	if err := writeOutputs(manifestPath, manifest, signaturePath, signature, opts.Force); err != nil {
		return err
	}

	p.GetLogger().Info("Wrote rotation manifest",
		"backend", backendID, "key_id", opts.KeyID, "epoch", m.Epoch, "manifest", manifestPath)

	return report(cmd.OutOrStdout(), m, carried, authority.Encode(), manifestPath, signaturePath)
}

// publicPerm is the mode of both outputs: they are published as release assets.
const publicPerm = 0o644

// writeOutputs never leaves a manifest without the signature written with it.
// Under force, a failed signature write puts the earlier manifest back.
func writeOutputs(manifestPath string, manifest []byte, signaturePath string, signature []byte, force bool) error {
	if !force {
		for _, path := range []string{manifestPath, signaturePath} {
			if _, err := os.Lstat(path); err == nil {
				return errors.Wrapf(signcmd.ErrKeyFileExists, "%q (pass --force to overwrite)", path)
			}
		}
	}

	earlier, readErr := os.ReadFile(manifestPath) //nolint:gosec // the operator's output path
	hadEarlier := readErr == nil

	if err := keyfile.Write(manifestPath, manifest, publicPerm, force); err != nil {
		return errors.Wrapf(err, "writing %s", manifestPath)
	}

	if err := keyfile.Write(signaturePath, signature, publicPerm, force); err != nil {
		return errors.Wrapf(undoManifest(manifestPath, earlier, hadEarlier), "writing %s: %v", signaturePath, err)
	}

	return nil
}

// undoManifest returns what happened to the manifest after its signature failed.
func undoManifest(path string, earlier []byte, hadEarlier bool) error {
	if hadEarlier {
		if err := keyfile.Write(path, earlier, publicPerm, true); err != nil {
			return errors.Newf("%s now holds the new manifest with the earlier signature, and restoring it failed: %v", path, err)
		}

		return errors.Newf("%s was restored to the earlier manifest", path)
	}

	if err := os.Remove(path); err != nil {
		return errors.Newf("%s holds an unsigned manifest, and removing it failed: %v", path, err)
	}

	return errors.Newf("%s was removed", path)
}

func request(opts *RotateOptions, epochSet bool) (rotate.Request, error) {
	req, err := schedule(opts, epochSet)
	if err != nil {
		return req, err
	}

	if req.Revoke, err = revocations(opts.Revoke); err != nil {
		return req, err
	}

	if req.Add, err = keyFiles(opts.Add); err != nil {
		return req, err
	}

	if req.Anchors, err = readAll(flagAnchor, opts.Anchor); err != nil {
		return req, err
	}

	if req.AnchorOnly, err = readAll(flagAnchorOnly, opts.AnchorOnly); err != nil {
		return req, err
	}

	if opts.Previous != "" {
		req.Previous, err = readPrevious(opts.Previous)
	}

	return req, err
}

func revocations(values []string) ([]rotate.Revocation, error) {
	out := make([]rotate.Revocation, 0, len(values))

	for _, v := range values {
		fp, at, hasTime := strings.Cut(v, "@")
		r := rotate.Revocation{Fingerprint: fp}

		if hasTime {
			since, err := time.Parse(time.RFC3339, at)
			if err != nil {
				return nil, errors.Newf("--%s %q: %q is not an RFC 3339 time", flagRevoke, v, at)
			}

			r.Since = since.UTC()
		}

		out = append(out, r)
	}

	return out, nil
}

func readAll(flag string, paths []string) ([][]byte, error) {
	out := make([][]byte, 0, len(paths))

	for _, path := range paths {
		b, err := os.ReadFile(path) //nolint:gosec // the operator names the file
		if err != nil {
			return nil, errors.Wrapf(err, "--%s %s", flag, path)
		}

		out = append(out, b)
	}

	return out, nil
}

func readPrevious(path string) (*rotate.Previous, error) {
	manifest, err := os.ReadFile(path) //nolint:gosec // the operator names the file
	if err != nil {
		return nil, errors.Wrapf(err, "--%s %s", flagPrevious, path)
	}

	sigPath := path + ".minisig"

	signature, err := os.ReadFile(sigPath) //nolint:gosec // beside the operator's file
	if err != nil {
		return nil, errors.Wrapf(err, "--%s needs its signature beside it at %s", flagPrevious, sigPath)
	}

	return &rotate.Previous{Manifest: manifest, Signature: signature}, nil
}

func report(w io.Writer, m verify.RotationManifest, carried rotate.Carried, authority, manifestPath, signaturePath string) error {
	var b strings.Builder

	fmt.Fprintf(&b, "Wrote %s and %s\n", manifestPath, signaturePath)
	fmt.Fprintf(&b, "epoch      %d (%s)\n", m.Epoch, m.Reason)
	fmt.Fprintf(&b, "not after  %s\n", m.NotAfter.UTC().Format(time.RFC3339))

	for _, a := range m.Add {
		fmt.Fprintf(&b, "add        %s%s\n", a.Fingerprint, carriedMark(carried, a.Fingerprint))
	}

	for _, r := range m.Revoke {
		fmt.Fprintf(&b, "revoke     %s since %s%s\n",
			r.Fingerprint, r.Since.UTC().Format(time.RFC3339), carriedMark(carried, r.Fingerprint))
	}

	fmt.Fprintf(&b, "authority  %s\n", authority)

	if _, err := io.WriteString(w, b.String()); err != nil {
		return errors.Wrap(err, "writing the summary")
	}

	return nil
}

func carriedMark(carried rotate.Carried, fingerprint string) string {
	if carried[fingerprint] {
		return "  (carried)"
	}

	return ""
}

func schedule(opts *RotateOptions, epochSet bool) (rotate.Request, error) {
	if epochSet && opts.Epoch == 0 {
		return rotate.Request{}, errors.Newf("--%s must be at least 1", flagEpoch)
	}

	reason := verify.RotationReason(opts.Reason)
	if reason != verify.RotationReasonScheduled && reason != verify.RotationReasonCompromise {
		return rotate.Request{}, errors.Newf("--%s must be %q or %q, not %q",
			flagReason, verify.RotationReasonScheduled, verify.RotationReasonCompromise, opts.Reason)
	}

	notAfter, err := time.Parse(time.RFC3339, opts.NotAfter)
	if err != nil {
		return rotate.Request{}, errors.Newf("--%s %q is not an RFC 3339 time", flagNotAfter, opts.NotAfter)
	}

	return rotate.Request{
		Reason:            reason,
		Now:               time.Now().UTC().Truncate(time.Second),
		NotAfter:          notAfter,
		Epoch:             opts.Epoch,
		AllowEpochGap:     opts.AllowEpochGap,
		PreviousAuthority: opts.PreviousAuthority,
	}, nil
}

func keyFiles(paths []string) ([]rotate.KeyFile, error) {
	contents, err := readAll(flagAdd, paths)
	if err != nil {
		return nil, err
	}

	out := make([]rotate.KeyFile, 0, len(paths))
	for i, armored := range contents {
		out = append(out, rotate.KeyFile{Name: paths[i], Armored: armored})
	}

	return out, nil
}
