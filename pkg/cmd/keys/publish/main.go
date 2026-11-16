package publish

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/keysite"
	"gitlab.com/phpboyscout/go/signing/minisign"
)

const (
	minisignDir = "minisign"
	algorithm   = "minisign-ED"
)

// The kinds are go/signing-cli's, which reach log records users already match
// on (go/signing#18). keysite's own sentinels carry signing.* kinds.
var (
	// ErrKeyAlreadyPublished is returned when a different key is already
	// published for the same project and generation. Consumers pin a published
	// key, so it is never replaced.
	ErrKeyAlreadyPublished = errors.NewSentinel("signing-cli.key_already_published", "a different key is already published at this path")

	// ErrInvalidProject is returned when --project is not a safe path segment.
	ErrInvalidProject = errors.NewSentinel("signing-cli.invalid_project", "project name must be lowercase alphanumeric with dots, dashes or underscores")

	// ErrInvalidStatus is returned when --status is not a known lifecycle state.
	ErrInvalidStatus = errors.NewSentinel("signing-cli.invalid_status", "unknown status")
)

// RunPublish stages the minisign public key at args[0] into the keys site at
// --output and records it in the site's manifest.
func RunPublish(_ context.Context, p *props.Props, opts *PublishOptions, args []string) error {
	if err := validate(opts); err != nil {
		return err
	}

	keyPath := args[0]

	key, err := readPublicKey(keyPath)
	if err != nil {
		return err
	}

	relPath := filepath.ToSlash(filepath.Join(minisignDir, opts.Project, fmt.Sprintf("v%d.pub", opts.Generation)))

	// The comment is part of the published bytes: change it and re-publishing
	// an unchanged key is refused as a different one.
	body, err := key.File(fmt.Sprintf("phpboyscout %s artefact signing v%d (minisign key %X)",
		opts.Project, opts.Generation, key.KeyID))
	if err != nil {
		return err //nolint:wrapcheck // the library names the comment as the fault
	}

	entry := keysite.Entry{
		ID:         fmt.Sprintf("%X", key.KeyID),
		Project:    opts.Project,
		Generation: opts.Generation,
		Algorithm:  algorithm,
		Purpose:    opts.Purpose,
		Status:     opts.Status,
		ValidFrom:  opts.ValidFrom,
		PubKey:     key.Encode(),
		Path:       relPath,
	}

	added, err := keysite.Publish(opts.Output, body, entry)
	if err != nil {
		return asCommandError(err, keysite.ErrKeyAlreadyPublished, ErrKeyAlreadyPublished)
	}

	p.GetLogger().Info("Published minisign public key",
		"project", opts.Project,
		"generation", opts.Generation,
		"minisign_key_id", entry.ID,
		"status", opts.Status,
		"path", relPath,
		"output", opts.Output,
		"new", added)

	return nil
}

// validate checks the flags before keysite does, because keysite's wording
// names entry fields where a user of this command typed flags.
func validate(opts *PublishOptions) error {
	if err := keysite.ValidateProject(opts.Project); err != nil {
		return asCommandError(err, keysite.ErrInvalidProject, ErrInvalidProject)
	}

	if opts.Generation < 1 {
		return errors.Newf("--generation must be 1 or greater, got %d", opts.Generation)
	}

	switch opts.Status {
	case keysite.StatusActive, keysite.StatusRetired, keysite.StatusRevoked:
	default:
		return errors.Wrapf(ErrInvalidStatus, "got %q; valid values are %q, %q, %q",
			opts.Status, keysite.StatusActive, keysite.StatusRetired, keysite.StatusRevoked)
	}

	if opts.ValidFrom != "" {
		if _, err := time.Parse(time.DateOnly, opts.ValidFrom); err != nil {
			return errors.Wrapf(err, "parsing --valid-from %q as YYYY-MM-DD", opts.ValidFrom)
		}
	}

	return nil
}

// asCommandError re-raises a keysite refusal under this command's sentinel,
// keeping the text. Any other error passes through.
func asCommandError(err, from, to error) error {
	if !errors.Is(err, from) {
		return err
	}

	return errors.Wrap(to, strings.TrimSuffix(err.Error(), ": "+from.Error()))
}

func readPublicKey(path string) (minisign.PublicKey, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: the operator names the key to publish
	if err != nil {
		return minisign.PublicKey{}, errors.Wrapf(err, "reading %s", path)
	}

	key, err := minisign.ParsePublicKey(string(raw))
	if err != nil {
		return minisign.PublicKey{}, errors.Wrapf(err, "parsing %s", path)
	}

	return key, nil
}
