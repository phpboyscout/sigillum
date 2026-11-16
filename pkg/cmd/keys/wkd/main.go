package wkd

import (
	"context"
	"os"
	"path/filepath"

	"gitlab.com/phpboyscout/go-tool-base/pkg/props"
	"gitlab.com/phpboyscout/go/errors"
	"gitlab.com/phpboyscout/go/signing/openpgpkey"
)

const submissionAddressAuto = "auto"

// RunWkd writes a Web Key Directory tree under --output from the armored public
// keys named in args, one hu/ file per email.
func RunWkd(_ context.Context, p *props.Props, opts *WkdOptions, args []string) error {
	inputs, err := readKeyFiles(args)
	if err != nil {
		return err
	}

	entries, err := entriesFor(inputs, opts.Emails)
	if err != nil {
		return err
	}

	submissionAddress := opts.SubmissionAddress
	if submissionAddress == submissionAddressAuto {
		if len(entries) == 0 {
			return errors.New(`--submission-address auto requires at least one resolvable --email`)
		}

		submissionAddress = entries[0].Email
	}

	written, err := openpgpkey.WriteWKDTree(opts.Output, opts.Domain, openpgpkey.Options{
		Method:            openpgpkey.Method(opts.Method),
		SubmissionAddress: submissionAddress,
	}, entries...)
	if err != nil {
		return errors.Wrap(err, "writing WKD tree")
	}

	logOutcome(p, opts, entries, written)

	return nil
}

func readKeyFiles(paths []string) ([]openpgpkey.ArmoredKeys, error) {
	inputs := make([]openpgpkey.ArmoredKeys, 0, len(paths))

	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // G304: the operator names the keys to publish
		if err != nil {
			return nil, errors.Wrapf(err, "reading %s", path)
		}

		inputs = append(inputs, openpgpkey.ArmoredKeys{Source: path, Data: data})
	}

	return inputs, nil
}

// entriesFor returns one entry per requested email, or per email the keys claim
// when none is requested. The requested ones are picked from the full set
// because the library's own refusal names an email where the user typed --email.
func entriesFor(inputs []openpgpkey.ArmoredKeys, emails []string) ([]openpgpkey.Entry, error) {
	claimed, err := openpgpkey.EntriesForWKD(inputs, nil)
	if err != nil {
		return nil, err //nolint:wrapcheck // names the file and the fault
	}

	if len(emails) == 0 {
		return claimed, nil
	}

	byEmail := make(map[string]openpgpkey.Entry, len(claimed))
	for _, entry := range claimed {
		byEmail[entry.Email] = entry
	}

	entries := make([]openpgpkey.Entry, 0, len(emails))

	for _, email := range emails {
		entry, ok := byEmail[email]
		if !ok {
			return nil, errors.Newf("no input key matched --email %s", email)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func logOutcome(p *props.Props, opts *WkdOptions, entries []openpgpkey.Entry, written []string) {
	log := p.GetLogger()

	for _, entry := range entries {
		hash, _ := openpgpkey.WKDHash(entry.Email)
		log.Info("WKD bucket", "email", entry.Email, "hash", hash, "keys", len(entry.Keys))
	}

	for _, w := range written {
		log.Info("wrote", "path", filepath.Join(opts.Output, w))
	}

	log.Info("WKD tree complete",
		"output", opts.Output,
		"method", opts.Method,
		"emails", len(entries),
		"files", len(written),
	)
}
