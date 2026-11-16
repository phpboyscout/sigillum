package sign_test

import (
	"testing"

	"gitlab.com/phpboyscout/sigillum/internal/signtest"
	"gitlab.com/phpboyscout/sigillum/pkg/cmd/sign"
)

const fakeBackend = "fake"

// signRequest is one invocation of the sign command. An empty field leaves
// its flag off the command line.
type signRequest struct {
	format    string
	backend   string
	keyID     string
	publicKey string
	output    string
	created   string
	project   string
	input     string
	appendSig bool
}

func (r signRequest) args() []string {
	var args []string

	for _, flag := range []struct{ name, value string }{
		{"format", r.format},
		{"backend", r.backend},
		{"key-id", r.keyID},
		{"public-key", r.publicKey},
		{"output", r.output},
		{"created", r.created},
		{"project", r.project},
	} {
		if flag.value != "" {
			args = append(args, "--"+flag.name, flag.value)
		}
	}

	if r.appendSig {
		args = append(args, "--append")
	}

	return append(args, r.input)
}

// runSign drives the real command, flag parsing included.
func runSign(t *testing.T, req signRequest) error {
	t.Helper()

	if req.backend == "" {
		req.backend = fakeBackend
	}

	if req.keyID == "" {
		req.keyID = "ignored"
	}

	return signtest.Execute(t, sign.NewCmdSign(signtest.Props()).Command, req.args()...)
}
