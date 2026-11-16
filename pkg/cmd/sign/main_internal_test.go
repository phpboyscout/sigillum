package sign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSameSignPath_CleanedSpellings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		output string
		input  string
		same   bool
	}{
		{name: "identical", output: "x.txt", input: "x.txt", same: true},
		{name: "dot-slash prefix", output: "./x.txt", input: "x.txt", same: true},
		{name: "redundant dotdot", output: "a/../x.txt", input: "x.txt", same: true},
		{name: "different files", output: "x.txt.sig", input: "x.txt", same: false},
		{name: "different dirs", output: "a/x.txt", input: "b/x.txt", same: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.same, sameSignPath(tc.output, tc.input))
		})
	}
}

func TestSameSignPath_SameFileViaSymlink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()

	target := filepath.Join(tmp, "artifact.txt")
	require.NoError(t, os.WriteFile(target, []byte("payload"), 0o600))

	link := filepath.Join(tmp, "link.txt")
	require.NoError(t, os.Symlink(target, link))

	assert.True(t, sameSignPath(link, target), "a symlink to the input is the input")
}
