package openpgp

// Unexported-surface tests that pin decisions a black-box test reaches only
// obliquely: the size-limit boundaries, the wildcard-pass guard, the two
// unreadable counters, the recipient-version window, the key-id rendering, and
// the packet-shape acceptance. Each is a point a mutation testing pass showed
// the suite did not notice a change to.

import (
	"errors"
	"strings"
	"testing"

	"gitlab.com/phpboyscout/go/encryption"
)

// errNotUnsupported stands in for any error that is not ErrUnsupported, so a
// packet that cannot be parsed for some other reason is judged malformed.
var errNotUnsupported = errors.New("some other parse error")

// TestHasHiddenNeedsAPositiveCount pins that the wildcard pass is made only when
// a wildcard recipient was actually seen — a zero count is not "zero or more".
func TestHasHiddenNeedsAPositiveCount(t *testing.T) {
	t.Parallel()

	none := candidateSet{hidden: 0}
	if none.hasHidden() {
		t.Error("hasHidden() with a zero count = true, want false")
	}

	one := candidateSet{hidden: 1}
	if !one.hasHidden() {
		t.Error("hasHidden() with one wildcard = false, want true")
	}
}

// TestExceedsAllowsTheLimitExactly pins that reaching a size limit exactly is
// allowed and only one octet past it is refused, at both real limits.
func TestExceedsAllowsTheLimitExactly(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		n, limit int64
		want     bool
	}{
		{4, 5, false},
		{5, 5, false},
		{6, 5, true},
		{maxMessage, maxMessage, false},
		{maxMessage + 1, maxMessage, true},
		{maxPlaintext, maxPlaintext, false},
		{maxPlaintext + 1, maxPlaintext, true},
	} {
		if got := exceeds(c.n, c.limit); got != c.want {
			t.Errorf("exceeds(%d, %d) = %v, want %v", c.n, c.limit, got, c.want)
		}
	}
}

// TestFileUnreadableSeparatesRealFromMalformed pins that a real-but-unsupported
// recipient packet increments unreadable and a malformed one increments
// malformed — each by one, never the other counter.
func TestFileUnreadableSeparatesRealFromMalformed(t *testing.T) {
	t.Parallel()

	var real candidateSet

	real.fileUnreadable([]byte{4}, encryption.ErrUnsupported) // v4, unsupported => a co-recipient
	if real.unreadable != 1 || real.malformed != 0 {
		t.Errorf("real recipient: unreadable=%d malformed=%d, want 1 and 0", real.unreadable, real.malformed)
	}

	var noise candidateSet

	noise.fileUnreadable([]byte{0}, errNotUnsupported) // not ErrUnsupported => damage
	if noise.malformed != 1 || noise.unreadable != 0 {
		t.Errorf("malformed packet: malformed=%d unreadable=%d, want 1 and 0", noise.malformed, noise.unreadable)
	}
}

// TestIsRealRecipientPacketVersionWindow pins the inclusive version window: the
// oldest and newest versions are recipients, one either side is not, and the
// window applies only to an unsupported-algorithm error over a non-empty body.
func TestIsRealRecipientPacketVersionWindow(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name string
		body []byte
		err  error
		want bool
	}{
		{"oldest v3", []byte{3}, encryption.ErrUnsupported, true},
		{"newest v6", []byte{6}, encryption.ErrUnsupported, true},
		{"below the window v2", []byte{2}, encryption.ErrUnsupported, false},
		{"above the window v7", []byte{7}, encryption.ErrUnsupported, false},
		{"empty body", []byte{}, encryption.ErrUnsupported, false},
		{"not an unsupported error", []byte{4}, errNotUnsupported, false},
	} {
		if got := isRealRecipientPacket(c.body, c.err); got != c.want {
			t.Errorf("%s: isRealRecipientPacket = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestKeyIDsRendersRetainedAndBeyond pins the two arms of the renderer: exactly
// the retained ids with no overflow suffix when the total matches, the suffix
// when it exceeds, and a positive total with nothing retained (the capacity that
// must still hold the one suffix line).
func TestKeyIDsRendersRetainedAndBeyond(t *testing.T) {
	t.Parallel()

	id1 := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	id2 := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}

	if got := keyIDs([][8]byte{id1, id2}, 2); strings.Contains(got, "more") {
		t.Errorf("keyIDs(2 ids, total 2) = %q, want no overflow suffix", got)
	}

	if got := keyIDs([][8]byte{id1, id2}, 5); !strings.Contains(got, "and 3 more") {
		t.Errorf("keyIDs(2 ids, total 5) = %q, want 'and 3 more'", got)
	}

	if got := keyIDs(nil, 5); got != "and 5 more" {
		t.Errorf("keyIDs(no ids, total 5) = %q, want 'and 5 more'", got)
	}
}

// TestCarriesContentSEDOnlyWhenNotFirst pins that a legacy encrypted-data packet
// settles the question only when it is NOT the first packet — a message never
// opens with its ciphertext, and a covering line that happens to start one must
// not be taken for it.
func TestCarriesContentSEDOnlyWhenNotFirst(t *testing.T) {
	t.Parallel()

	sed := encryption.Packet{Tag: tagSED, Body: []byte{0x00}}

	if !carriesContent(sed, false) {
		t.Error("a legacy encrypted-data packet not in first position should carry content")
	}

	if carriesContent(sed, true) {
		t.Error("a legacy encrypted-data packet in first position must not be recognised")
	}
}

// TestCarriesContentShapeBoundaries pins the three inclusive bounds of a shaped
// packet — minimum body length, minimum version, maximum version — using the
// public-key shape (>= 6 octets, versions 3 through 6). Each is asserted at the
// boundary and one step outside it.
func TestCarriesContentShapeBoundaries(t *testing.T) {
	t.Parallel()

	// At exactly the minimum body length AND the minimum version: both inclusive.
	atMin := encryption.Packet{Tag: encryption.TagPublicKey, Body: []byte{3, 0, 0, 0, 0, 0}}
	if !carriesContent(atMin, false) {
		t.Error("a public-key packet at exactly minBody and minVersion should carry content")
	}

	// At exactly the maximum version: inclusive.
	atMaxVer := encryption.Packet{Tag: encryption.TagPublicKey, Body: []byte{6, 0, 0, 0, 0, 0}}
	if !carriesContent(atMaxVer, false) {
		t.Error("a public-key packet at exactly maxVersion should carry content")
	}

	// One octet short of the minimum body, and either side of the version window.
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"one octet short of minBody", []byte{3, 0, 0, 0, 0}},
		{"below minVersion", []byte{2, 0, 0, 0, 0, 0}},
		{"above maxVersion", []byte{7, 0, 0, 0, 0, 0}},
	} {
		if carriesContent(encryption.Packet{Tag: encryption.TagPublicKey, Body: c.body}, false) {
			t.Errorf("%s: carriesContent = true, want it refused", c.name)
		}
	}
}
