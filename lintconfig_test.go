package sigillum_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestEveryLintExclusionGovernsAnEnabledLinter covers finding 17.
//
// A file-scoped exclusion in .golangci.yaml is the sanctioned replacement for
// an inline //nolint, which is forbidden estate-wide. Its value is entirely in
// the written reasoning beside it: this construct, in this file, for this
// stated reason.
//
// That value is void if the linter is not running. The nolint remediation added
// three exclusions for gochecknoglobals, gochecknoinits and containedctx, none
// of which were in the enable list — so they suppressed nothing, and the comment
// claiming "a global introduced anywhere else still fails" was false. Nothing
// failed anywhere. That is worse than the directive it replaced, which at least
// sat beside the thing it excused and could be seen.
//
// Nothing in the toolchain reports an exclusion for a linter that is off, so
// this is the check.
//
// Ported here last of the three modules, which is why it found something
// immediately: sigillum's own _test.go exclusion block listed gochecknoglobals,
// a linter this module does not enable, so the exclusion governed nothing. The
// two sibling modules had carried this guard for a round already.
func TestEveryLintExclusionGovernsAnEnabledLinter(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".golangci.yaml")
	if err != nil {
		t.Fatalf("reading the lint config: %v", err)
	}

	enabled, excluded := parseLintConfig(string(raw))

	// A skip here would be the one way this test goes quiet while still
	// reporting success, and the parser it depends on is indentation-sensitive:
	// a full YAML round-trip rewrites the exclusion lists as indentless
	// sequences, parseLintConfig then finds nothing, and a suite that had been
	// checking every exclusion silently checks none.
	//
	// So: no exclusions is only believable if the file says none. Anything else
	// means the parser lost them, which is a failure of this test rather than a
	// property of the config.
	if len(excluded) == 0 {
		if strings.Contains(string(raw), "- path:") {
			t.Fatal("the config declares path exclusions but none were parsed; parseLintConfig " +
				"has lost track of the file's shape and this test is no longer checking anything")
		}

		t.Skip("no file-scoped exclusions to check")
	}

	for _, linter := range excluded {
		if enabled[linter] {
			continue
		}

		t.Errorf("%q is excluded for a path but is not enabled, so the exclusion suppresses "+
			"nothing and its written reasoning governs nothing", linter)
	}
}

// TestEveryLintExclusionNamesAFileThatExists is the other half of the same rule.
//
// An exclusion is a statement about a specific file, and its written reasoning
// describes that file. When the file is gone — or was never here, because the
// block was copied from a sibling module — the reasoning describes nothing and
// a reader has to work out which of the two is true.
//
// Both modules in this family carried an exclusion for verify/signing_wkd.go,
// which exists in neither. Deleting them is easy; this is what stops the next
// copy-paste reintroducing one.
func TestEveryLintExclusionNamesAFileThatExists(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".golangci.yaml")
	if err != nil {
		t.Fatalf("reading the lint config: %v", err)
	}

	for _, pattern := range exclusionPaths(string(raw)) {
		// Only patterns concrete enough to resolve are checked. `_test\.go`
		// and the like are suffix rules that match many files by design.
		literal, ok := literalPath(pattern)
		if !ok {
			continue
		}

		if _, err := os.Stat(literal); err != nil {
			t.Errorf("the exclusion for %q names %s, which does not exist — its reasoning describes nothing",
				pattern, literal)
		}
	}
}

// exclusionPaths returns the `- path:` values under exclusions.rules.
func exclusionPaths(cfg string) []string {
	var paths []string

	for _, line := range strings.Split(cfg, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "- path: ")
		if !ok {
			continue
		}

		paths = append(paths, strings.Trim(value, `"'`))
	}

	return paths
}

// literalPath turns a path pattern into a filename, when it is one.
//
// Reports false for anything still carrying regex metacharacters after the
// escaped dots are unescaped: those match a class of files rather than naming
// one, and there is nothing to look for.
func literalPath(pattern string) (string, bool) {
	unescaped := strings.ReplaceAll(pattern, `\.`, ".")

	if strings.ContainsAny(unescaped, `\^$*+?()[]{}|`) {
		return "", false
	}

	// A trailing slash names a directory, which Stat handles either way.
	if !strings.Contains(unescaped, "/") && strings.HasPrefix(unescaped, "_") {
		return "", false
	}

	return strings.TrimSuffix(unescaped, "/"), true
}

// golangciDefaults are the linters golangci-lint runs without being asked, so
// an exclusion for one of them is doing real work even though `enable` does not
// mention it.
var golangciDefaults = map[string]bool{
	"errcheck":    true,
	"govet":       true,
	"ineffassign": true,
	"staticcheck": true,
	"unused":      true,
}

// parseLintConfig returns the enabled linters and every linter named by a
// file-scoped exclusion.
//
// Indentation-based rather than a YAML dependency: the shape being read is two
// flat lists, and pulling in a parser for that would be worse than the parsing.
func parseLintConfig(cfg string) (enabled map[string]bool, excluded []string) {
	enabled = map[string]bool{}
	for name := range golangciDefaults {
		enabled[name] = true
	}

	const (
		enableIndent    = 4  // "  enable:" items sit at four spaces
		exclusionIndent = 10 // items under exclusions.rules[].linters
	)

	var inEnable, inExclusionLinters bool

	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if key, isKey := sectionKey(trimmed); isKey {
			inEnable = key == "enable"
			inExclusionLinters = key == "linters" && indent >= exclusionIndent-2

			continue
		}

		name, ok := strings.CutPrefix(trimmed, "- ")
		if !ok {
			continue
		}

		// "- path: keyservice\.go" starts a new exclusion rule; it is a mapping
		// entry, not a linter name. Reaching one means any linters list that
		// was open belongs to the previous rule.
		if strings.Contains(name, ":") {
			inExclusionLinters = false

			continue
		}

		switch {
		case inEnable && indent == enableIndent:
			enabled[name] = true
		case inExclusionLinters:
			excluded = append(excluded, name)
		}
	}

	return enabled, excluded
}

// sectionKey reports the mapping key a line opens, if it opens one.
func sectionKey(trimmed string) (string, bool) {
	if strings.HasPrefix(trimmed, "- ") || !strings.HasSuffix(trimmed, ":") {
		return "", false
	}

	return strings.TrimSuffix(trimmed, ":"), true
}

// TestFormatterSettingsGovernAnEnabledFormatter is the exclusions rule applied
// to the other half of the file.
//
// A settings block for a formatter that is not enabled configures nothing, in
// exactly the way an exclusion for a linter that is not enabled suppresses
// nothing — and the guard above was written for the second and never looked at
// the first. All three modules carried a gofumpt block while enabling only
// gofmt and goimports, so its module-path and extra-rules governed nothing and
// nothing said so.
func TestFormatterSettingsGovernAnEnabledFormatter(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".golangci.yaml")
	if err != nil {
		t.Fatalf("reading the lint config: %v", err)
	}

	enabled, configured := parseFormatters(string(raw))

	for _, name := range configured {
		if !enabled[name] {
			t.Errorf("%q has a settings block but is not enabled, so those settings govern nothing",
				name)
		}
	}
}

// TestLocalPrefixesNamesThisModule covers an import-grouping rule pointed at
// somebody else.
//
// goimports groups imports of the local module apart from third-party ones, so
// a local-prefixes naming a different module puts this module's own imports in
// the wrong group — and since the gate then never fires, nothing reports it.
// Both encryption modules named gitlab.com/phpboyscout/go/signing, which
// neither of them is.
func TestLocalPrefixesNamesThisModule(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(".golangci.yaml")
	if err != nil {
		t.Fatalf("reading the lint config: %v", err)
	}

	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	match := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindSubmatch(mod)
	if match == nil {
		t.Fatal("go.mod declares no module path")
	}

	self := string(match[1])

	prefixes := localPrefixes(string(raw))
	if len(prefixes) == 0 {
		t.Skip("no local-prefixes configured")
	}

	if !slices.Contains(prefixes, self) {
		t.Errorf("local-prefixes is %v and this module is %q, so goimports groups this module's "+
			"own imports as third-party and the gate governs nothing", prefixes, self)
	}
}

// parseFormatters returns the enabled formatters and every formatter with a
// settings block.
func parseFormatters(cfg string) (enabled map[string]bool, configured []string) {
	enabled = map[string]bool{}

	var inFormatters, inEnable, inSettings bool

	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			inFormatters = trimmed == "formatters:"
			inEnable, inSettings = false, false

			continue
		}

		if !inFormatters {
			continue
		}

		if key, isKey := sectionKey(trimmed); isKey {
			switch {
			case indent == 2:
				inEnable, inSettings = key == "enable", key == "settings"
			case indent == 4 && inSettings:
				configured = append(configured, key)
			}

			continue
		}

		if name, ok := strings.CutPrefix(trimmed, "- "); ok && inEnable {
			enabled[name] = true
		}
	}

	return enabled, configured
}

// localPrefixes returns the values under formatters.settings.goimports.
func localPrefixes(cfg string) []string {
	var (
		out    []string
		inList bool
	)

	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)

		if key, isKey := sectionKey(trimmed); isKey {
			inList = key == "local-prefixes"

			continue
		}

		if value, ok := strings.CutPrefix(trimmed, "- "); ok && inList {
			out = append(out, strings.Trim(value, `"'`))
		}
	}

	return out
}
