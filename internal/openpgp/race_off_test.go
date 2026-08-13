//go:build !race

package openpgp_test

// raceDetector reports whether this binary was built with -race. See
// race_on_test.go for why any test cares.
const raceDetector = false
