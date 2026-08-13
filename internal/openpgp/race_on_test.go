//go:build race

package openpgp_test

// raceDetector reports whether this binary was built with -race.
//
// The detector instruments every allocation, so a test that measures heap
// growth against the size of its input measures the instrumentation instead —
// the candidate-memory test reads about 7x without it and about 21x with it,
// which says nothing about the code. The property is still worth asserting, so
// it is asserted in the ordinary build and skipped here rather than loosened to
// a threshold that would pass either way.
const raceDetector = true
