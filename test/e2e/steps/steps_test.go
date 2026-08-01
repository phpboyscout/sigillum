package steps_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
)

// TestFeatures runs the Godog behaviour suite. It is gated on
// INT_TEST_E2E so the unit run stays fast; the cicd go-test component
// sets INT_TEST_E2E=1 for the dedicated e2e job.
func TestFeatures(t *testing.T) {
	if os.Getenv("INT_TEST_E2E") == "" {
		t.Skip("set INT_TEST_E2E=1 to run the Godog behaviour suite")
	}

	suite := godog.TestSuite{
		ScenarioInitializer: initializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../../features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
