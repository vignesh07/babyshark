package app

import "testing"

func TestRunMissingArgs(t *testing.T) {
	if code := Run([]string{}); code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}
