package buildinfo

import "testing"

func TestSummary(t *testing.T) {
	t.Parallel()

	originalVersion := Version
	originalCommit := Commit
	t.Cleanup(func() {
		Version = originalVersion
		Commit = originalCommit
	})

	Version = "1.2.3"
	Commit = "abc1234"
	if got, want := Summary(), "1.2.3 (abc1234)"; got != want {
		t.Fatalf("Summary mismatch: got %q want %q", got, want)
	}

	Commit = "unknown"
	if got, want := Summary(), "1.2.3"; got != want {
		t.Fatalf("Summary mismatch without commit: got %q want %q", got, want)
	}
}
