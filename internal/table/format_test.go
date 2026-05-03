package table

import "testing"

func TestFormatBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0B"},
		{512, "512B"},
		{1023, "1023B"},
		{1024, "1K"},
		{1536, "2K"},
		{1048576, "1M"},
		{5242880, "5M"},
		{1073741824, "1.0G"},
		{5368709120, "5.0G"},
		{1099511627776, "1.0T"},
	}

	for _, test := range tests {
		got := FormatBytes(test.input)
		if got != test.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestFormatCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{500, "500"},
		{999, "999"},
		{1000, "1.0K"},
		{1500, "1.5K"},
		{1000000, "1.0M"},
		{1000000000, "1.0G"},
	}

	for _, test := range tests {
		got := FormatCount(test.input)
		if got != test.want {
			t.Errorf("FormatCount(%d) = %q, want %q", test.input, got, test.want)
		}
	}
}
