package stringutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsASCII(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		s    string
		want bool
	}{
		"ASCII string":     {s: "hello", want: true},
		"Non-ASCII string": {s: "hello£", want: false},
		"Empty string":     {s: "", want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := IsASCII(tt.s)
			require.Equal(t, tt.want, got)
		})
	}
}
