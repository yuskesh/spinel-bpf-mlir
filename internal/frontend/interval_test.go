package frontend

import (
	"math/big"
	"testing"
)

// TestFloorDiv checks that floorDiv agrees with Ruby's Integer#/ (the expected values are CRuby's).
func TestFloorDiv(t *testing.T) {
	t.Parallel()
	for _, c := range [][3]int64{{-7, 2, -4}, {7, -2, -4}, {-7, -2, 3}, {7, 2, 3}, {6, -2, -3}, {-8, 8, -1}, {0, -8, 0}} {
		if got := floorDiv(big.NewInt(c[0]), big.NewInt(c[1])); got.Int64() != c[2] {
			t.Errorf("%d / %d = %s, want %d", c[0], c[1], got, c[2])
		}
	}
}

func TestIvBit(t *testing.T) {
	t.Parallel()
	a := iv(big.NewInt(-5), big.NewInt(100))
	m := point(big.NewInt(0xFF))
	if r := ivBit("&", a, m); r.Lo.Sign() != 0 || r.Hi.Int64() != 0xFF {
		t.Fatal(r)
	}
	if r := ivBit("|", iv(big.NewInt(0), big.NewInt(5)), iv(big.NewInt(0), big.NewInt(9))); r.Hi.Int64() != 15 {
		t.Fatal(r)
	}
}

// TestUnescape tests the decoding of the percent-encoding in Spinel's text AST (Spinel escapes strings there with percent-encoding,
// not with the backslashes its documentation describes).
func TestUnescape(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"%25": "%", "a%20b": "a b", "x%0Ay": "x\ny", "plain": "plain", "%2": "%2", "100%25%25": "100%%"} {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q, want %q", in, got, want)
		}
	}
}
