// SPDX-License-Identifier: BSD-3-Clause

package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	k, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := k.Sign(Claims{Expiry: now.Add(time.Hour), Class: "c1", Session: "s7"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := k.Verify(tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Class != "c1" || c.Session != "s7" || c.KeyID != 1 || !c.Expiry.Equal(now.Add(time.Hour)) {
		t.Fatalf("%+v", c)
	}
	if _, err := k.Verify(tok, now.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v", err)
	}
}

func TestTokenTampered(t *testing.T) {
	k, _ := NewKeys()
	other, _ := NewKeys()
	now := time.Unix(1_800_000_000, 0)
	tok, _ := k.Sign(Claims{Expiry: now.Add(time.Hour), Class: "c1", Session: "s7"})
	// Another relay's key: same key id, other key.
	if _, err := other.Verify(tok, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key: %v", err)
	}
	// Change the session id inside the claims, keep the signature.
	forged, _ := k.Sign(Claims{Expiry: now.Add(time.Hour), Class: "c1", Session: "s8"})
	head := forged[:strings.LastIndexByte(forged, '.')]
	sig := tok[strings.LastIndexByte(tok, '.'):]
	if _, err := k.Verify(head+sig, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("spliced: %v", err)
	}
	for _, bad := range []string{"", "v2." + tok[3:], tok + ".x", tok + "=", strings.Replace(tok, "v1.", "v1..", 1), strings.Repeat("a", MaxTokenLen+1)} {
		if _, err := k.Verify(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnknownKey(t *testing.T) {
	k, _ := NewKeys()
	now := time.Unix(1_800_000_000, 0)
	tok, _ := k.Sign(Claims{Expiry: now.Add(time.Hour), Class: "c", Session: "s"})
	k.Current = 2
	k.Private[2] = k.Private[1]
	delete(k.Private, 1)
	if _, err := k.Verify(tok, now); !errors.Is(err, ErrKey) {
		t.Fatal(err)
	}
}

func TestJoinCode(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c, err := NewJoinCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != CodeLen || strings.ContainsAny(c, "ILOU") {
			t.Fatal(c)
		}
		n, err := NormalizeJoinCode(strings.ToLower(c[:5]) + "-" + c[5:])
		if err != nil || n != c {
			t.Fatal(c, n, err)
		}
		seen[c] = true
	}
	if len(seen) < 99 {
		t.Fatal("codes repeat")
	}
	if n, _ := NormalizeJoinCode("o1l1o 1i1o1"); n != "0111011101" {
		t.Fatal(n)
	}
	for _, bad := range []string{"", "ABC", "ABCDEFGHJKM", "ABCDEFGHJ!", "ABCDEFGHJU"} {
		if _, err := NormalizeJoinCode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"Alice":                        "alice",
		"Jean-Pierre Dupont":           "jean-pierre-dupont",
		"  Zoé  ":                      "zo",
		"42":                           "s-42",
		"!!!":                          "student",
		"<script>alert(1)</script>":    "script-alert-1-scrip", // 20 bytes
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa": "aaaaaaaaaaaaaaaaaaaa",
	} {
		if got := Label(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestCleanDisplayName(t *testing.T) {
	if got := CleanDisplayName(" Bob‮\x00\n "); got != "Bob" {
		t.Fatalf("%q", got)
	}
	if got := CleanDisplayName(strings.Repeat("é", 100)); len([]rune(got)) != 40 {
		t.Fatal(len([]rune(got)))
	}
}

func TestEqual(t *testing.T) {
	if !Equal("abc", "abc") || Equal("abc", "abd") || Equal("abc", "ab") {
		t.Fatal("Equal")
	}
}

func FuzzParseToken(f *testing.F) {
	k, _ := NewKeys()
	tok, _ := k.Sign(Claims{Expiry: time.Unix(1_800_000_000, 0), Class: "c", Session: "s"})
	f.Add(tok)
	f.Add("v1..")
	f.Add("v1.AA.AA")
	f.Fuzz(func(t *testing.T, s string) {
		c, head, sig, err := ParseToken(s)
		if err != nil {
			return
		}
		if len(sig) != 64 || !strings.HasPrefix(s, head+".") || len(c.Class) > 64 || len(c.Session) > 64 {
			t.Fatalf("%q parsed into %+v", s, c)
		}
		// A parsed token never verifies under a key that did not sign it.
		if _, err := k.Verify(s, time.Unix(0, 0)); err == nil && s != tok {
			t.Fatalf("%q verified", s)
		}
	})
}

func FuzzNormalizeJoinCode(f *testing.F) {
	f.Add("ABCDE-FGHJK")
	f.Add("oooooooooo")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := NormalizeJoinCode(s)
		if err != nil {
			return
		}
		if len(n) != CodeLen {
			t.Fatal(n)
		}
		for _, r := range n {
			if !strings.ContainsRune(codeAlphabet, r) {
				t.Fatal(n)
			}
		}
	})
}

func FuzzLabel(f *testing.F) {
	f.Add("Alice")
	f.Add("ü-ü")
	f.Fuzz(func(t *testing.T, s string) {
		l := Label(s)
		if l == "" || len(l) > 22 || l[0] == '-' || l[len(l)-1] == '-' {
			t.Fatalf("%q -> %q", s, l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				t.Fatalf("%q -> %q", s, l)
			}
		}
	})
}
