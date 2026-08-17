// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package version

import (
	"strings"
	"testing"
)

// The pseudo version is the whole reason this package does any parsing: it is
// what the toolchain stamps on `go install` for a repository without a release
// tag, and printing it whole is what made the version line unreadable.
func TestSplitPseudoTakesApartAGoInstallVersion(t *testing.T) {
	rev, date, ok := splitPseudo("v0.0.0-20260816202400-dc8e73d072ba")
	if !ok {
		t.Fatal("a real pseudo version was not recognised")
	}
	if rev != "dc8e73d072ba" {
		t.Errorf("revision = %q, want dc8e73d072ba", rev)
	}
	if date != "2026-08-16" {
		t.Errorf("date = %q, want 2026-08-16", date)
	}
}

func TestSplitPseudoRejectsReleaseTags(t *testing.T) {
	// Tags with a prerelease segment are the trap here: they have the dashes a
	// pseudo version has, so only the 14-digit stamp and 12 hex digits tell
	// them apart. Treating one as a pseudo version would drop the tag name.
	for _, v := range []string{
		"v1.2.3",
		"v1.2.3-rc.1",
		"v1.2.3-beta-2",
		"(devel)",
		"",
		// Right shape, wrong widths.
		"v0.0.0-2026081620240-dc8e73d072ba",
		"v0.0.0-20260816202400-dc8e73d072b",
		"v0.0.0-20260816202400-dc8e73d072bz",
	} {
		if _, _, ok := splitPseudo(v); ok {
			t.Errorf("%q was read as a pseudo version", v)
		}
	}
}

func TestReleaseNormalisesTheVSpelling(t *testing.T) {
	// The module path carries "v1.2.3", goreleaser hands over "1.2.3". The
	// same release must not print two names depending on how it was installed.
	if got := release("v1.2.3"); got != "1.2.3" {
		t.Errorf("release(v1.2.3) = %q, want 1.2.3", got)
	}
	if got := release("1.2.3"); got != "1.2.3" {
		t.Errorf("release(1.2.3) = %q, want 1.2.3", got)
	}
}

func TestShortDateKeepsTheDayAndRejectsJunk(t *testing.T) {
	if got := shortDate("2026-08-16T20:24:00Z"); got != "2026-08-16" {
		t.Errorf("shortDate = %q, want 2026-08-16", got)
	}
	for _, d := range []string{"", "unknown", "2026/08/16", "20260816", "xxxx-xx-xx"} {
		if got := shortDate(d); got != "" {
			t.Errorf("shortDate(%q) = %q, want empty", d, got)
		}
	}
}

func TestRenderedIdentity(t *testing.T) {
	cases := []struct {
		name         string
		b            build
		short, whole string
	}{
		{
			name:  "release build",
			b:     build{version: "1.2.3", commit: "a1b2c3d4e5f6", date: "2026-08-16"},
			short: "1.2.3",
			whole: "1.2.3 (a1b2c3d, 2026-08-16)",
		},
		{
			// `go install ...@latest` against an untagged repository. The
			// commit is what identifies the build, so it belongs in the name.
			name:  "untagged install",
			b:     build{version: "dev", commit: "dc8e73d072ba", date: "2026-08-16"},
			short: "dev-dc8e73d",
			whole: "dev-dc8e73d (2026-08-16)",
		},
		{
			name:  "uncommitted working tree",
			b:     build{version: "dev", commit: "dc8e73d072ba", date: "2026-08-16", dirty: true},
			short: "dev-dc8e73d-dirty",
			whole: "dev-dc8e73d-dirty (2026-08-16)",
		},
		{
			name:  "no vcs information at all",
			b:     build{version: "dev"},
			short: "dev",
			whole: "dev",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.b.short(); got != c.short {
				t.Errorf("short() = %q, want %q", got, c.short)
			}
			if got := c.b.string(); got != c.whole {
				t.Errorf("string() = %q, want %q", got, c.whole)
			}
		})
	}
}

// Whatever the build, the version line has to stay something a person can read
// back over the phone: no pseudo version, no 40 character revision.
func TestResolvedIdentityIsReadable(t *testing.T) {
	s := String()
	if s == "" {
		t.Fatal("String() is empty")
	}
	if _, _, ok := splitPseudo(strings.Fields(s)[0]); ok {
		t.Errorf("String() = %q, still a raw pseudo version", s)
	}
	if strings.Contains(s, "(devel)") {
		t.Errorf("String() = %q, leaked the toolchain placeholder", s)
	}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')' || r == ','
	}) {
		if len(f) > 12 && isHex(f) {
			t.Errorf("String() = %q, contains an unshortened revision", s)
		}
	}
	if b := resolve(); b.version != "dev" && strings.HasPrefix(b.version, "v") {
		t.Errorf("version = %q, want the v stripped", b.version)
	}
}
