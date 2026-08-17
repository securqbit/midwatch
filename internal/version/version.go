// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package version carries build identity for the midwatch binary.
package version

import (
	"runtime/debug"
	"strings"
	"sync"
)

// Version is overwritten at build time via
// -ldflags "-X github.com/securqbit/midwatch/internal/version.Version=1.2.3".
// Release builds (the Makefile and .goreleaser.yaml) set all three. Unstamped
// builds fall back to what the Go toolchain embeds; see resolve.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// build is the resolved identity: the linker flags where they were set, the
// toolchain's own build info where they were not.
type build struct {
	version string // "1.2.3", or "dev" for an untagged build
	commit  string // full or short revision, may be empty
	date    string // YYYY-MM-DD, may be empty
	dirty   bool   // the working tree carried uncommitted changes
}

// resolve reads build identity once. Nothing here can change during a run.
//
// The toolchain stamps a module version and VCS settings by itself, but the
// module version it stamps for anything without a release tag is a pseudo
// version: `v0.0.0-20260816202400-dc8e73d072ba+dirty`. That is precise and
// unreadable, and printing it as-is makes an untagged build look like a
// released one. So a pseudo version is taken apart for the parts worth showing
// (revision, date) rather than shown whole.
var resolve = sync.OnceValue(func() build {
	b := build{commit: Commit, date: shortDate(Date)}
	if Version != "" && Version != "dev" {
		b.version = release(Version)
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if b.version == "" {
			b.version = "dev"
		}
		return b
	}

	main := bi.Main.Version
	if trimmed, ok := strings.CutSuffix(main, "+dirty"); ok {
		main = trimmed
		b.dirty = true
	}
	rev, date, pseudo := splitPseudo(main)
	if b.version == "" {
		// "(devel)" and pseudo versions both mean "no release tag here".
		if pseudo || main == "" || main == "(devel)" {
			b.version = "dev"
		} else {
			b.version = release(main)
		}
	}
	if pseudo {
		if b.commit == "" {
			b.commit = rev
		}
		if b.date == "" {
			b.date = date
		}
	}

	// VCS settings are present for builds made from a checkout, and are more
	// precise than the pseudo version, so they win.
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				b.commit = s.Value
			}
		case "vcs.time":
			if d := shortDate(s.Value); d != "" {
				b.date = d
			}
		case "vcs.modified":
			b.dirty = b.dirty || s.Value == "true"
		}
	}
	return b
})

// Short returns the version alone, for the JSON report. Untagged builds are
// named after the commit they came from, because a report is evidence and
// bare "dev" would not say which build produced it.
func Short() string { return resolve().short() }

// String returns a human readable build identifier: the version, then whatever
// else is known about where it came from.
func String() string { return resolve().string() }

func (b build) short() string {
	v := b.version
	if v == "dev" && b.commit != "" {
		v += "-" + shortCommit(b.commit)
	}
	if b.dirty && !strings.HasSuffix(v, "-dirty") {
		v += "-dirty"
	}
	return v
}

func (b build) string() string {
	short := b.short()

	var detail []string
	if c := shortCommit(b.commit); c != "" && !strings.Contains(short, c) {
		detail = append(detail, c)
	}
	if b.date != "" {
		detail = append(detail, b.date)
	}
	if len(detail) == 0 {
		return short
	}
	return short + " (" + strings.Join(detail, ", ") + ")"
}

// release normalises a release version to one spelling. The module path
// carries "v1.2.3" and goreleaser hands over "1.2.3"; the same build should
// not print two different names depending on how it was installed.
func release(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// splitPseudo reports whether v is a Go pseudo version, and if so returns the
// revision and date buried in it. The shape is <base>-<yyyymmddhhmmss>-<rev>,
// where the revision is exactly 12 hex digits.
func splitPseudo(v string) (rev, date string, ok bool) {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return "", "", false
	}
	rev = parts[len(parts)-1]
	stamp := parts[len(parts)-2]
	if len(rev) != 12 || !isHex(rev) || len(stamp) != 14 || !isDigits(stamp) {
		return "", "", false
	}
	return rev, stamp[:4] + "-" + stamp[4:6] + "-" + stamp[6:8], true
}

// shortDate keeps the day from an RFC 3339 timestamp. The hour a binary was
// linked is noise; the day it was cut is not.
func shortDate(d string) string {
	d = strings.TrimSpace(d)
	if len(d) < 10 || d[4] != '-' || d[7] != '-' {
		return ""
	}
	if !isDigits(d[:4]) || !isDigits(d[5:7]) || !isDigits(d[8:10]) {
		return ""
	}
	return d[:10]
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
