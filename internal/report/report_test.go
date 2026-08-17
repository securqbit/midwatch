// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSeverityRoundTrip(t *testing.T) {
	for _, name := range []string{"info", "low", "medium", "high", "critical"} {
		s, ok := ParseSeverity(name)
		if !ok {
			t.Fatalf("ParseSeverity(%q) failed", name)
		}
		if s.String() != name {
			t.Errorf("%q round tripped to %q", name, s.String())
		}
	}
	if _, ok := ParseSeverity("catastrophic"); ok {
		t.Error("ParseSeverity accepted an unknown severity")
	}
	if _, ok := ParseSeverity("HIGH"); !ok {
		t.Error("ParseSeverity should be case insensitive")
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(SevInfo < SevLow && SevLow < SevMedium && SevMedium < SevHigh && SevHigh < SevCritical) {
		t.Fatal("severity ordering is not monotonic; --fail-on comparisons depend on it")
	}
}

func TestModuleMaxSeverity(t *testing.T) {
	m := NewModule("tls", "TLS", KindInterception)
	if _, has := m.MaxSeverity(); has {
		t.Error("an empty module reported a max severity")
	}
	m.Add("a", "low thing", SevLow, "")
	m.Add("b", "bad thing", SevHigh, "")
	m.Add("c", "medium thing", SevMedium, "")

	worst, has := m.MaxSeverity()
	if !has || worst != SevHigh {
		t.Errorf("MaxSeverity = %v/%v, want high/true", worst, has)
	}
	m.SortFindings()
	if m.Findings[0].Severity != SevHigh {
		t.Error("SortFindings did not put the worst finding first")
	}
}

func TestRowsGroupIntoSections(t *testing.T) {
	m := NewModule("dns", "DNS", KindInterception)
	m.Row("answers", StatusOK, "one", "value", "note")
	m.Row("answers", StatusBad, "two", "value", "note")
	m.Row("transport", StatusWarn, "three", "", "")

	if len(m.Sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(m.Sections))
	}
	if len(m.Sections[0].Rows) != 2 {
		t.Errorf("first section has %d rows, want 2", len(m.Sections[0].Rows))
	}
	if m.Sections[0].Title != "answers" {
		t.Errorf("section order not preserved: got %q first", m.Sections[0].Title)
	}
}

// Posture modules describe policy, not attack. They must not be able to push
// the run's verdict toward "compromised" on their own.
func TestPostureLevelDoesNotDriveVerdict(t *testing.T) {
	started := time.Now()
	r := &Report{Tool: "midwatch"}

	clean := NewModule("tls", "TLS", KindInterception)
	clean.SetLevel(0, "L0", "No interception detected", "")
	r.Add(clean)

	strict := NewModule("egress", "Egress", KindPosture)
	strict.SetLevel(3, "E3", "Web-only egress", "")
	r.Add(strict)

	r.Finalize(started)

	if got := r.MaxInterceptionLevel(); got != 0 {
		t.Errorf("MaxInterceptionLevel = %d, want 0", got)
	}
	if got := r.MaxLevel(); got != 3 {
		t.Errorf("MaxLevel = %d, want 3 (posture levels are still reported)", got)
	}
	if !strings.HasPrefix(r.Verdict, "Clean") {
		t.Errorf("verdict = %q, want a clean verdict driven by interception only", r.Verdict)
	}
}

// Posture findings are reported and can gate CI, but they describe policy, so
// they must not deduct from the score or unsettle the verdict. A network that
// prefers HTTP/2 over HTTP/3, or filters a port, is not an intercepted one.
func TestPostureFindingsDoNotDriveScoreOrVerdict(t *testing.T) {
	r := &Report{Tool: "midwatch"}

	clean := NewModule("tls", "TLS", KindInterception)
	clean.SetLevel(0, "L0", "No interception detected", "")
	r.Add(clean)

	egress := NewModule("egress", "Egress", KindPosture)
	egress.Add("egress.quic-blocked", "QUIC blocked", SevMedium, "")
	egress.Add("egress.udp-blocked", "UDP blocked", SevLow, "")
	r.Add(egress)

	slow := NewModule("time", "Time", KindPosture)
	slow.Add("time.skew", "Clock skew", SevHigh, "")
	r.Add(slow)

	r.Finalize(time.Now())

	if r.Score != 100 {
		t.Errorf("score = %d, want 100 (posture findings must not deduct)", r.Score)
	}
	if !strings.HasPrefix(r.Verdict, "Clean") {
		t.Errorf("verdict = %q, want Clean — no interception was detected", r.Verdict)
	}
	// --fail-on reads MaxSeverity, so posture findings still gate a build.
	if worst, has := r.MaxSeverity(); !has || worst != SevHigh {
		t.Errorf("MaxSeverity = %v/%v, want high/true so --fail-on still sees posture", worst, has)
	}
	if _, has := r.MaxInterceptionSeverity(); has {
		t.Error("MaxInterceptionSeverity reported a finding, but only posture modules had any")
	}
}

// An interception finding of the same severity must still move the score, or
// the exclusion above would have hollowed out the scoring entirely.
func TestInterceptionFindingsStillDriveScore(t *testing.T) {
	r := &Report{Tool: "midwatch"}
	m := NewModule("dns", "DNS", KindInterception)
	m.Add("dns.query-rewritten", "Query rewritten", SevMedium, "")
	r.Add(m)
	r.Finalize(time.Now())

	if r.Score != 92 {
		t.Errorf("score = %d, want 92", r.Score)
	}
	if !strings.HasPrefix(r.Verdict, "Observed") {
		t.Errorf("verdict = %q, want Observed", r.Verdict)
	}
}

// Blocking the services people use to reach each other is not policy trivia.
// It has to cost the score and it has to be named in the verdict, or a run that
// found Signal and Telegram unreachable would print "Clean".
func TestCensorshipFindingsDriveScoreAndVerdict(t *testing.T) {
	r := &Report{Tool: "midwatch"}

	clean := NewModule("tls", "TLS", KindInterception)
	clean.SetLevel(0, "L0", "No interception detected", "")
	r.Add(clean)

	comms := NewModule("comms", "Communication reachability", KindCensorship)
	comms.SetLevel(3, "C3", "Private messaging blocked", "")
	comms.Add("comms.blocked", "Signal and Telegram cannot be reached on this network", SevHigh, "")
	r.Add(comms)

	r.Finalize(time.Now())

	if r.Score != 82 {
		t.Errorf("score = %d, want 82 (a high censorship finding must deduct)", r.Score)
	}
	if !strings.HasPrefix(r.Verdict, "Censored") {
		t.Errorf("verdict = %q, want it to lead with Censored", r.Verdict)
	}
	// The claim has to stay accurate: nothing here was decrypted.
	if strings.Contains(r.Verdict, "decrypted") {
		t.Errorf("verdict = %q, but no interception was found", r.Verdict)
	}
	if worst, has := r.MaxCensorshipSeverity(); !has || worst != SevHigh {
		t.Errorf("MaxCensorshipSeverity = %v/%v, want high/true", worst, has)
	}
	if _, has := r.MaxInterceptionSeverity(); has {
		t.Error("a blocking finding must not be counted as interception")
	}
}

func TestCensorshipSeverityChoosesTheSentence(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SevHigh, "Censored"},
		{SevCritical, "Censored"},
		{SevMedium, "Restricted"},
		// Downgraded behind a tunnel: the tunnel operator's forwarding policy
		// is not this network censoring anyone.
		{SevInfo, "Clean"},
		{SevLow, "Clean"},
	}
	for _, tc := range tests {
		t.Run(tc.want+"/"+tc.sev.String(), func(t *testing.T) {
			r := &Report{Tool: "midwatch"}
			m := NewModule("comms", "Comms", KindCensorship)
			m.Add("comms.blocked", "blocked", tc.sev, "")
			r.Add(m)
			r.Finalize(time.Now())
			if !strings.HasPrefix(r.Verdict, tc.want) {
				t.Errorf("severity %v gave verdict %q, want it to start with %q",
					tc.sev, r.Verdict, tc.want)
			}
		})
	}
}

// Both axes at once must produce one sentence that says both things, without
// either claim borrowing the other's evidence.
func TestInterceptionAndCensorshipCompose(t *testing.T) {
	r := &Report{Tool: "midwatch"}

	tls := NewModule("tls", "TLS", KindInterception)
	tls.SetLevel(3, "L3", "Full decryption via an installed root", "")
	tls.Add("tls.intercepted", "decrypted", SevHigh, "")
	r.Add(tls)

	comms := NewModule("comms", "Comms", KindCensorship)
	comms.Add("comms.blocked", "blocked", SevHigh, "")
	r.Add(comms)

	r.Finalize(time.Now())

	if r.Score != 64 {
		t.Errorf("score = %d, want 64 (both axes deduct)", r.Score)
	}
	for _, want := range []string{"Compromised", "censored", "decrypted", "contact"} {
		if !strings.Contains(r.Verdict, want) {
			t.Errorf("verdict %q is missing %q", r.Verdict, want)
		}
	}
}

// A censorship module that found nothing still changes the clean sentence,
// because "no blocking detected" is only sayable when blocking was looked for.
func TestCleanVerdictMentionsBlockingOnlyWhenChecked(t *testing.T) {
	withComms := &Report{Tool: "midwatch"}
	withComms.Add(NewModule("comms", "Comms", KindCensorship))
	withComms.Finalize(time.Now())
	if !strings.Contains(withComms.Verdict, "blocking") {
		t.Errorf("verdict = %q, want it to record that blocking was checked", withComms.Verdict)
	}

	withoutComms := &Report{Tool: "midwatch"}
	withoutComms.Add(NewModule("tls", "TLS", KindInterception))
	withoutComms.Finalize(time.Now())
	if strings.Contains(withoutComms.Verdict, "blocking") {
		t.Errorf("verdict = %q claims nothing was blocked, but nothing checked", withoutComms.Verdict)
	}
}

// A finding may measure something its module does not. The comms module finds a
// forged certificate while checking reachability, and that is interception —
// scored, and described, as interception.
func TestFindingKindOverridesItsModule(t *testing.T) {
	r := &Report{Tool: "midwatch"}
	comms := NewModule("comms", "Comms", KindCensorship)
	comms.SetLevel(4, "C4", "Communication intercepted", "")
	comms.AddOfKind(KindInterception, "comms.intercepted", "forged certificate", SevCritical, "")
	r.Add(comms)
	r.Finalize(time.Now())

	if worst, has := r.MaxInterceptionSeverity(); !has || worst != SevCritical {
		t.Errorf("MaxInterceptionSeverity = %v/%v, want critical/true", worst, has)
	}
	if _, has := r.MaxCensorshipSeverity(); has {
		t.Error("the overridden finding must not also count as censorship")
	}
	if r.Score != 66 {
		t.Errorf("score = %d, want 66", r.Score)
	}
	// A confirmed forgery is a compromise even though the module that found it
	// grades reachability, and nothing here was actually blocked.
	if !strings.HasPrefix(r.Verdict, "Compromised") {
		t.Errorf("verdict = %q, want Compromised", r.Verdict)
	}
	if strings.Contains(r.Verdict, "censored") {
		t.Errorf("verdict = %q claims censorship, but nothing was blocked", r.Verdict)
	}
	// The override travels into the JSON so consumers can see it too.
	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"kind": "interception"`) {
		t.Error("the finding's kind override is missing from the JSON output")
	}
}

func TestFinalizeScoring(t *testing.T) {
	tests := []struct {
		name      string
		sev       Severity
		count     int
		level     int
		wantScore int
		wantWord  string
	}{
		{"nothing found", SevInfo, 0, 0, 100, "Clean"},
		{"one medium", SevMedium, 1, 0, 92, "Observed"},
		{"one high", SevHigh, 1, 1, 82, "Observed"},
		{"two high", SevHigh, 2, 2, 64, "Tampered"},
		{"one critical", SevCritical, 1, 4, 66, "Compromised"},
		{"floor at zero", SevCritical, 9, 4, 0, "Compromised"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Tool: "midwatch"}
			m := NewModule("tls", "TLS", KindInterception)
			for i := 0; i < tc.count; i++ {
				m.Add("id", "finding", tc.sev, "")
			}
			m.SetLevel(tc.level, "L", "level", "")
			r.Add(m)
			r.Finalize(time.Now())

			if r.Score != tc.wantScore {
				t.Errorf("score = %d, want %d", r.Score, tc.wantScore)
			}
			if !strings.HasPrefix(r.Verdict, tc.wantWord) {
				t.Errorf("verdict = %q, want it to start with %q", r.Verdict, tc.wantWord)
			}
		})
	}
}

func TestJSONShape(t *testing.T) {
	r := &Report{Tool: "midwatch", Version: "test", StartedAt: time.Now(), Platform: "test/test"}
	m := NewModule("tls", "TLS interception", KindInterception)
	m.SetLevel(2, "L2", "Selective decryption", "summary")
	m.Row("endpoints", StatusBad, "host", "value", "note")
	m.Add("tls.intercepted", "title", SevCritical, "detail", "evidence")
	r.Add(m)
	r.Finalize(time.Now())

	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	mods, ok := decoded["modules"].([]any)
	if !ok || len(mods) != 1 {
		t.Fatalf("modules missing from JSON output")
	}
	mod := mods[0].(map[string]any)
	if mod["kind"] != "interception" {
		t.Errorf("kind = %v, want interception", mod["kind"])
	}
	// Enums must serialise as names: consumers should never see ordinals.
	f := mod["findings"].([]any)[0].(map[string]any)
	if f["severity"] != "critical" {
		t.Errorf("severity serialised as %v, want \"critical\"", f["severity"])
	}
	row := mod["sections"].([]any)[0].(map[string]any)["rows"].([]any)[0].(map[string]any)
	if row["status"] != "bad" {
		t.Errorf("status serialised as %v, want \"bad\"", row["status"])
	}
}

func TestRenderModuleIsPlainWithoutColor(t *testing.T) {
	m := NewModule("tls", "TLS interception", KindInterception)
	m.SetLevel(4, "L4", "Untrusted interception", "a summary that should be wrapped across lines")
	m.Row("endpoints", StatusBad, "host.example", "value", "note")
	m.Add("tls.intercepted", "Traffic is being decrypted", SevCritical, "detail", "evidence")
	m.Done()

	var buf bytes.Buffer
	RenderModule(&buf, Palette{On: false}, m)
	out := buf.String()

	if strings.Contains(out, "\x1b[") {
		t.Error("ANSI escapes present when colour is disabled")
	}
	for _, want := range []string{"TLS INTERCEPTION", "L4", "Untrusted interception", "host.example", "CRITICAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output is missing %q", want)
		}
	}
}

func TestWrapText(t *testing.T) {
	lines := wrapText("the quick brown fox jumps over the lazy dog", 20)
	if len(lines) < 2 {
		t.Fatalf("wrapText did not wrap: %v", lines)
	}
	for _, l := range lines {
		if len(l) > 20 {
			t.Errorf("line exceeds width: %q", l)
		}
	}
	if got := wrapText("   ", 20); got != nil {
		t.Errorf("wrapText(blank) = %v, want nil", got)
	}
}

func TestScoreBarBounds(t *testing.T) {
	for _, score := range []int{-10, 0, 50, 100, 250} {
		bar := scoreBar(score)
		if n := len([]rune(bar)); n != 24 {
			t.Errorf("scoreBar(%d) has %d runes, want 24", score, n)
		}
	}
}
