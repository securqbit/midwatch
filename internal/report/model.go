// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package report holds the result model shared by every midwatch check module,
// plus the terminal and JSON renderers.
//
// A run produces a Report containing one Module per check family. A Module
// carries an optional interception Level (the 0-4 ladder), zero or more
// Sections of observed evidence, and zero or more Findings. Renderers only
// ever consume this model, so adding a check never means touching output code.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < SevInfo || int(s) >= len(severityNames) {
		return "info"
	}
	return severityNames[s]
}

// MarshalJSON emits the lowercase name rather than the ordinal.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity maps a name to a Severity. It is used by --fail-on.
func ParseSeverity(s string) (Severity, bool) {
	for i, n := range severityNames {
		if strings.EqualFold(n, s) {
			return Severity(i), true
		}
	}
	return SevInfo, false
}

// Status is the per-row verdict used for evidence tables.
type Status int

const (
	StatusOK Status = iota
	StatusInfo
	StatusWarn
	StatusBad
	StatusSkip
)

var statusNames = [...]string{"ok", "info", "warn", "bad", "skip"}

func (s Status) String() string {
	if s < StatusOK || int(s) >= len(statusNames) {
		return "info"
	}
	return statusNames[s]
}

// MarshalJSON emits the lowercase name rather than the ordinal.
func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Row is a single observation inside a Section.
type Row struct {
	Status Status `json:"status"`
	Label  string `json:"label"`
	Value  string `json:"value,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Section groups related observations under a heading.
type Section struct {
	Title string `json:"title"`
	Rows  []Row  `json:"rows"`
}

// Finding is something the operator should act on.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
	Evidence []string `json:"evidence,omitempty"`

	// Kind overrides the module's kind for scoring and for the verdict. Empty
	// means the module's own kind, which is almost always right.
	//
	// It exists because one module can honestly observe two different things.
	// The comms module measures censorship, but while establishing that Signal
	// is reachable it may find Signal answered by a forged certificate — and
	// that is interception, scored and described as interception, whatever the
	// module was looking for when it tripped over it.
	Kind Kind `json:"kind,omitempty"`
}

// kindOr resolves the finding's effective kind against its module's.
func (f Finding) kindOr(module Kind) Kind {
	if f.Kind == "" {
		return module
	}
	return f.Kind
}

// Level is a module's position on the 0-4 interception ladder.
type Level struct {
	Score   int    `json:"score"`
	Code    string `json:"code"`
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

// Kind separates the three different things a module can measure. All of them
// produce levels and findings, but they are not the same claim about a network
// and the summary must not conflate them.
//
//   - KindInterception: somebody is reading or rewriting your traffic. An
//     attack on confidentiality.
//   - KindCensorship: somebody is deciding who you are permitted to reach. An
//     attack on your ability to communicate at all. A network that blocks
//     Signal has not made a bandwidth decision; it has taken a conversation
//     away from you, and a tool that files that under "policy" alongside a
//     closed SMTP port is burying the more serious of the two.
//   - KindPosture: policy that constrains you without doing either. A firewall
//     that permits only 80 and 443 is a choice somebody made, and reporting it
//     with the weight of an attack would teach the reader to ignore both.
//
// Interception and censorship both deduct from the score and both speak in the
// verdict. Posture does neither, though it is still reported in full and still
// visible to --fail-on.
type Kind string

const (
	KindInterception Kind = "interception"
	KindCensorship   Kind = "censorship"
	KindPosture      Kind = "posture"
)

// Module is the result of one check family (tls, dns, http, ...).
type Module struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Kind       Kind      `json:"kind"`
	Level      *Level    `json:"level,omitempty"`
	Sections   []Section `json:"sections,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
	Errors     []string  `json:"errors,omitempty"`
	DurationMS int64     `json:"duration_ms"`

	started time.Time
}

// NewModule starts a module and its timer.
func NewModule(id, title string, kind Kind) *Module {
	return &Module{ID: id, Title: title, Kind: kind, started: time.Now()}
}

// Done stops the module timer.
func (m *Module) Done() {
	if !m.started.IsZero() {
		m.DurationMS = time.Since(m.started).Milliseconds()
	}
}

// section returns the index of the named section, creating it if needed.
//
// It deliberately returns an index rather than a *Section. A pointer into
// m.Sections is invalidated by the next append, so a caller that held one
// across two calls would silently write rows into an orphaned array. An index
// stays correct because sections are only ever appended.
func (m *Module) section(title string) int {
	for i := range m.Sections {
		if m.Sections[i].Title == title {
			return i
		}
	}
	m.Sections = append(m.Sections, Section{Title: title})
	return len(m.Sections) - 1
}

// Row appends an observation to the named section, creating it on first use.
func (m *Module) Row(section string, st Status, label, value, note string) {
	i := m.section(section)
	m.Sections[i].Rows = append(m.Sections[i].Rows,
		Row{Status: st, Label: label, Value: value, Note: note})
}

// Add records a finding of the module's own kind.
func (m *Module) Add(id, title string, sev Severity, detail string, evidence ...string) {
	m.Findings = append(m.Findings, Finding{
		ID: id, Title: title, Severity: sev, Detail: detail, Evidence: evidence,
	})
}

// AddOfKind records a finding that measures something other than what its
// module was built to measure. See Finding.Kind.
func (m *Module) AddOfKind(k Kind, id, title string, sev Severity, detail string, evidence ...string) {
	m.Findings = append(m.Findings, Finding{
		ID: id, Title: title, Severity: sev, Detail: detail, Evidence: evidence, Kind: k,
	})
}

// Fail records a module-level error (a check that could not run).
func (m *Module) Fail(format string, args ...any) {
	m.Errors = append(m.Errors, fmt.Sprintf(format, args...))
}

// SetLevel assigns the interception level.
func (m *Module) SetLevel(score int, code, name, summary string) {
	m.Level = &Level{Score: score, Code: code, Name: name, Summary: summary}
}

// MaxSeverity returns the worst severity recorded, and whether any exist.
func (m *Module) MaxSeverity() (Severity, bool) {
	worst, ok := SevInfo, false
	for _, f := range m.Findings {
		if !ok || f.Severity > worst {
			worst, ok = f.Severity, true
		}
	}
	return worst, ok
}

// SortFindings orders findings most severe first, stable by ID within a rank.
func (m *Module) SortFindings() {
	sort.SliceStable(m.Findings, func(i, j int) bool {
		return m.Findings[i].Severity > m.Findings[j].Severity
	})
}

// Report is a complete midwatch run.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Platform   string    `json:"platform"`
	Modules    []*Module `json:"modules"`
	Score      int       `json:"score"`
	Verdict    string    `json:"verdict"`
}

// Add appends a finished module.
func (r *Report) Add(m *Module) {
	m.Done()
	m.SortFindings()
	r.Modules = append(r.Modules, m)
}

// MaxSeverity returns the worst severity across all modules.
func (r *Report) MaxSeverity() (Severity, bool) {
	worst, ok := SevInfo, false
	for _, m := range r.Modules {
		if s, has := m.MaxSeverity(); has && (!ok || s > worst) {
			worst, ok = s, true
		}
	}
	return worst, ok
}

// MaxLevel returns the highest level reached by any module.
func (r *Report) MaxLevel() int {
	max := 0
	for _, m := range r.Modules {
		if m.Level != nil && m.Level.Score > max {
			max = m.Level.Score
		}
	}
	return max
}

// MaxInterceptionLevel returns the highest level among modules that measure
// interception, ignoring posture modules such as egress policy.
func (r *Report) MaxInterceptionLevel() int {
	max := 0
	for _, m := range r.Modules {
		if m.Kind == KindInterception && m.Level != nil && m.Level.Score > max {
			max = m.Level.Score
		}
	}
	return max
}

// MaxSeverityOfKind returns the worst severity among findings of one kind,
// resolved per finding rather than per module.
func (r *Report) MaxSeverityOfKind(k Kind) (Severity, bool) {
	worst, ok := SevInfo, false
	for _, m := range r.Modules {
		for _, f := range m.Findings {
			if f.kindOr(m.Kind) != k {
				continue
			}
			if !ok || f.Severity > worst {
				worst, ok = f.Severity, true
			}
		}
	}
	return worst, ok
}

// MaxInterceptionSeverity returns the worst severity among findings that
// describe interception, ignoring posture findings such as egress policy.
func (r *Report) MaxInterceptionSeverity() (Severity, bool) {
	return r.MaxSeverityOfKind(KindInterception)
}

// MaxCensorshipSeverity returns the worst severity among findings that
// describe restrictions on who this network lets you contact.
func (r *Report) MaxCensorshipSeverity() (Severity, bool) {
	return r.MaxSeverityOfKind(KindCensorship)
}

// hasKind reports whether any module measured the given kind, so the summary
// can tell "nothing was blocked" from "blocking was never checked".
func (r *Report) hasKind(k Kind) bool {
	for _, m := range r.Modules {
		if m.Kind == k {
			return true
		}
	}
	return false
}

// severityCost is what one finding deducts from a perfect 100. It is
// deliberately steep at the top so a single confirmed event cannot be averaged
// away by clean checks.
func severityCost(s Severity) int {
	switch s {
	case SevCritical:
		return 34
	case SevHigh:
		return 18
	case SevMedium:
		return 8
	case SevLow:
		return 3
	}
	return 0
}

// Finalize computes the trust score and verdict.
//
// Two kinds of finding deduct from a perfect 100: interception, which attacks
// what your traffic says, and censorship, which attacks whether you can hold
// the conversation at all. Both are things done to the user, so both are
// counted and both are named in the verdict.
//
// Posture findings — egress policy and time sources — are excluded from the
// score and the verdict, for the same reason their levels already are: a
// restrictive firewall is a choice, and a score that mixes it in tells the user
// a filtered network is a compromised one. They are still rendered in full, and
// --fail-on still sees them through MaxSeverity, so a run can be gated on
// posture when that is what the operator wants.
//
// The two scoring axes are kept apart while the sentence is chosen, because
// their thresholds mean different things. Deductions for blocked messengers
// must never push the run into "traffic is being decrypted", which would be a
// claim midwatch has no evidence for.
func (r *Report) Finalize(started time.Time) {
	r.DurationMS = time.Since(started).Milliseconds()

	interceptCost, censorCost := 0, 0
	for _, m := range r.Modules {
		for _, f := range m.Findings {
			switch f.kindOr(m.Kind) {
			case KindInterception:
				interceptCost += severityCost(f.Severity)
			case KindCensorship:
				censorCost += severityCost(f.Severity)
			}
		}
	}
	r.Score = max(0, 100-interceptCost-censorCost)

	label, detail := r.interceptionVerdict(100 - interceptCost)
	censorLabel, censorDetail := r.censorshipVerdict()

	switch {
	case label != "" && censorLabel != "":
		r.Verdict = label + " and " + strings.ToLower(censorLabel) + " — " + detail + ", and " + censorDetail
	case label != "":
		r.Verdict = label + " — " + detail
	case censorLabel != "":
		r.Verdict = censorLabel + " — " + censorDetail
	case r.hasKind(KindCensorship):
		r.Verdict = "Clean — no interception or blocking detected on this network"
	default:
		r.Verdict = "Clean — no interception detected on this network"
	}
}

// interceptionVerdict describes what is being done to the traffic itself,
// scored on interception findings alone. An empty label means nothing was
// found.
func (r *Report) interceptionVerdict(score int) (label, detail string) {
	worst, has := r.MaxInterceptionSeverity()
	switch level := r.MaxInterceptionLevel(); {
	// A critical interception finding is a confirmed forgery, and says so even
	// when it surfaced in a module whose own ladder measures something else.
	case level >= 3 || score < 40 || (has && worst >= SevCritical):
		return "Compromised", "traffic is being decrypted or rewritten in transit"
	case level == 2 || score < 65:
		return "Tampered", "a middlebox is selectively intercepting traffic"
	// Never call a run clean while something worth acting on is outstanding,
	// even if the arithmetic still looks comfortable.
	case level == 1 || score < 85 || (has && worst >= SevMedium):
		return "Observed", "traffic is intact but metadata is visible and constrained"
	}
	return "", ""
}

// censorshipVerdict describes what is being done to the user's ability to reach
// other people. It reads finding severity rather than a module level, because
// the comms ladder's top rung measures interception and is already spoken for
// by interceptionVerdict.
func (r *Report) censorshipVerdict() (label, detail string) {
	worst, has := r.MaxCensorshipSeverity()
	if !has {
		return "", ""
	}
	switch {
	case worst >= SevHigh:
		return "Censored", "this network decides who you are able to contact"
	case worst >= SevMedium:
		return "Restricted", "this network limits how you are able to communicate"
	}
	return "", ""
}
