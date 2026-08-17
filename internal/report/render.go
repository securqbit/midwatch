// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Palette renders ANSI styling, or nothing at all when colour is disabled.
type Palette struct{ On bool }

func (p Palette) wrap(code, s string) string {
	if !p.On || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Palette) Bold(s string) string    { return p.wrap("1", s) }
func (p Palette) Dim(s string) string     { return p.wrap("2", s) }
func (p Palette) Red(s string) string     { return p.wrap("31", s) }
func (p Palette) Green(s string) string   { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string  { return p.wrap("33", s) }
func (p Palette) Blue(s string) string    { return p.wrap("34", s) }
func (p Palette) Magenta(s string) string { return p.wrap("35", s) }
func (p Palette) Cyan(s string) string    { return p.wrap("36", s) }
func (p Palette) Gray(s string) string    { return p.wrap("90", s) }

// ColorEnabled decides whether to emit ANSI escapes, honouring NO_COLOR,
// FORCE_COLOR, TERM=dumb and whether stdout is a terminal.
func ColorEnabled(force, disable bool) bool {
	if disable {
		return false
	}
	if force {
		return true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (p Palette) statusGlyph(s Status) string {
	switch s {
	case StatusOK:
		return p.Green("ok  ")
	case StatusWarn:
		return p.Yellow("warn")
	case StatusBad:
		return p.Red("bad ")
	case StatusSkip:
		return p.Gray("skip")
	default:
		return p.Blue("info")
	}
}

func (p Palette) severityTag(s Severity) string {
	switch s {
	case SevCritical:
		return p.Red(p.Bold("CRITICAL"))
	case SevHigh:
		return p.Red("HIGH    ")
	case SevMedium:
		return p.Yellow("MEDIUM  ")
	case SevLow:
		return p.Cyan("LOW     ")
	default:
		return p.Gray("INFO    ")
	}
}

// levelColor maps the 0-4 ladder onto a colour ramp.
func (p Palette) levelColor(score int, s string) string {
	switch {
	case score >= 4:
		return p.Red(p.Bold(s))
	case score == 3:
		return p.Red(s)
	case score == 2:
		return p.Yellow(s)
	case score == 1:
		return p.Cyan(s)
	default:
		return p.Green(s)
	}
}

const ruleWidth = 68

// Header prints the run banner.
func Header(w io.Writer, p Palette, r *Report) {
	fmt.Fprintf(w, "\n  %s %s  %s\n",
		p.Bold("midwatch"),
		p.Dim(r.Version),
		p.Gray(r.Platform+"  ·  "+r.StartedAt.Format("2006-01-02 15:04:05 MST")))
	fmt.Fprintln(w)
}

// RenderModule prints one finished module. Used both for streaming output
// during a scan and for single-module commands.
func RenderModule(w io.Writer, p Palette, m *Module) {
	title := strings.ToUpper(m.Title)
	pad := ruleWidth - len(title) - 4
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(w, "  %s %s %s\n", p.Gray("──"), p.Bold(title), p.Gray(strings.Repeat("─", pad)))

	if m.Level != nil {
		badge := fmt.Sprintf(" %s ", m.Level.Code)
		fmt.Fprintf(w, "  %s  %s\n", p.levelColor(m.Level.Score, badge), p.Bold(m.Level.Name))
		for _, line := range wrapText(m.Level.Summary, ruleWidth-8) {
			fmt.Fprintf(w, "        %s\n", p.Dim(line))
		}
	}

	for _, s := range m.Sections {
		if len(s.Rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  %s\n", p.Gray(s.Title))
		width := 0
		for _, row := range s.Rows {
			if len(row.Label) > width {
				width = len(row.Label)
			}
		}
		if width > 30 {
			width = 30
		}
		for _, row := range s.Rows {
			label := row.Label
			if len(label) < width {
				label += strings.Repeat(" ", width-len(label))
			}
			line := fmt.Sprintf("  %s  %s", p.statusGlyph(row.Status), label)
			if row.Value != "" {
				line += "  " + row.Value
			}
			if row.Note != "" {
				line += "  " + p.Dim(row.Note)
			}
			fmt.Fprintln(w, line)
		}
	}

	if len(m.Findings) > 0 {
		fmt.Fprintf(w, "\n  %s\n", p.Gray("findings"))
		for _, f := range m.Findings {
			fmt.Fprintf(w, "  %s  %s  %s\n", p.severityTag(f.Severity), p.Bold(f.Title), p.Gray(f.ID))
			for _, line := range wrapText(f.Detail, ruleWidth-12) {
				fmt.Fprintf(w, "            %s\n", line)
			}
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "            %s %s\n", p.Gray("·"), p.Dim(e))
			}
		}
	}

	for _, e := range m.Errors {
		fmt.Fprintf(w, "  %s  %s\n", p.Gray("note"), p.Dim(e))
	}
	fmt.Fprintln(w)
}

// Summary prints the closing verdict block.
func Summary(w io.Writer, p Palette, r *Report) {
	fmt.Fprintf(w, "  %s %s %s\n", p.Gray("──"), p.Bold("VERDICT"), p.Gray(strings.Repeat("─", ruleWidth-13)))

	bar := scoreBar(r.Score)
	col := p.Green
	switch {
	case r.Score < 40:
		col = p.Red
	case r.Score < 65:
		col = p.Yellow
	case r.Score < 85:
		col = p.Cyan
	}
	fmt.Fprintf(w, "  %s  %s\n", col(bar), col(p.Bold(fmt.Sprintf("%d/100", r.Score))))
	fmt.Fprintf(w, "  %s\n", p.Bold(r.Verdict))

	counts := map[Severity]int{}
	for _, m := range r.Modules {
		for _, f := range m.Findings {
			counts[f.Severity]++
		}
	}
	var parts []string
	for _, s := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no findings")
	}
	fmt.Fprintf(w, "  %s\n", p.Dim(strings.Join(parts, "  ·  ")))

	var levels []string
	for _, m := range r.Modules {
		if m.Level != nil {
			levels = append(levels, fmt.Sprintf("%s %s", m.ID, p.levelColor(m.Level.Score, m.Level.Code)))
		}
	}
	if len(levels) > 0 {
		fmt.Fprintf(w, "  %s\n", p.Dim(strings.Join(levels, "  ")))
	}
	fmt.Fprintf(w, "  %s\n\n", p.Gray(fmt.Sprintf("completed in %.1fs", float64(r.DurationMS)/1000)))
}

func scoreBar(score int) string {
	const width = 24
	filled := score * width / 100
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// JSON writes the machine readable form of a report.
func JSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func wrapText(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if width < 20 {
		width = 20
	}
	var lines []string
	var cur strings.Builder
	for _, word := range strings.Fields(s) {
		if cur.Len() > 0 && cur.Len()+1+len(word) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(word)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
