// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/securqbit/midwatch/internal/report"
)

func TestSplitTargets(t *testing.T) {
	got := splitTargets("bank.example.com, intranet.corp:8443 ,")
	want := []string{"bank.example.com:443", "intranet.corp:8443"}
	if len(got) != len(want) {
		t.Fatalf("splitTargets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i], want[i])
		}
	}
	if splitTargets("") != nil {
		t.Error("an empty --targets should fall back to the built-in list")
	}
	if splitTargets("   ") != nil {
		t.Error("a blank --targets should fall back to the built-in list")
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	o, err := parseFlags("scan", nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if o.timeout != 8*time.Second {
		t.Errorf("default timeout = %v, want 8s", o.timeout)
	}
	if o.failOn != "high" {
		t.Errorf("default --fail-on = %q, want high", o.failOn)
	}
	if o.json || o.quiet || o.deep {
		t.Error("output modes should default to off")
	}
}

func TestParseFlagsRejectsBadInput(t *testing.T) {
	if _, err := parseFlags("scan", []string{"--fail-on", "catastrophic"}); err == nil {
		t.Error("parseFlags accepted an unknown severity")
	}
	if _, err := parseFlags("scan", []string{"--timeout", "0s"}); err == nil {
		t.Error("parseFlags accepted a zero timeout")
	}
	if _, err := parseFlags("scan", []string{"--timeout", "-5s"}); err == nil {
		t.Error("parseFlags accepted a negative timeout")
	}
	if _, err := parseFlags("scan", []string{"--fail-on", "never"}); err != nil {
		t.Errorf("parseFlags rejected the documented 'never' value: %v", err)
	}
}

func buildReport(sev report.Severity, withFinding bool) *report.Report {
	r := &report.Report{Tool: "midwatch"}
	m := report.NewModule("tls", "TLS", report.KindInterception)
	if withFinding {
		m.Add("tls.test", "finding", sev, "")
	}
	r.Add(m)
	r.Finalize(time.Now())
	return r
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name    string
		sev     report.Severity
		present bool
		failOn  string
		want    int
	}{
		{"clean run", report.SevInfo, false, "high", ExitClean},
		{"below threshold", report.SevMedium, true, "high", ExitClean},
		{"at threshold", report.SevHigh, true, "high", ExitFinding},
		{"above threshold", report.SevCritical, true, "high", ExitFinding},
		{"strict threshold", report.SevLow, true, "low", ExitFinding},
		{"never fails", report.SevCritical, true, "never", ExitClean},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := exitCode(buildReport(tc.sev, tc.present), tc.failOn)
			if got != tc.want {
				t.Errorf("exitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunVersionAndHelp(t *testing.T) {
	if got := Run([]string{"--version"}); got != ExitClean {
		t.Errorf("--version exited %d, want %d", got, ExitClean)
	}
	if got := Run([]string{"--help"}); got != ExitClean {
		t.Errorf("--help exited %d, want %d", got, ExitClean)
	}
	if got := Run([]string{"nonsense"}); got != ExitError {
		t.Errorf("unknown command exited %d, want %d", got, ExitError)
	}
	if got := Run(nil); got != ExitError {
		t.Errorf("no arguments exited %d, want %d", got, ExitError)
	}
}

func TestUsageDocumentsEveryCommand(t *testing.T) {
	var sb strings.Builder
	usage(&sb)
	text := sb.String()
	for _, cmd := range []string{"scan", "tls", "dns", "http", "egress", "comms", "time", "version"} {
		if !strings.Contains(text, cmd) {
			t.Errorf("usage text does not mention the %q command", cmd)
		}
	}
	for _, flag := range []string{"--json", "--quiet", "--deep", "--timeout", "--targets", "--fail-on"} {
		if !strings.Contains(text, flag) {
			t.Errorf("usage text does not mention %s", flag)
		}
	}
}

func TestScanCoversEveryAdvertisedModule(t *testing.T) {
	// A scan must run everything the help text promises. If a module is added
	// to one list and not the other, a scan would silently skip part of what
	// it claims to check.
	var sb strings.Builder
	usage(&sb)
	text := sb.String()
	for _, id := range allModules {
		if !strings.Contains(text, id) {
			t.Errorf("module %q runs in a scan but is undocumented", id)
		}
	}
}

func TestRunModuleRejectsUnknownID(t *testing.T) {
	if m := runModule(context.Background(), "not-a-module", &options{timeout: time.Second}); m != nil {
		t.Errorf("runModule returned %v for an unknown id, want nil", m)
	}
}
