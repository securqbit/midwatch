// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package cli wires the check modules to a command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/securqbit/midwatch/internal/checks/commscheck"
	"github.com/securqbit/midwatch/internal/checks/dnscheck"
	"github.com/securqbit/midwatch/internal/checks/egresscheck"
	"github.com/securqbit/midwatch/internal/checks/httpcheck"
	"github.com/securqbit/midwatch/internal/checks/timecheck"
	"github.com/securqbit/midwatch/internal/checks/tlscheck"
	"github.com/securqbit/midwatch/internal/report"
	"github.com/securqbit/midwatch/internal/version"
)

// Exit codes. They are part of the interface: CI and monitoring depend on
// them, so they are documented in the README and must not be reshuffled.
const (
	ExitClean   = 0 // nothing met the failure threshold
	ExitFinding = 1 // a finding at or above --fail-on was reported
	ExitError   = 2 // midwatch could not run the requested checks
)

// allModules is the set a bare `midwatch scan` runs, in the order it runs them.
// The usage text and the dispatch in runModule are both derived from it.
var allModules = []string{"tls", "dns", "http", "egress", "comms", "time"}

type options struct {
	json     bool
	noColor  bool
	forceCol bool
	quiet    bool
	deep     bool
	timeout  time.Duration
	failOn   string
	targets  string
	modules  []string
}

// Run parses arguments and executes. It returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage(os.Stdout)
		return ExitError
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return ExitClean
	case "-v", "--version", "version":
		fmt.Printf("midwatch %s\n", version.String())
		fmt.Printf("%s/%s, %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
		return ExitClean
	}

	var mods []string
	switch cmd {
	case "scan":
		mods = allModules
	case "tls", "dns", "http", "egress", "comms", "time":
		mods = []string{cmd}
	default:
		if strings.HasPrefix(cmd, "-") {
			// Bare flags mean a full scan, so `midwatch --json` behaves.
			mods = allModules
			rest = args
		} else {
			fmt.Fprintf(os.Stderr, "midwatch: unknown command %q\n\n", cmd)
			usage(os.Stderr)
			return ExitError
		}
	}

	opts, err := parseFlags(cmd, rest)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		fmt.Fprintf(os.Stderr, "midwatch: %v\n", err)
		return ExitError
	}
	opts.modules = mods
	return execute(opts)
}

func parseFlags(name string, args []string) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("midwatch "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&o.json, "json", false, "emit the full report as JSON")
	fs.BoolVar(&o.noColor, "no-color", false, "disable ANSI colour")
	fs.BoolVar(&o.forceCol, "color", false, "force ANSI colour even when not a terminal")
	fs.BoolVar(&o.quiet, "quiet", false, "print only the verdict and any findings")
	fs.BoolVar(&o.deep, "deep", false, "run additional, slower and noisier probes")
	fs.DurationVar(&o.timeout, "timeout", 8*time.Second, "per-probe timeout")
	fs.StringVar(&o.failOn, "fail-on", "high",
		"exit non-zero when a finding of this severity or worse is reported (info|low|medium|high|critical|never)")
	fs.StringVar(&o.targets, "targets", "",
		"comma separated host:port list to test instead of the built-in TLS endpoints")
	fs.Usage = func() { usage(os.Stderr) }
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if o.timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	if o.failOn != "never" {
		if _, ok := report.ParseSeverity(o.failOn); !ok {
			return nil, fmt.Errorf("invalid --fail-on value %q", o.failOn)
		}
	}
	return o, nil
}

func execute(o *options) int {
	// Ctrl-C cancels probes in flight rather than killing the process mid
	// write, so partial results still render.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pal := report.Palette{On: report.ColorEnabled(o.forceCol, o.noColor || o.json)}
	started := time.Now()
	rep := &report.Report{
		Tool:      "midwatch",
		Version:   version.Short(),
		StartedAt: started,
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}

	out := os.Stdout
	streaming := !o.json && !o.quiet
	if streaming {
		report.Header(out, pal, rep)
	}

	// Modules are independent, so they all start at once. Rendering still
	// happens strictly in the order the modules were requested: a module is
	// printed only once it and everything before it has finished, which keeps
	// the streaming output identical to what a sequential run would produce
	// while costing the slowest module rather than their sum.
	done := make([]chan struct{}, len(o.modules))
	mods := make([]*report.Module, len(o.modules))
	for i := range o.modules {
		done[i] = make(chan struct{})
	}
	for i, id := range o.modules {
		go func(i int, id string) {
			defer close(done[i])
			if ctx.Err() != nil {
				return
			}
			mods[i] = runModule(ctx, id, o)
		}(i, id)
	}
	for i := range o.modules {
		<-done[i]
		m := mods[i]
		if m == nil {
			continue
		}
		rep.Add(m)
		if streaming {
			report.RenderModule(out, pal, m)
		}
	}

	rep.Finalize(started)

	switch {
	case o.json:
		if err := report.JSON(out, rep); err != nil {
			fmt.Fprintf(os.Stderr, "midwatch: %v\n", err)
			return ExitError
		}
	case o.quiet:
		renderQuiet(out, pal, rep)
	default:
		report.Summary(out, pal, rep)
	}

	if ctx.Err() != nil {
		return ExitError
	}
	return exitCode(rep, o.failOn)
}

func runModule(ctx context.Context, id string, o *options) *report.Module {
	switch id {
	case "tls":
		return tlscheck.Run(ctx, tlscheck.Options{
			Targets: splitTargets(o.targets),
			Timeout: o.timeout,
			Deep:    o.deep,
		})
	case "dns":
		return dnscheck.Run(ctx, dnscheck.Options{Timeout: o.timeout, Deep: o.deep})
	case "http":
		return httpcheck.Run(ctx, httpcheck.Options{Timeout: o.timeout, Deep: o.deep})
	case "egress":
		return egresscheck.Run(ctx, egresscheck.Options{Timeout: o.timeout, Deep: o.deep})
	case "comms":
		return commscheck.Run(ctx, commscheck.Options{Timeout: o.timeout, Deep: o.deep})
	case "time":
		return timecheck.Run(ctx, timecheck.Options{Timeout: o.timeout, Deep: o.deep})
	}
	return nil
}

func splitTargets(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.Contains(t, ":") {
			t += ":443"
		}
		out = append(out, t)
	}
	return out
}

func renderQuiet(w io.Writer, p report.Palette, r *report.Report) {
	for _, m := range r.Modules {
		if m.Level != nil {
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.ID, m.Level.Code, m.Level.Name)
		}
		for _, f := range m.Findings {
			fmt.Fprintf(w, "%s\t%s\t%s\n", strings.ToUpper(f.Severity.String()), f.ID, f.Title)
		}
	}
	fmt.Fprintf(w, "%d/100\t%s\n", r.Score, p.Bold(r.Verdict))
}

func exitCode(r *report.Report, failOn string) int {
	if failOn == "never" {
		return ExitClean
	}
	threshold, ok := report.ParseSeverity(failOn)
	if !ok {
		return ExitClean
	}
	if worst, has := r.MaxSeverity(); has && worst >= threshold {
		return ExitFinding
	}
	return ExitClean
}

const usageText = `midwatch — find out who is watching your network

USAGE
  midwatch <command> [flags]

COMMANDS
  scan      run every check and print an overall verdict (the usual choice)
  tls       detect TLS interception and grade how deep it goes
  dns       detect DNS redirection, hijacking and answer forgery
  http      detect transparent proxies, captive portals and downgrades
  egress    map which ports and protocols this network permits
  comms     detect blocking of messengers, calls and conferencing
  time      verify the clock and the NTP source behind it
  version   print build information

FLAGS
  --json              emit the full report as JSON
  --quiet             print only levels, findings and the verdict
  --deep              run additional, slower and noisier probes
  --timeout DURATION  per-probe timeout (default 8s)
  --targets LIST      comma separated host:port list for the TLS check
  --fail-on LEVEL     exit 1 at this severity or worse: info, low, medium,
                      high (default), critical, or never
  --color/--no-color  force or suppress ANSI colour

EXIT CODES
  0  clean, or nothing met the --fail-on threshold
  1  a finding at or above the threshold was reported
  2  midwatch could not complete the requested checks

EXAMPLES
  midwatch scan
  midwatch tls --deep --targets bank.example.com:443
  midwatch scan --json > network-report.json
  midwatch scan --quiet --fail-on medium   # for CI and monitoring

midwatch only reads the network. It sends ordinary handshakes and lookups to
public endpoints, stores nothing and reports nothing home.
`

func usage(w io.Writer) { fmt.Fprint(w, usageText) }
