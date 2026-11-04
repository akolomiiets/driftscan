// Command driftscan detects Terraform/OpenTofu drift across many Roots and reports only what changed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/akolomiiets/driftscan/internal/advise"
	"github.com/akolomiiets/driftscan/internal/cloudtrail"
	"github.com/akolomiiets/driftscan/internal/compare"
	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/enrich"
	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/output"
	"github.com/akolomiiets/driftscan/internal/runner"
	"github.com/akolomiiets/driftscan/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

const usage = `driftscan detects Terraform/OpenTofu drift and reports only what changed.

Usage:
  driftscan scan      [flags]              plan every Root, compare with the Baseline, emit outputs
  driftscan report    [flags] RAW.json...  merge raw shard Reports, compare, emit outputs
  driftscan enrich    [flags] RAW.json     add owners (and with -cloudtrail, who changed what), in place
  driftscan advise    [flags] RAW.json     add AI triage notes, in place (experimental)
  driftscan unmanaged [flags]              count AWS resources that no state manages (experimental)
  driftscan version

Run "driftscan <command> -h" for flags.
Exit codes: 0 ok, 1 Findings at or above -fail-on, 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "scan":
		return cmdScan(ctx, args[1:], stdout, stderr)
	case "report":
		return cmdReport(ctx, args[1:], stdout, stderr)
	case "advise":
		return cmdAdvise(ctx, args[1:], stdout, stderr, newBedrock)
	case "enrich":
		return cmdEnrich(ctx, args[1:], stdout, stderr)
	case "unmanaged":
		return cmdUnmanaged(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "driftscan", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return exitError
}

// emitFlags are shared by scan and report: everything after the raw Report exists.
type emitFlags struct {
	configPath string
	baseline   string
	out        string
	markdown   string
	sarif      string
	html       string
	slack      bool
	otlp       bool
	digest     bool
	failOn     string
	runURL     string
	dir        string

	annotations     string
	annotatePending bool
}

func (e *emitFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&e.configPath, "config", "", "config file (default <dir>/drift.yaml if present)")
	fs.StringVar(&e.baseline, "baseline", "", "previous Report to compare with; missing file means first Scan")
	fs.StringVar(&e.out, "out", "driftscan-report.json", "where to write the compared Report (the next Baseline)")
	fs.StringVar(&e.markdown, "markdown", "auto", `Markdown summary path; "auto" appends to $GITHUB_STEP_SUMMARY when set; "" disables`)
	fs.StringVar(&e.sarif, "sarif", "", "SARIF 2.1.0 output path")
	fs.StringVar(&e.html, "html", "", "self-contained HTML report path")
	fs.BoolVar(&e.slack, "slack", false, "post alerts to the Slack webhook named by slack.webhook_env")
	fs.BoolVar(&e.otlp, "otlp", false, "send metrics to the OTLP/HTTP endpoint named by otlp.endpoint_env")
	fs.BoolVar(&e.digest, "digest", false, "also alert on persisting Findings seen at least noise.digest_after times")
	fs.StringVar(&e.failOn, "fail-on", "high", `exit 1 when an active Finding has at least this severity; "none" disables`)
	fs.StringVar(&e.annotations, "annotations", "auto", `GitHub annotations on stdout: auto (on when GITHUB_ACTIONS is "true"), on or off`)
	fs.BoolVar(&e.annotatePending, "annotate-pending", true, "include pending changes in GitHub annotations")
	fs.StringVar(&e.runURL, "run-url", githubRunURL(), "link added to Slack messages")
}

func githubRunURL() string {
	s, r, id := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if s == "" || r == "" || id == "" {
		return ""
	}
	return s + "/" + r + "/actions/runs/" + id
}

// sourceFromEnv builds the link base for source locations from the GitHub Actions environment.
// When the scan directory cannot be placed inside GITHUB_WORKSPACE no link is built at all, so a
// link never points to a wrong path.
func sourceFromEnv(dir string) output.Source {
	var src output.Source
	server, repo, sha := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_SHA")
	if server != "" && repo != "" && sha != "" {
		src.BlobURL = strings.TrimRight(server, "/") + "/" + repo + "/blob/" + sha
	}
	ws := os.Getenv("GITHUB_WORKSPACE")
	if ws == "" {
		return src
	}
	absWs, absDir := resolvePath(ws), resolvePath(dir)
	rel, err := filepath.Rel(absWs, absDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return output.Source{}
	}
	if rel = filepath.ToSlash(rel); rel != "." {
		src.Prefix = rel
	}
	return src
}

// resolvePath returns the absolute path with symlinks resolved, or just the absolute path if
// they cannot be resolved.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

func loadConfig(path, dir string) (config.Config, error) {
	if path != "" {
		return config.Load(path, true)
	}
	return config.Load(filepath.Join(dir, "drift.yaml"), false)
}

func cmdScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", ".", "directory to scan; Root paths and SARIF locations are relative to it")
	shard := fs.String("shard", "", "scan only shard i/n of the Roots, e.g. 2/4")
	rawOut := fs.String("raw-out", "", "write the raw (uncompared) Report here and stop; for shards")
	list := fs.Bool("list", false, "print the discovered Roots and exit")
	var e emitFlags
	e.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	e.dir = *dir
	modes, err := e.parseModes()
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}

	cfg, err := loadConfig(e.configPath, *dir)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	roots, err := discover.Roots(os.DirFS(*dir), cfg)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan: discover:", err)
		return exitError
	}
	shardI, shardN := 1, 1
	if *shard != "" {
		var err error
		if shardI, shardN, err = parseShard(*shard); err != nil {
			fmt.Fprintln(stderr, "driftscan:", err)
			return exitError
		}
		roots = discover.Shard(roots, shardI, shardN)
	}
	if *list {
		for _, r := range roots {
			fmt.Fprintln(stdout, r.Path)
		}
		return exitOK
	}
	fmt.Fprintf(stderr, "driftscan %s: scanning %d Roots with %s (concurrency %d)\n", version, len(roots), cfg.Binary, cfg.Concurrency)

	raw := scan.Run(ctx, cfg, roots, runner.Exec{Binary: cfg.Binary, Dir: *dir}, time.Now(), "driftscan "+version)
	if shardN > 1 {
		raw.Shard = fmt.Sprintf("%d/%d", shardI, shardN)
		raw.Partial = true
	}
	if *rawOut != "" {
		if err := writeReport(*rawOut, raw); err != nil {
			fmt.Fprintln(stderr, "driftscan:", err)
			return exitError
		}
		return exitOK
	}
	return emit(ctx, cfg, e, modes, raw, stdout, stderr)
}

func cmdReport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", ".", "directory the Reports were scanned from; source paths are relative to it")
	complete := fs.Bool("complete", false, "the given Reports cover every Root (e.g. one per environment), so Baseline Findings of Roots absent from them resolve; a shard split missing a shard, or a Partial Report, stays partial")
	var e emitFlags
	e.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	e.dir = *dir
	modes, err := e.parseModes()
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "driftscan report: give at least one raw Report")
		return exitError
	}
	cfg, err := loadConfig(e.configPath, *dir)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	var parts []finding.Report
	for _, p := range fs.Args() {
		r, err := readReport(p)
		if err != nil {
			fmt.Fprintln(stderr, "driftscan:", err)
			return exitError
		}
		parts = append(parts, r)
	}
	merged, why := merge(parts, *complete)
	switch why {
	case partialShards:
		fmt.Fprintln(stderr, "driftscan: shard Reports are incomplete; Findings of Roots not scanned stay unknown")
	case partialCoverage:
		fmt.Fprintln(stderr, "driftscan: merged Reports cannot prove full coverage; Baseline Findings of Roots absent from them stay unknown (pass -complete if these Reports cover every Root)")
	}
	if n := duplicateRoots(parts); n > 0 {
		fmt.Fprintf(stderr, "driftscan: %d Root path(s) appear in more than one Report; scan every environment from one common directory so Root paths stay distinct\n", n)
	}
	return emit(ctx, cfg, e, modes, merged, stdout, stderr)
}

// Why a merged Report is Partial; the empty value means complete.
const (
	partialNone     = ""
	partialShards   = "shards"
	partialCoverage = "coverage"
)

// merge joins Reports. Shards never share a Root, so findings are concatenated. The result is
// Partial when a part is Partial on its own or a shard split is incomplete (complete never
// overrides that; a repeated shard index also counts, which is what shards of several environments
// look like), or when several independent parts (unsharded Reports, or a whole shard split)
// are given without complete, since nothing proves they cover every Root.
func merge(parts []finding.Report, complete bool) (finding.Report, string) {
	out := finding.Report{Version: finding.ReportVersion, Tool: parts[0].Tool, StartedAt: parts[0].StartedAt}
	splits := map[int]map[int]bool{}
	units := 0
	broken := false
	for _, p := range parts {
		if p.Shard == "" {
			units++
			broken = broken || p.Partial
		} else if i, n, err := parseShard(p.Shard); err == nil {
			if splits[n] == nil {
				splits[n] = map[int]bool{}
			}
			if splits[n][i] {
				broken = true
			}
			splits[n][i] = true
		} else {
			broken = true
		}
		if p.StartedAt.Before(out.StartedAt) {
			out.StartedAt = p.StartedAt
		}
		out.Duration = max(out.Duration, p.Duration)
		out.Roots = append(out.Roots, p.Roots...)
		out.Findings = append(out.Findings, p.Findings...)
	}
	for n, set := range splits {
		broken = broken || len(set) != n
	}
	if len(splits) > 0 {
		units++
	}
	broken = broken || len(splits) > 1
	scan.Sort(out.Findings)
	switch {
	case broken:
		out.Partial = true
		return out, partialShards
	case units > 1 && !complete:
		out.Partial = true
		return out, partialCoverage
	}
	return out, partialNone
}

// duplicateRoots counts Root paths that appear in more than one part, which happens when parts
// were scanned from different directories.
func duplicateRoots(parts []finding.Report) int {
	owner := map[string]int{}
	dup := map[string]bool{}
	for i, p := range parts {
		for _, r := range p.Roots {
			if prev, ok := owner[r.Path]; ok && prev != i {
				dup[r.Path] = true
			}
			owner[r.Path] = i
		}
	}
	return len(dup)
}

// emitModes are the parsed values of -annotations and -fail-on.
type emitModes struct {
	annotate  bool
	failOff   bool
	threshold finding.Severity
}

// parseModes validates -annotations and -fail-on; scan and report call it before any real work.
func (e emitFlags) parseModes() (emitModes, error) {
	var m emitModes
	m.failOff = e.failOn == "none"
	if !m.failOff {
		var err error
		if m.threshold, err = finding.ParseSeverity(e.failOn); err != nil {
			return m, fmt.Errorf("-fail-on: %w", err)
		}
	}
	var err error
	if m.annotate, err = annotationsEnabled(e.annotations); err != nil {
		return m, fmt.Errorf("-annotations: %w", err)
	}
	return m, nil
}

func annotationsEnabled(mode string) (bool, error) {
	switch mode {
	case "on":
		return true, nil
	case "off":
		return false, nil
	case "auto":
		return os.Getenv("GITHUB_ACTIONS") == "true", nil
	}
	return false, fmt.Errorf("unknown value %q (want auto, on or off)", mode)
}

func emit(ctx context.Context, cfg config.Config, e emitFlags, modes emitModes, raw finding.Report, stdout, stderr io.Writer) int {
	var base *finding.Report
	if e.baseline != "" {
		b, err := readReport(e.baseline)
		switch {
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stderr, "driftscan: no Baseline at %s, treating this as the first Scan\n", e.baseline)
		case err != nil:
			fmt.Fprintln(stderr, "driftscan:", err)
			return exitError
		default:
			base = &b
		}
	}
	now := time.Now()
	rep := compare.Compare(base, raw, now)

	code := exitOK
	fail := func(what string, err error) {
		fmt.Fprintf(stderr, "driftscan: %s: %v\n", what, err)
		code = exitError
	}
	src := sourceFromEnv(e.dir)
	if path := markdownPath(e.markdown); path != "" {
		if err := appendMarkdown(path, rep, src); err != nil {
			fail("markdown", err)
		}
	} else if e.markdown == "auto" {
		fmt.Fprint(stdout, output.Markdown(rep, src, output.MarkdownBudget))
	}
	if modes.annotate {
		for _, l := range output.Annotations(rep, src, e.annotatePending) {
			fmt.Fprintln(stdout, l)
		}
	}
	if e.sarif != "" {
		b, err := output.SARIF(rep, version)
		if err == nil {
			err = os.WriteFile(e.sarif, b, 0o644)
		}
		if err != nil {
			fail("sarif", err)
		}
	}
	if e.html != "" {
		b, err := output.HTML(rep, src, now)
		if err == nil {
			err = os.WriteFile(e.html, b, 0o644)
		}
		if err != nil {
			fail("html", err)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if e.slack {
		webhook := os.Getenv(cfg.Slack.WebhookEnv)
		alerts := compare.Alerts(rep, compare.Options{Digest: e.digest, DigestAfter: cfg.Noise.DigestAfter, BrokenRootAfter: cfg.Noise.BrokenRootAfter})
		msgs := output.SlackMessages(rep, alerts, cfg.Slack.GroupBy, e.runURL)
		switch {
		case webhook == "":
			fail("slack", fmt.Errorf("%s is empty", cfg.Slack.WebhookEnv))
		case len(msgs) > 0:
			if err := output.PostSlack(ctx, client, webhook, msgs); err != nil {
				fail("slack", err)
			}
		}
	}
	if e.otlp {
		endpoint := os.Getenv(cfg.OTLP.EndpointEnv)
		if endpoint == "" {
			fail("otlp", fmt.Errorf("%s is empty", cfg.OTLP.EndpointEnv))
		} else if err := output.PostOTLP(ctx, client, endpoint, os.Getenv(cfg.OTLP.HeadersEnv), output.OTLPMetrics(rep, now)); err != nil {
			fail("otlp", err)
		}
	}

	// Written last: if an alert was not delivered, the Baseline must not advance, or the next run
	// would see those Findings as persisting and never alert them.
	if e.out != "" {
		path := e.out
		if code != exitOK {
			path = e.out + ".undelivered"
			fmt.Fprintf(stderr, "driftscan: delivery failed, Report written to %s; Baseline not advanced\n", path)
		}
		if err := writeReport(path, rep); err != nil {
			fail("report", err)
		}
	}

	c := output.Count(rep)
	fmt.Fprintf(stderr, "driftscan: %d Roots, %d Drift, %d Pending, %d Scan errors, %d resolved\n", c.Roots, c.Drift, c.Pending, c.Errors, c.Resolved)
	if code != exitOK {
		return code
	}
	if !modes.failOff {
		if failing := compare.Failing(rep, modes.threshold); len(failing) > 0 {
			fmt.Fprintf(stderr, "driftscan: %d active Findings at or above %s\n", len(failing), modes.threshold)
			return exitFindings
		}
	}
	return exitOK
}

func markdownPath(flagVal string) string {
	if flagVal == "auto" {
		return os.Getenv("GITHUB_STEP_SUMMARY")
	}
	return flagVal
}

func parseShard(s string) (int, int, error) {
	a, b, ok := strings.Cut(s, "/")
	i, err1 := strconv.Atoi(a)
	n, err2 := strconv.Atoi(b)
	if !ok || err1 != nil || err2 != nil || n < 1 || i < 1 || i > n {
		return 0, 0, fmt.Errorf("-shard must be i/n with 1 <= i <= n, got %q", s)
	}
	return i, n, nil
}

func readReport(path string) (finding.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return finding.Report{}, err
	}
	r, err := finding.Unmarshal(b)
	if err != nil {
		return finding.Report{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

func writeReport(path string, r finding.Report) error {
	b, err := r.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// minAppendBudget is the smallest budget used when the summary file is already nearly full.
const minAppendBudget = 4 * 1024

// appendMarkdown appends the summary to path. Whatever the file already holds counts against the
// size limit, and a missing final newline is added so the summary starts on its own line.
func appendMarkdown(path string, rep finding.Report, src output.Source) error {
	budget, prefix := output.MarkdownBudget, ""
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		budget = max(budget-int(fi.Size()), minAppendBudget)
		if !endsWithNewline(path, fi.Size()) {
			prefix = "\n"
			budget--
		}
	}
	return appendFile(path, prefix+output.Markdown(rep, src, budget))
}

func endsWithNewline(path string, size int64) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return true
	}
	return last[0] == '\n'
}

func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdEnrich(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enrich", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "repository root (where CODEOWNERS and .git live)")
	prefix := fs.String("prefix", "", "scanned directory relative to -repo (the -C given to scan)")
	gitOwner := fs.Bool("git-owner", false, "fall back to the last commit author email of the Root directory")
	out := fs.String("out", "", "write here instead of overwriting the input")
	ct := fs.Bool("cloudtrail", false, "also set who last changed each drifted AWS resource (needs state read access, terraform and cloudtrail:LookupEvents)")
	dir := fs.String("C", ".", "scanned directory, as given to scan (used with -cloudtrail)")
	configPath := fs.String("config", "", "config file (default <C>/drift.yaml if present; used with -cloudtrail)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "driftscan enrich: give exactly one raw Report")
		return exitError
	}
	r, err := readReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	co, err := enrich.LoadCodeowners(os.DirFS(*repo))
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	var git enrich.GitOwner
	if *gitOwner {
		if isShallow(ctx, *repo) {
			fmt.Fprintln(stderr, "driftscan: -git-owner: the repository is a shallow clone, so every owner would be the last merger; use fetch-depth: 0")
		}
		git = func(dir string) string {
			c := exec.CommandContext(ctx, "git", "-C", *repo, "log", "-1", "--format=%ae", "--", dir)
			b, err := c.Output()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
	}
	r = enrich.Owners(r, co, path.Clean(*prefix), git)
	if *ct {
		cfg, err := loadConfig(*configPath, *dir)
		if err != nil {
			fmt.Fprintln(stderr, "driftscan:", err)
			return exitError
		}
		roots, err := discover.Roots(os.DirFS(*dir), cfg)
		if err != nil {
			fmt.Fprintln(stderr, "driftscan: discover:", err)
			return exitError
		}
		r = enrich.Actors(ctx, r, roots, runner.Exec{Binary: cfg.Binary, Dir: *dir}, cloudtrail.New(), time.Now(), stderr)
	}
	dst := *out
	if dst == "" {
		dst = fs.Arg(0)
	}
	if err := writeReport(dst, r); err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	return exitOK
}

func isShallow(ctx context.Context, repo string) bool {
	b, err := exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "--is-shallow-repository").Output()
	return err == nil && strings.TrimSpace(string(b)) == "true"
}

func newBedrock(ctx context.Context, model string) (advise.Advisor, error) {
	return advise.NewBedrock(ctx, model)
}

func cmdAdvise(ctx context.Context, args []string, stdout, stderr io.Writer,
	newAdvisor func(context.Context, string) (advise.Advisor, error)) int {
	fs := flag.NewFlagSet("advise", flag.ContinueOnError)
	fs.SetOutput(stderr)
	model := fs.String("model", "", "Bedrock model or inference profile id (or advisor.model in drift.yaml); required")
	dir := fs.String("C", ".", "scanned directory, as given to scan (where drift.yaml is)")
	configPath := fs.String("config", "", "config file (default <C>/drift.yaml if present)")
	maxFindings := fs.Int("max-findings", 50, "send at most this many Findings in total, highest Severity first")
	includeInfo := fs.Bool("include-info", false, "also advise info-severity Findings")
	includeAck := fs.Bool("include-acknowledged", false, "also advise acknowledged Findings")
	out := fs.String("out", "", "write here instead of overwriting the input")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "driftscan advise: give exactly one raw Report")
		return exitError
	}
	if *maxFindings <= 0 {
		fmt.Fprintln(stderr, "driftscan advise: -max-findings must be greater than 0")
		return exitError
	}
	cfg, err := loadConfig(*configPath, *dir)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	if *model == "" {
		*model = cfg.Advisor.Model
	}
	if *model == "" {
		fmt.Fprintln(stderr, "driftscan advise: set -model or advisor.model in drift.yaml (check the current model id in the Bedrock console)")
		return exitError
	}
	r, err := readReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	a, err := newAdvisor(ctx, *model)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	res := advise.Run(ctx, a, &r, advise.Options{MaxFindings: *maxFindings, IncludeInfo: *includeInfo, IncludeAcknowledged: *includeAck})
	for _, e := range res.Errors {
		fmt.Fprintln(stderr, "driftscan: advise:", e)
	}
	fmt.Fprintf(stdout, "advise: %d sent, %d advised, %d dropped, %d skipped\n", res.Sent, res.Advised, res.Dropped, res.Skipped)
	dst := *out
	if dst == "" {
		dst = fs.Arg(0)
	}
	if err := writeReport(dst, r); err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	if len(res.Errors) > 0 {
		return exitError
	}
	return exitOK
}
