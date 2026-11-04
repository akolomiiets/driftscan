package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/akolomiiets/driftscan/internal/discover"
	"github.com/akolomiiets/driftscan/internal/output"
	"github.com/akolomiiets/driftscan/internal/runner"
	"github.com/akolomiiets/driftscan/internal/unmanaged"
)

func cmdUnmanaged(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unmanaged", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("C", ".", "directory with the Roots, as for scan")
	configPath := fs.String("config", "", "config file (default <dir>/drift.yaml if present)")
	types := fs.String("types", strings.Join(unmanaged.DefaultTypes, ","), "comma-separated AWS Config resource types to count")
	aggregator := fs.String("aggregator", "", "AWS Config aggregator name; queries all its accounts and regions")
	examples := fs.Int("examples", 0, "list up to N unmanaged ARNs (else resource ids) per type in the JSON and Markdown")
	out := fs.String("out", "unmanaged.json", `JSON output path; "" disables`)
	markdown := fs.String("markdown", "auto", `Markdown summary path; "auto" appends to $GITHUB_STEP_SUMMARY when set; "" disables`)
	otlp := fs.Bool("otlp", false, "send the driftscan.unmanaged gauge to the OTLP/HTTP endpoint named by otlp.endpoint_env")
	failOver := fs.Int("fail-over", -1, "exit 1 when the total unmanaged count is above N; -1 disables")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	typeList := strings.Split(*types, ",")
	for i := range typeList {
		typeList[i] = strings.TrimSpace(typeList[i])
	}
	if err := unmanaged.ValidateTypes(typeList); err != nil {
		fmt.Fprintln(stderr, "driftscan: -types:", err)
		return exitError
	}

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
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan: aws:", err)
		return exitError
	}
	inv := unmanaged.ConfigInventory{API: configservice.NewFromConfig(awsCfg), Aggregator: *aggregator}

	fmt.Fprintf(stderr, "driftscan %s: reading state of %d Roots\n", version, len(roots))
	res, err := runUnmanaged(ctx, runner.Exec{Binary: cfg.Binary, Dir: *dir}, inv, roots, typeList, *examples, cfg.Concurrency)
	if err != nil {
		fmt.Fprintln(stderr, "driftscan:", err)
		return exitError
	}
	return emitUnmanaged(ctx, res, unmanagedOut{
		out: *out, markdown: *markdown, otlp: *otlp, failOver: *failOver,
		endpointEnv: cfg.OTLP.EndpointEnv, headersEnv: cfg.OTLP.HeadersEnv,
	}, stdout, stderr)
}

func runUnmanaged(ctx context.Context, st unmanaged.StateReader, inv unmanaged.Inventory, roots []discover.Root, types []string, examples, concurrency int) (unmanaged.Result, error) {
	managed, err := unmanaged.ManagedIDs(ctx, st, roots, concurrency)
	if err != nil {
		return unmanaged.Result{}, err
	}
	resources, err := inv.List(ctx, types)
	if err != nil {
		return unmanaged.Result{}, err
	}
	return unmanaged.Count(resources, managed, types, examples), nil
}

type unmanagedOut struct {
	out, markdown, endpointEnv, headersEnv string
	otlp                                   bool
	failOver                               int
}

func emitUnmanaged(ctx context.Context, res unmanaged.Result, o unmanagedOut, stdout, stderr io.Writer) int {
	code := exitOK
	fail := func(what string, err error) {
		fmt.Fprintf(stderr, "driftscan: %s: %v\n", what, err)
		code = exitError
	}
	if o.out != "" {
		b, err := unmanaged.JSON(res)
		if err == nil {
			err = os.WriteFile(o.out, b, 0o644)
		}
		if err != nil {
			fail("json", err)
		}
	}
	md := unmanaged.Markdown(res)
	if p := markdownPath(o.markdown); p != "" {
		if err := appendFile(p, md); err != nil {
			fail("markdown", err)
		}
	} else if o.markdown == "auto" {
		fmt.Fprint(stdout, md)
	}
	if o.otlp {
		endpoint := os.Getenv(o.endpointEnv)
		client := &http.Client{Timeout: 30 * time.Second}
		if endpoint == "" {
			fail("otlp", fmt.Errorf("%s is empty", o.endpointEnv))
		} else if err := output.PostOTLP(ctx, client, endpoint, os.Getenv(o.headersEnv), unmanaged.OTLPMetrics(res, time.Now())); err != nil {
			fail("otlp", err)
		}
	}
	for _, tc := range res.Types {
		if tc.Total == 0 {
			fmt.Fprintf(stderr, "driftscan: warning: no AWS Config records for %s: recorder off, type not recorded, or wrong region (IAM is recorded only in the home region)\n", tc.Type)
		}
	}
	total := res.TotalUnmanaged()
	fmt.Fprintf(stderr, "driftscan: %d unmanaged resources across %d types\n", total, len(res.Types))
	if code != exitOK {
		return code
	}
	if o.failOver >= 0 && total > o.failOver {
		fmt.Fprintf(stderr, "driftscan: %d unmanaged is above -fail-over %d\n", total, o.failOver)
		return exitFindings
	}
	return exitOK
}
