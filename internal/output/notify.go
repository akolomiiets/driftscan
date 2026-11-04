package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// MaxSlackLines caps one message; the rest is summarised as "+N more".
const MaxSlackLines = 30

// SlackMessages builds the message texts for the alert Findings. groupBy "root" gives one message
// per Root, "scan" one message. A first Scan (not compared) gives one "baseline established" line.
// runURL, when set, is linked at the end of each message.
func SlackMessages(r finding.Report, alerts []finding.Finding, groupBy, runURL string) []string {
	if !r.Compared {
		c := Count(r)
		return []string{fmt.Sprintf(":information_source: driftscan baseline established: %d Drift, %d Pending changes, %d Scan errors across %d Roots.%s",
			c.Drift, c.Pending, c.Errors, c.Roots, link(runURL))}
	}
	if len(alerts) == 0 {
		return nil
	}
	groups := map[string][]finding.Finding{}
	if groupBy == "root" {
		for _, f := range alerts {
			groups[f.Root] = append(groups[f.Root], f)
		}
	} else {
		groups[""] = alerts
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var msgs []string
	for _, k := range keys {
		fs := groups[k]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
		var b strings.Builder
		title := "driftscan"
		if k != "" {
			title += " `" + k + "`"
		}
		fmt.Fprintf(&b, "*%s*: %s\n", title, tally(fs))
		for i, f := range fs {
			if i == MaxSlackLines {
				fmt.Fprintf(&b, "+%d more\n", len(fs)-i)
				break
			}
			b.WriteString(slackLine(f, k == "") + "\n")
		}
		b.WriteString(link(runURL))
		msgs = append(msgs, strings.TrimRight(b.String(), "\n"))
	}
	return msgs
}

func tally(fs []finding.Finding) string {
	n := map[finding.Status]int{}
	for _, f := range fs {
		n[f.Status]++
	}
	var parts []string
	for _, s := range []finding.Status{finding.StatusNew, finding.StatusChanged, finding.StatusResolved, finding.StatusPersisting} {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func slackLine(f finding.Finding, withRoot bool) string {
	icon := map[finding.Status]string{
		finding.StatusNew: ":red_circle:", finding.StatusChanged: ":large_orange_circle:",
		finding.StatusResolved: ":white_check_mark:", finding.StatusPersisting: ":hourglass:",
	}[f.Status]
	root := ""
	if withRoot {
		root = "`" + f.Root + "` "
	}
	switch f.Kind {
	case finding.KindScanError:
		if f.Status == finding.StatusPersisting {
			return fmt.Sprintf("%s %sstill failing after %d scans: %s", ":rotating_light:", root, f.SeenCount, f.Message)
		}
		return fmt.Sprintf("%s %s*scan error* %s", icon, root, f.Message)
	}
	what := strings.Join(f.Paths, ", ")
	if what == "" {
		what = strings.Join(f.Actions, ", ")
	}
	kind := "drift"
	if f.Kind == finding.KindPending {
		kind = "pending"
	}
	line := fmt.Sprintf("%s [%s] %s%s `%s`: %s", icon, f.Severity, root, kind, f.Address, what)
	if f.Owner != "" {
		line += " - " + f.Owner
	}
	if f.ChangedBy != "" {
		line += " - changed by " + f.ChangedBy
	}
	if f.AdviceAction != "" {
		line += " [AI: " + f.AdviceAction + "]"
	}
	return line
}

func link(u string) string {
	if u == "" {
		return ""
	}
	return " <" + u + "|run>"
}

// PostSlack sends each message to a Slack incoming webhook.
func PostSlack(ctx context.Context, client *http.Client, webhook string, msgs []string) error {
	for _, m := range msgs {
		body, _ := json.Marshal(map[string]string{"text": m})
		if err := post(ctx, client, webhook, body, nil); err != nil {
			return fmt.Errorf("slack: %w", err)
		}
	}
	return nil
}

// OTLPMetrics builds an OTLP/HTTP JSON metrics payload:
//   - driftscan.findings (gauge): active Findings by root, kind, severity, status
//   - driftscan.root.up (gauge): 1 if the Root was planned, 0 on Scan error
//   - driftscan.scan.duration (gauge, seconds)
func OTLPMetrics(r finding.Report, now time.Time) []byte {
	ts := strconv.FormatInt(now.UnixNano(), 10)
	type kv = map[string]any
	attr := func(pairs ...string) []kv {
		var out []kv
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, kv{"key": pairs[i], "value": kv{"stringValue": pairs[i+1]}})
		}
		return out
	}

	counts := map[[4]string]int{}
	for _, f := range r.Findings {
		if !f.Active() {
			continue
		}
		counts[[4]string{f.Root, string(f.Kind), f.Severity.String(), string(f.Status)}]++
	}
	keys := make([][4]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.Join(keys[i][:], "|") < strings.Join(keys[j][:], "|") })
	var findingPts []kv
	for _, k := range keys {
		findingPts = append(findingPts, kv{
			"attributes":   attr("root", k[0], "kind", k[1], "severity", k[2], "status", k[3]),
			"timeUnixNano": ts, "asInt": strconv.Itoa(counts[k]),
		})
	}
	var upPts []kv
	for _, root := range r.Roots {
		up := "1"
		if root.Outcome == finding.RootError {
			up = "0"
		}
		upPts = append(upPts, kv{"attributes": attr("root", root.Path, "outcome", string(root.Outcome)), "timeUnixNano": ts, "asInt": up})
	}

	metrics := []kv{
		{"name": "driftscan.findings", "unit": "{finding}", "gauge": kv{"dataPoints": nonNil(findingPts)}},
		{"name": "driftscan.root.up", "unit": "1", "gauge": kv{"dataPoints": nonNil(upPts)}},
		{"name": "driftscan.scan.duration", "unit": "s", "gauge": kv{"dataPoints": []kv{{"timeUnixNano": ts, "asDouble": r.Duration.Seconds()}}}},
	}
	doc := kv{"resourceMetrics": []kv{{
		"resource":     kv{"attributes": attr("service.name", "driftscan")},
		"scopeMetrics": []kv{{"scope": kv{"name": "driftscan"}, "metrics": metrics}},
	}}}
	b, _ := json.Marshal(doc)
	return b
}

func nonNil(v []map[string]any) []map[string]any {
	if v == nil {
		return []map[string]any{}
	}
	return v
}

// PostOTLP sends a payload from OTLPMetrics. headers uses the OTEL_EXPORTER_OTLP_HEADERS format.
func PostOTLP(ctx context.Context, client *http.Client, endpoint, headers string, payload []byte) error {
	h := map[string]string{}
	for _, pair := range strings.Split(headers, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			h[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := post(ctx, client, endpoint, payload, h); err != nil {
		return fmt.Errorf("otlp: %w", err)
	}
	return nil
}

func post(ctx context.Context, client *http.Client, url string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
