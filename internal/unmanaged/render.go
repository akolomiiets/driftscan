package unmanaged

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// JSON renders the Result as the -out file.
func JSON(r Result) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Markdown renders the Result as a step summary section.
func Markdown(r Result) string {
	var b strings.Builder
	b.WriteString("## driftscan: unmanaged resources\n\n")
	b.WriteString("| Resource type | Total | Managed | Unmanaged |\n|---|---:|---:|---:|\n")
	for _, t := range r.Types {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %d |\n", t.Type, t.Total, t.Managed, t.Unmanaged)
	}
	for _, t := range r.Types {
		if len(t.Examples) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n`%s` examples: `%s`\n", t.Type, strings.Join(t.Examples, "`, `"))
	}
	b.WriteString("\n")
	return b.String()
}

// OTLPMetrics builds an OTLP/HTTP JSON payload with the gauge driftscan.unmanaged by resource_type.
func OTLPMetrics(r Result, now time.Time) []byte {
	type kv = map[string]any
	ts := strconv.FormatInt(now.UnixNano(), 10)
	pts := []kv{}
	for _, t := range r.Types {
		pts = append(pts, kv{
			"attributes":   []kv{{"key": "resource_type", "value": kv{"stringValue": t.Type}}},
			"timeUnixNano": ts, "asInt": strconv.Itoa(t.Unmanaged),
		})
	}
	doc := kv{"resourceMetrics": []kv{{
		"resource": kv{"attributes": []kv{{"key": "service.name", "value": kv{"stringValue": "driftscan"}}}},
		"scopeMetrics": []kv{{"scope": kv{"name": "driftscan"}, "metrics": []kv{
			{"name": "driftscan.unmanaged", "unit": "{resource}", "gauge": kv{"dataPoints": pts}},
		}}},
	}}}
	b, _ := json.Marshal(doc)
	return b
}
