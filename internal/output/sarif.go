package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akolomiiets/driftscan/internal/finding"
)

// SARIF renders active Findings as SARIF 2.1.0. Locations are relative to %SRCROOT%, i.e. the
// scanned directory, which should be the repository root for GitHub Code Scanning.
func SARIF(r finding.Report, version string) ([]byte, error) {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  msg            `json:"fullDescription"`
		Help             msg            `json:"help"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type artifact struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId"`
	}
	type physical struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           *region  `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}

	rules := []rule{
		{ID: "drift", Name: "TerraformDrift",
			ShortDescription: msg{"Infrastructure changed outside Terraform"},
			FullDescription:  msg{"The real resource differs from the Terraform state: someone or something changed it without a Terraform apply."},
			Help:             msg{"Decide whether to revert the change (terraform apply) or adopt it into code, then rescan."},
			Properties:       map[string]any{"tags": []string{"security", "terraform", "drift"}}},
		{ID: "pending", Name: "TerraformPendingChange",
			ShortDescription: msg{"Code change not applied"},
			FullDescription:  msg{"The Terraform code differs from the state: a merged change was never applied."},
			Help:             msg{"Apply the change or revert the code."}},
		{ID: "scan-error", Name: "DriftscanScanError",
			ShortDescription: msg{"Root could not be planned"},
			FullDescription:  msg{"driftscan could not plan this Root, so its drift is unknown."},
			Help:             msg{"Check credentials, backend access and provider errors for this Root."}},
	}

	var results []result
	for _, f := range r.Findings {
		if !f.Active() {
			continue
		}
		ruleID := string(f.Kind)
		if f.Kind == finding.KindScanError {
			ruleID = "scan-error"
		}
		file := f.File
		if file == "" {
			file = strings.TrimSuffix(f.Root, "/") + "/"
		}
		phys := physical{ArtifactLocation: artifact{URI: file, URIBaseID: "%SRCROOT%"}}
		if f.Line > 0 {
			phys.Region = &region{StartLine: f.Line}
		}
		sum := sha256.Sum256([]byte(f.Key()))
		results = append(results, result{
			RuleID:              ruleID,
			Level:               level(f.Severity),
			Message:             msg{sarifMessage(f)},
			Locations:           []location{{PhysicalLocation: phys}},
			PartialFingerprints: map[string]string{"driftscanKey/v1": hex.EncodeToString(sum[:16])},
			Properties: map[string]any{
				"severity": f.Severity.String(), "status": string(f.Status), "root": f.Root,
				"address": f.Address, "paths": f.Paths,
			},
		})
	}
	if results == nil {
		results = []result{}
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "driftscan", "version": version,
				"informationUri": "https://github.com/akolomiiets/driftscan",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func level(s finding.Severity) string {
	switch {
	case s >= finding.SeverityHigh:
		return "error"
	case s == finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifMessage(f finding.Finding) string {
	switch f.Kind {
	case finding.KindScanError:
		return fmt.Sprintf("Root %s could not be planned: %s", f.Root, f.Message)
	case finding.KindPending:
		return fmt.Sprintf("%s in %s has an unapplied change (%s)", f.Address, f.Root, strings.Join(f.Actions, ", "))
	}
	what := strings.Join(f.Actions, ", ")
	if len(f.Paths) > 0 {
		what = "attributes " + strings.Join(f.Paths, ", ")
	}
	ack := ""
	if f.Acknowledged {
		ack = " (" + ackText(f.AckReason) + ")"
	}
	return fmt.Sprintf("%s in %s drifted: %s%s", f.Address, f.Root, what, ack)
}
