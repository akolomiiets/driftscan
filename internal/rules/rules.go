// Package rules assigns Severity to Findings and drops the ones ignore rules cover.
package rules

import (
	"time"

	"github.com/akolomiiets/driftscan/internal/config"
	"github.com/akolomiiets/driftscan/internal/finding"
	"github.com/akolomiiets/driftscan/internal/glob"
)

// Defaults are the built-in Severity rules. Order matters: the last match wins, so the broad
// medium baseline comes first and the tag-only rule last.
var Defaults = []config.Rule{
	{Type: "*", Severity: finding.SeverityMedium},

	// AWS
	{Type: "aws_iam_*", Severity: finding.SeverityHigh},
	{Type: "aws_*security_group*", Severity: finding.SeverityHigh},
	{Type: "aws_network_acl*", Severity: finding.SeverityHigh},
	{Type: "aws_kms_*", Severity: finding.SeverityHigh},
	{Type: "aws_s3_bucket_policy", Severity: finding.SeverityHigh},
	{Type: "aws_s3_bucket_public_access_block", Severity: finding.SeverityHigh},
	{Type: "aws_s3_account_public_access_block", Severity: finding.SeverityHigh},
	{Type: "aws_s3_bucket_acl", Severity: finding.SeverityHigh},
	{Type: "aws_secretsmanager_secret_policy", Severity: finding.SeverityHigh},
	{Type: "aws_lb_listener*", Severity: finding.SeverityHigh},
	{Type: "aws_cloudtrail", Severity: finding.SeverityHigh},
	{Type: "aws_organizations_policy*", Severity: finding.SeverityCritical},

	// Azure
	{Type: "azurerm_role_*", Severity: finding.SeverityHigh},
	{Type: "azurerm_network_security_*", Severity: finding.SeverityHigh},
	{Type: "azurerm_key_vault*", Severity: finding.SeverityHigh},
	{Type: "azurerm_firewall*", Severity: finding.SeverityHigh},
	{Type: "azuread_*", Severity: finding.SeverityHigh},

	// GCP
	{Type: "google_*_iam_*", Severity: finding.SeverityHigh},
	{Type: "google_compute_firewall*", Severity: finding.SeverityHigh},
	{Type: "google_kms_*", Severity: finding.SeverityHigh},
	{Type: "google_service_account*", Severity: finding.SeverityHigh},
	{Type: "google_storage_bucket_iam_*", Severity: finding.SeverityHigh},

	// Tag-only drift is bookkeeping, not risk.
	{Attribute: "tags*", Severity: finding.SeverityInfo},
	{Attribute: "*labels", Severity: finding.SeverityInfo},
}

// Apply sets Severity on every Finding and returns the ones no active ignore rule covers.
// Scan errors keep their Severity (high) and are never ignored. Pending changes use cfg.Pending
// severity unless a user rule with kind: pending matches. Acknowledged drift is info.
func Apply(fs []finding.Finding, cfg config.Config, now time.Time) []finding.Finding {
	ruleset := cfg.Severity.Rules
	if cfg.Severity.DefaultsOn() {
		ruleset = append(append([]config.Rule{}, Defaults...), cfg.Severity.Rules...)
	}
	out := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Kind == finding.KindScanError {
			out = append(out, f)
			continue
		}
		if f.Kind == finding.KindPending && !cfg.Pending.On() {
			continue
		}
		if ignored(f, cfg.Ignore, now) {
			continue
		}
		f.Severity = severity(f, ruleset, cfg.Severity.Rules, cfg.Pending.Severity)
		out = append(out, f)
	}
	return out
}

func severity(f finding.Finding, ruleset, userRules []config.Rule, pendingSev finding.Severity) finding.Severity {
	if f.Acknowledged {
		return finding.SeverityInfo
	}
	if f.Kind == finding.KindPending {
		sev := pendingSev
		for _, r := range userRules {
			if r.Kind == finding.KindPending && matches(r, f) {
				sev = r.Severity
			}
		}
		return sev
	}
	sev := finding.SeverityMedium
	for _, r := range ruleset {
		if r.Kind == finding.KindPending {
			continue
		}
		if matches(r, f) {
			sev = r.Severity
		}
	}
	return sev
}

// matches checks type and address globs, and for an attribute rule requires every drifted path to
// fall under it, so "tags" only downgrades drift that touches nothing but tags.
func matches(r config.Rule, f finding.Finding) bool {
	if r.Type != "" && !glob.Match(r.Type, f.Type, '/') {
		return false
	}
	if r.Address != "" && !glob.Match(r.Address, f.Address, '/') {
		return false
	}
	if r.Attribute != "" {
		if len(f.Paths) == 0 {
			return false
		}
		for _, p := range f.Paths {
			if !attrMatch(r.Attribute, p) {
				return false
			}
		}
	}
	return true
}

func ignored(f finding.Finding, rules []config.IgnoreRule, now time.Time) bool {
	for _, r := range rules {
		if r.Expired(now) {
			continue
		}
		if r.Type != "" && !glob.Match(r.Type, f.Type, '/') {
			continue
		}
		if r.Address != "" && !glob.Match(r.Address, f.Address, '/') {
			continue
		}
		if r.Root != "" && !glob.MatchPath(r.Root, f.Root) {
			continue
		}
		if r.Attribute != "" {
			if len(f.Paths) == 0 {
				continue
			}
			all := true
			for _, p := range f.Paths {
				if !attrMatch(r.Attribute, p) {
					all = false
					break
				}
			}
			if !all {
				continue
			}
		}
		return true
	}
	return false
}

// attrMatch is true when path, or any parent of it, matches the pattern as a dotted glob,
// so "tags*" covers "tags_all.Name" and "ingress" covers "ingress[0].cidr_blocks".
func attrMatch(pattern, path string) bool {
	for i := 0; i < len(path); i++ {
		if (path[i] == '.' || path[i] == '[') && glob.Match(pattern, path[:i], '.') {
			return true
		}
	}
	return glob.Match(pattern, path, '.')
}
