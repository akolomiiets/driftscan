SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BIN := $(HERE).bin/driftscan
# every Root except the one that must stay unapplied (a Scan error on purpose)
APPLY_ROOTS := $(filter-out %/scan-error,$(wildcard $(HERE)envs/*/*))
PENDING_OVERRIDE := $(HERE)envs/dev/pending-change/pending_override.tf

.PHONY: up build apply break pending scan rescan fix down

# one provider download shared by all Roots
export TF_PLUGIN_CACHE_DIR := $(HERE).tfcache

up:
	mkdir -p $(TF_PLUGIN_CACHE_DIR)
	cd $(HERE) && docker compose up -d --wait

build:
	cd $(HERE)../.. && go build -o $(BIN) ./cmd/driftscan

apply:
	for d in $(APPLY_ROOTS); do \
	  echo "== apply $${d#$(HERE)}"; \
	  terraform -chdir=$$d init -input=false -no-color >/dev/null; \
	  terraform -chdir=$$d apply -auto-approve -input=false -no-color >/dev/null; \
	done

break:
	$(HERE)scripts/break.sh

# Edit the code of one Root after apply, without changing anything outside Terraform: a Pending change.
pending:
	printf 'variable "retention_seconds" {\n  default = 3600\n}\n' > $(PENDING_OVERRIDE)

# The scan-error Root needs init first or it would fail for a different reason.
scan: build
	rm -f $(HERE)summary.md
	cd $(HERE) && terraform -chdir=envs/dev/scan-error init -input=false -no-color >/dev/null
	cd $(HERE) && $(BIN) scan -C . -baseline baseline.json -out baseline.json \
	  -html report.html -markdown summary.md -annotations on -fail-on none

rescan: scan

# Apply every Root again (also applies the Pending change), then run `make rescan` to see what resolved.
fix:
	$(MAKE) -f $(lastword $(MAKEFILE_LIST)) apply

down:
	cd $(HERE) && docker compose down -v
	rm -f $(PENDING_OVERRIDE) $(HERE)baseline.json $(HERE)report.html $(HERE)summary.md
	find $(HERE)envs \( -name '*.tfstate*' -o -name .terraform -o -name .terraform.lock.hcl \) -prune -exec rm -rf {} +
