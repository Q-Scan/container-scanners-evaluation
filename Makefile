# Container Scanners Evaluation - Makefile
# Runs all vulnerability scanners on a given image and outputs SARIF results

# Default image if not specified
IMAGE ?= python:3.4-alpine

# Output directory for scan results
RESULTS_DIR := results

# Image name sanitized for filenames (replace : and / with _)
IMAGE_SAFE := $(shell echo "$(IMAGE)" | sed 's/[:\/@]/_/g')

# Full path for this image's results
IMAGE_RESULTS_DIR := $(RESULTS_DIR)/$(IMAGE_SAFE)

# SBOM directories for each generator
SBOM_SYFT_DIR := $(IMAGE_RESULTS_DIR)/sbom/syft
SBOM_TRIVY_DIR := $(IMAGE_RESULTS_DIR)/sbom/trivy
SBOM_SCOUT_DIR := $(IMAGE_RESULTS_DIR)/sbom/docker-scout

# SBOM file paths
SBOM_SYFT_FILE := $(SBOM_SYFT_DIR)/sbom.cdx.json
SBOM_TRIVY_FILE := $(SBOM_TRIVY_DIR)/sbom.spdx.json
SBOM_SCOUT_FILE := $(SBOM_SCOUT_DIR)/sbom.spdx.json

# Create directories
$(IMAGE_RESULTS_DIR):
	mkdir -p $(IMAGE_RESULTS_DIR)

$(SBOM_SYFT_DIR):
	mkdir -p $(SBOM_SYFT_DIR)

$(SBOM_TRIVY_DIR):
	mkdir -p $(SBOM_TRIVY_DIR)

$(SBOM_SCOUT_DIR):
	mkdir -p $(SBOM_SCOUT_DIR)

# ============================================================================
# DIRECT IMAGE SCANNING (output SARIF)
# ============================================================================

.PHONY: scan-trivy
scan-trivy: $(IMAGE_RESULTS_DIR)
	@echo "🔍 Scanning with Trivy: $(IMAGE)"
	trivy image $(IMAGE) --format sarif --output $(IMAGE_RESULTS_DIR)/trivy.sarif

.PHONY: scan-grype
scan-grype: $(IMAGE_RESULTS_DIR)
	@echo "🔍 Scanning with Grype: $(IMAGE)"
	grype $(IMAGE) -o sarif --file $(IMAGE_RESULTS_DIR)/grype.sarif

.PHONY: scan-snyk
scan-snyk: $(IMAGE_RESULTS_DIR)
	@echo "🔍 Scanning with Snyk: $(IMAGE)"
	snyk container test $(IMAGE) --sarif-file-output=$(IMAGE_RESULTS_DIR)/snyk.sarif || true

.PHONY: scan-docker-scout
scan-docker-scout: $(IMAGE_RESULTS_DIR)
	@echo "🔍 Scanning with Docker Scout: $(IMAGE)"
	docker scout cves $(IMAGE) --format sarif --output $(IMAGE_RESULTS_DIR)/docker-scout.sarif

.PHONY: scan-all
scan-all: scan-trivy scan-grype scan-snyk scan-docker-scout
	@echo "✅ All direct image scans completed. Results in $(IMAGE_RESULTS_DIR)/"

# ============================================================================
# SBOM GENERATION (Multiple Generators)
# ============================================================================

.PHONY: sbom-syft
sbom-syft: $(SBOM_SYFT_DIR)
	@if [ -f "$(SBOM_SYFT_FILE)" ]; then \
		echo "📦 SBOM (Syft) already exists, skipping: $(SBOM_SYFT_FILE)"; \
	else \
		echo "📦 Generating SBOM with Syft (CycloneDX): $(IMAGE)"; \
		syft $(IMAGE) -o cyclonedx-json | jq . > $(SBOM_SYFT_FILE); \
	fi

.PHONY: sbom-trivy
sbom-trivy: $(SBOM_TRIVY_DIR)
	@if [ -f "$(SBOM_TRIVY_FILE)" ]; then \
		echo "📦 SBOM (Trivy) already exists, skipping: $(SBOM_TRIVY_FILE)"; \
	else \
		echo "📦 Generating SBOM with Trivy: $(IMAGE)"; \
		trivy image $(IMAGE) --format spdx-json --output $(SBOM_TRIVY_FILE); \
	fi

.PHONY: sbom-docker-scout
sbom-docker-scout: $(SBOM_SCOUT_DIR)
	@if [ -f "$(SBOM_SCOUT_FILE)" ]; then \
		echo "📦 SBOM (Docker Scout) already exists, skipping: $(SBOM_SCOUT_FILE)"; \
	else \
		echo "📦 Generating SBOM with Docker Scout: $(IMAGE)"; \
		docker scout sbom $(IMAGE) --format spdx --output $(SBOM_SCOUT_FILE); \
	fi

.PHONY: sbom-all
sbom-all: sbom-syft sbom-trivy sbom-docker-scout
	@echo "✅ All SBOMs generated in $(IMAGE_RESULTS_DIR)/sbom/"

# ============================================================================
# SBOM-BASED SCANNING: SYFT SBOM
# ============================================================================

.PHONY: scan-sbom-syft-trivy
scan-sbom-syft-trivy: sbom-syft
	@echo "🔍 Scanning Syft SBOM with Trivy"
	trivy sbom $(SBOM_SYFT_FILE) --format sarif --output $(SBOM_SYFT_DIR)/trivy.sarif

.PHONY: scan-sbom-syft-grype
scan-sbom-syft-grype: sbom-syft
	@echo "🔍 Scanning Syft SBOM with Grype"
	grype sbom:$(SBOM_SYFT_FILE) -o sarif --file $(SBOM_SYFT_DIR)/grype.sarif

.PHONY: scan-sbom-syft-snyk
scan-sbom-syft-snyk: sbom-syft
	@echo "🔍 Scanning Syft SBOM with Snyk"
	snyk sbom test --experimental --file=$(SBOM_SYFT_FILE) --json >$(SBOM_SYFT_DIR)/snyk.json || true

.PHONY: scan-sbom-syft-docker-scout
scan-sbom-syft-docker-scout: sbom-syft
	@echo "🔍 Scanning Syft SBOM with Docker Scout"
	docker scout cves sbom://$(SBOM_SYFT_FILE) --format sarif --output $(SBOM_SYFT_DIR)/docker-scout.sarif

.PHONY: scan-sbom-syft-all
scan-sbom-syft-all: scan-sbom-syft-trivy scan-sbom-syft-grype scan-sbom-syft-snyk scan-sbom-syft-docker-scout
	@echo "✅ All scanners completed on Syft SBOM. Results in $(SBOM_SYFT_DIR)/"

# ============================================================================
# SBOM-BASED SCANNING: TRIVY SBOM
# ============================================================================

.PHONY: scan-sbom-trivy-trivy
scan-sbom-trivy-trivy: sbom-trivy
	@echo "🔍 Scanning Trivy SBOM with Trivy"
	trivy sbom $(SBOM_TRIVY_FILE) --format sarif --output $(SBOM_TRIVY_DIR)/trivy.sarif

.PHONY: scan-sbom-trivy-grype
scan-sbom-trivy-grype: sbom-trivy
	@echo "🔍 Scanning Trivy SBOM with Grype"
	grype sbom:$(SBOM_TRIVY_FILE) -o sarif --file $(SBOM_TRIVY_DIR)/grype.sarif

.PHONY: scan-sbom-trivy-snyk
scan-sbom-trivy-snyk: sbom-trivy
	@echo "🔍 Scanning Trivy SBOM with Snyk"
	snyk sbom test --experimental --file=$(SBOM_TRIVY_FILE) --json >$(SBOM_TRIVY_DIR)/snyk.json || true

.PHONY: scan-sbom-trivy-docker-scout
scan-sbom-trivy-docker-scout: sbom-trivy
	@echo "🔍 Scanning Trivy SBOM with Docker Scout"
	docker scout cves sbom://$(SBOM_TRIVY_FILE) --format sarif --output $(SBOM_TRIVY_DIR)/docker-scout.sarif

.PHONY: scan-sbom-trivy-all
scan-sbom-trivy-all: scan-sbom-trivy-trivy scan-sbom-trivy-grype scan-sbom-trivy-snyk scan-sbom-trivy-docker-scout
	@echo "✅ All scanners completed on Trivy SBOM. Results in $(SBOM_TRIVY_DIR)/"

# ============================================================================
# SBOM-BASED SCANNING: DOCKER SCOUT SBOM
# ============================================================================

.PHONY: scan-sbom-scout-trivy
scan-sbom-scout-trivy: sbom-docker-scout
	@echo "🔍 Scanning Docker Scout SBOM with Trivy"
	trivy sbom $(SBOM_SCOUT_FILE) --format sarif --output $(SBOM_SCOUT_DIR)/trivy.sarif

.PHONY: scan-sbom-scout-grype
scan-sbom-scout-grype: sbom-docker-scout
	@echo "🔍 Scanning Docker Scout SBOM with Grype"
	grype sbom:$(SBOM_SCOUT_FILE) -o sarif --file $(SBOM_SCOUT_DIR)/grype.sarif

.PHONY: scan-sbom-scout-snyk
scan-sbom-scout-snyk: sbom-docker-scout
	@echo "🔍 Scanning Docker Scout SBOM with Snyk"
	snyk sbom test --experimental --file=$(SBOM_SCOUT_FILE) --json >$(SBOM_SCOUT_DIR)/snyk.json || true

.PHONY: scan-sbom-scout-docker-scout
scan-sbom-scout-docker-scout: sbom-docker-scout
	@echo "🔍 Scanning Docker Scout SBOM with Docker Scout"
	docker scout cves sbom://$(SBOM_SCOUT_FILE) --format sarif --output $(SBOM_SCOUT_DIR)/docker-scout.sarif

.PHONY: scan-sbom-scout-all
scan-sbom-scout-all: scan-sbom-scout-trivy scan-sbom-scout-grype scan-sbom-scout-snyk scan-sbom-scout-docker-scout
	@echo "✅ All scanners completed on Docker Scout SBOM. Results in $(SBOM_SCOUT_DIR)/"

# ============================================================================
# AGGREGATE TARGETS
# ============================================================================

.PHONY: scan-sbom-all
scan-sbom-all: scan-sbom-syft-all scan-sbom-trivy-all scan-sbom-scout-all
	@echo "✅ All SBOM-based scans completed (3 generators × 4 scanners = 12 scans)"

.PHONY: scan-everything
scan-everything: scan-all scan-sbom-all
	@echo ""
	@echo "🎉 ALL SCANS COMPLETED!"
	@echo "   - 4 direct image scans"
	@echo "   - 3 SBOMs generated (Syft, Trivy, Docker Scout)"
	@echo "   - 12 SBOM-based scans (4 scanners × 3 SBOMs)"
	@echo "   Results in $(IMAGE_RESULTS_DIR)/"

# ============================================================================
# UTILITIES
# ============================================================================

.PHONY: clean
clean:
	@echo "🧹 Cleaning results directory"
	rm -rf $(RESULTS_DIR)

.PHONY: help
help:
	@echo "Container Scanners Evaluation"
	@echo ""
	@echo "Usage: make <target> IMAGE=<image-name>"
	@echo ""
	@echo "Examples:"
	@echo "  make scan-everything IMAGE=python:3.4-alpine  # Run ALL scans"
	@echo "  make scan-all IMAGE=nginx:latest              # Direct image scans only"
	@echo ""
	@echo "=== MASTER COMMAND ==="
	@echo "  scan-everything    Run ALL scans (direct + all SBOM combinations)"
	@echo ""
	@echo "=== Direct Image Scanning ==="
	@echo "  scan-all           Run all 4 scanners on the image"
	@echo "  scan-trivy         Trivy only"
	@echo "  scan-grype         Grype only"
	@echo "  scan-snyk          Snyk only"
	@echo "  scan-docker-scout  Docker Scout only"
	@echo ""
	@echo "=== SBOM Generation ==="
	@echo "  sbom-all           Generate SBOMs with all 3 generators"
	@echo "  sbom-syft          Generate SBOM with Syft"
	@echo "  sbom-trivy         Generate SBOM with Trivy"
	@echo "  sbom-docker-scout  Generate SBOM with Docker Scout"
	@echo ""
	@echo "=== SBOM-based Scanning (by generator) ==="
	@echo "  scan-sbom-all          Run all scanners on all SBOMs (12 scans)"
	@echo "  scan-sbom-syft-all     Run all scanners on Syft SBOM"
	@echo "  scan-sbom-trivy-all    Run all scanners on Trivy SBOM"
	@echo "  scan-sbom-scout-all    Run all scanners on Docker Scout SBOM"
	@echo ""
	@echo "=== Utilities ==="
	@echo "  clean              Remove all results"
	@echo "  help               Show this help message"
