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

# Create results directory for this image
$(IMAGE_RESULTS_DIR):
	mkdir -p $(IMAGE_RESULTS_DIR)

# ============================================================================
# VULNERABILITY SCANNERS (output SARIF)
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

# ============================================================================
# SBOM GENERATION (Syft)
# ============================================================================

# SBOM directory and file path
SBOM_DIR := $(IMAGE_RESULTS_DIR)/sbom
SBOM_FILE := $(SBOM_DIR)/sbom-syft.spdx.json

# Create SBOM directory
$(SBOM_DIR):
	mkdir -p $(SBOM_DIR)

.PHONY: sbom-syft
sbom-syft: $(SBOM_DIR)
	@if [ -f "$(SBOM_FILE)" ]; then \
		echo "📦 SBOM already exists, skipping generation: $(SBOM_FILE)"; \
	else \
		echo "📦 Generating SBOM with Syft: $(IMAGE)"; \
		syft $(IMAGE) -o spdx-json --file $(SBOM_FILE); \
	fi

# ============================================================================
# SBOM-BASED VULNERABILITY SCANNING
# ============================================================================

.PHONY: scan-sbom-trivy
scan-sbom-trivy: sbom-syft
	@echo "🔍 Scanning SBOM with Trivy"
	trivy sbom $(SBOM_FILE) --format sarif --output $(SBOM_DIR)/trivy.sarif

.PHONY: scan-sbom-grype
scan-sbom-grype: sbom-syft
	@echo "🔍 Scanning SBOM with Grype"
	grype sbom:$(SBOM_FILE) -o sarif --file $(SBOM_DIR)/grype.sarif

.PHONY: scan-sbom-snyk
scan-sbom-snyk: sbom-syft
	@echo "🔍 Scanning SBOM with Snyk"
	snyk sbom test --experimental --file=$(SBOM_FILE) --json >$(SBOM_DIR)/snyk.json || true

.PHONY: scan-sbom-docker-scout
scan-sbom-docker-scout: sbom-syft
	@echo "🔍 Scanning SBOM with Docker Scout"
	docker scout cves sbom://$(SBOM_FILE) --format sarif --output $(SBOM_DIR)/docker-scout.sarif

# ============================================================================
# AGGREGATE TARGETS
# ============================================================================

.PHONY: scan-all
scan-all: scan-trivy scan-grype scan-snyk scan-docker-scout
	@echo "✅ All vulnerability scans completed. Results in $(IMAGE_RESULTS_DIR)/"

.PHONY: scan-sbom-all
scan-sbom-all: scan-sbom-trivy scan-sbom-grype scan-sbom-snyk scan-sbom-docker-scout
	@echo "✅ All SBOM-based scans completed. Results in $(SBOM_DIR)/"

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
	@echo "  make scan-all IMAGE=python:3.4-alpine"
	@echo "  make scan-sbom-all IMAGE=nginx:latest"
	@echo ""
	@echo "Image Scanning (direct):"
	@echo "  scan-all           Run all 4 vulnerability scanners on the image"
	@echo "  scan-trivy         Run Trivy scanner only"
	@echo "  scan-grype         Run Grype scanner only"
	@echo "  scan-snyk          Run Snyk scanner only"
	@echo "  scan-docker-scout  Run Docker Scout scanner only"
	@echo ""
	@echo "SBOM-based Scanning (generate SBOM first, then scan):"
	@echo "  scan-sbom-all          Generate SBOM with Syft, then scan with all scanners"
	@echo "  scan-sbom-trivy        Generate SBOM, scan with Trivy"
	@echo "  scan-sbom-grype        Generate SBOM, scan with Grype"
	@echo "  scan-sbom-snyk         Generate SBOM, scan with Snyk"
	@echo "  scan-sbom-docker-scout Generate SBOM, scan with Docker Scout"
	@echo "  sbom-syft              Generate SBOM only (SPDX format)"
	@echo ""
	@echo "Utilities:"
	@echo "  clean              Remove all results"
	@echo "  help               Show this help message"
