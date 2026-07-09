# Container Scanners Evaluation - Makefile

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
SBOM_SCOUT_DIR := $(IMAGE_RESULTS_DIR)/sbom/scout

# SBOM file paths
SBOM_SYFT_FILE := $(SBOM_SYFT_DIR)/sbom.spdx.json
SBOM_TRIVY_FILE := $(SBOM_TRIVY_DIR)/sbom.spdx.json
SBOM_SCOUT_FILE := $(SBOM_SCOUT_DIR)/sbom.spdx.json

# CycloneDX SBOM file paths (format-control experiment)
SBOM_SYFT_CDX_FILE := $(SBOM_SYFT_DIR)/sbom.cdx.json
SBOM_TRIVY_CDX_FILE := $(SBOM_TRIVY_DIR)/sbom.cdx.json

GENERATORS := syft trivy scout
SCANNERS := trivy grype snyk docker-scout

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
# DIRECT IMAGE SCANNING (output JSON)
# ============================================================================

.PHONY: scan-trivy
scan-trivy: $(IMAGE_RESULTS_DIR)
	@echo "Scanning with Trivy: $(IMAGE)"
	trivy image $(IMAGE) --format json --scanners vuln,misconfig,secret,license --output $(IMAGE_RESULTS_DIR)/trivy.json

.PHONY: scan-grype
scan-grype: $(IMAGE_RESULTS_DIR)
	@echo "Scanning with Grype: $(IMAGE)"
	grype $(IMAGE) --by-cve --add-cpes-if-none -o json --file $(IMAGE_RESULTS_DIR)/grype.json

.PHONY: scan-snyk
scan-snyk: $(IMAGE_RESULTS_DIR)
	@echo "Scanning with Snyk: $(IMAGE)"
	snyk container test --json --app-vulns $(IMAGE) --json-file-output=$(IMAGE_RESULTS_DIR)/snyk.json || true

.PHONY: scan-docker-scout
scan-docker-scout: $(IMAGE_RESULTS_DIR)
	@echo "Scanning with Docker Scout: $(IMAGE)"
	docker scout cves $(IMAGE) --format sarif --output $(IMAGE_RESULTS_DIR)/docker-scout.sarif.json

.PHONY: scan-all
scan-all: $(foreach scan,$(SCANNERS),scan-$(scan))
	@echo "All direct image scans completed. Results in $(IMAGE_RESULTS_DIR)/"

# ============================================================================
# SBOM GENERATION (Multiple Generators)
# ============================================================================

.PHONY: sbom-syft
sbom-syft: $(SBOM_SYFT_DIR)
	@if [ -f "$(SBOM_SYFT_FILE)" ]; then \
		echo "SBOM (Syft) already exists, skipping: $(SBOM_SYFT_FILE)"; \
	else \
		echo "Generating SBOM with Syft: $(IMAGE)"; \
		syft $(IMAGE) -o spdx-json --enrich all | jq . > $(SBOM_SYFT_FILE); \
	fi

.PHONY: sbom-trivy
sbom-trivy: $(SBOM_TRIVY_DIR)
	@if [ -f "$(SBOM_TRIVY_FILE)" ]; then \
		echo "SBOM (Trivy) already exists, skipping: $(SBOM_TRIVY_FILE)"; \
	else \
		echo "Generating SBOM with Trivy: $(IMAGE)"; \
		trivy image $(IMAGE) --format spdx-json --scanners vuln,misconfig,secret,license --output $(SBOM_TRIVY_FILE); \
	fi

.PHONY: sbom-scout
sbom-scout: $(SBOM_SCOUT_DIR)
	@if [ -f "$(SBOM_SCOUT_FILE)" ]; then \
		echo "SBOM (Docker Scout) already exists, skipping: $(SBOM_SCOUT_FILE)"; \
	else \
		echo "Generating SBOM with Docker Scout: $(IMAGE)"; \
		docker scout sbom $(IMAGE) --format spdx --output $(SBOM_SCOUT_FILE); \
	fi

.PHONY: sbom-all
sbom-all: $(foreach gen,$(GENERATORS),sbom-$(gen))
	@echo "All SBOMs generated in $(IMAGE_RESULTS_DIR)/sbom/"

# ============================================================================
# COMMON SBOM-BASED SCANNING RULES (The "Common Jobs")
# ============================================================================

# This rule handles: scan-sbom-syft-trivy, scan-sbom-trivy-trivy, scan-sbom-scout-trivy
.PHONY: scan-sbom-%-trivy
scan-sbom-%-trivy: sbom-%
	@echo "Scanning $* SBOM with Trivy"
	@SBOM_FILE=$(IMAGE_RESULTS_DIR)/sbom/$*/sbom.spdx.json; \
	trivy sbom $$SBOM_FILE --format json --scanners vuln,license --output $(IMAGE_RESULTS_DIR)/sbom/$*/trivy.json

# This rule handles: scan-sbom-syft-grype, scan-sbom-trivy-grype, scan-sbom-scout-grype
.PHONY: scan-sbom-%-grype
scan-sbom-%-grype: sbom-%
	@echo "Scanning $* SBOM with Grype"
	@SBOM_FILE=$(IMAGE_RESULTS_DIR)/sbom/$*/sbom.spdx.json; \
	grype sbom:$$SBOM_FILE --by-cve --add-cpes-if-none -o json --file $(IMAGE_RESULTS_DIR)/sbom/$*/grype.json

# This rule handles: scan-sbom-syft-snyk, scan-sbom-trivy-snyk, scan-sbom-scout-snyk
.PHONY: scan-sbom-%-snyk
scan-sbom-%-snyk: sbom-%
	@echo "Scanning $* SBOM with Snyk"
	@SBOM_FILE=$(IMAGE_RESULTS_DIR)/sbom/$*/sbom.spdx.json; \
	snyk sbom test --experimental --file=$$SBOM_FILE --json > $(IMAGE_RESULTS_DIR)/sbom/$*/snyk.json || true

# This rule handles: scan-sbom-syft-docker-scout, scan-sbom-trivy-docker-scout, scan-sbom-scout-docker-scout
.PHONY: scan-sbom-%-docker-scout
scan-sbom-%-docker-scout: sbom-%
	@echo "Scanning $* SBOM with Docker Scout"
	@SBOM_FILE=$(IMAGE_RESULTS_DIR)/sbom/$*/sbom.spdx.json; \
	docker scout cves sbom://$$SBOM_FILE --format sarif --output $(IMAGE_RESULTS_DIR)/sbom/$*/docker-scout.sarif.json

# Aggregate target for a specific generator (e.g., scan-sbom-syft-all)
.PHONY: scan-sbom-%-all
scan-sbom-%-all: $(foreach scan,$(SCANNERS),scan-sbom-%-$(scan))
	@echo "All scanners completed on $* SBOM. Results in $(IMAGE_RESULTS_DIR)/sbom/$*/"

# ============================================================================
# AGGREGATE TARGETS
# ============================================================================

.PHONY: scan-sbom-all
scan-sbom-all: $(foreach gen,$(GENERATORS),scan-sbom-$(gen)-all)
	@echo "All SBOM-based scans completed (3 generators x 4 scanners = 12 scans)"

.PHONY: scan-everything
scan-everything: scan-all scan-sbom-all
	@echo ""
	@echo "ALL SCANS COMPLETED!"
	@echo "   - 4 direct image scans"
	@echo "   - 3 SBOMs generated (Syft, Trivy, Docker Scout)"
	@echo "   - 12 SBOM-based scans (4 scanners × 3 SBOMs)"
	@echo "   Results in $(IMAGE_RESULTS_DIR)/"

# ============================================================================
# CYCLONEDX FORMAT CONTROL (SPDX vs CycloneDX)
# ----------------------------------------------------------------------------
# A separate control that tests whether the SBOM *format* (not its content) is
# responsible for the loss seen when exchanging SBOMs across tools. Scope:
# 2 images x (Syft, Trivy) x 4 scanners = 16 configs. Docker Scout is omitted
# as a generator here to keep the control matrix small. This is intentionally
# OUTSIDE the 144-scan core matrix and is run explicitly, not by scan-everything.
# ============================================================================

.PHONY: sbom-cdx-syft
sbom-cdx-syft: $(SBOM_SYFT_DIR)
	@if [ -f "$(SBOM_SYFT_CDX_FILE)" ]; then \
		echo "SBOM CycloneDX (Syft) already exists, skipping: $(SBOM_SYFT_CDX_FILE)"; \
	else \
		echo "Generating CycloneDX SBOM with Syft: $(IMAGE)"; \
		syft $(IMAGE) -o cyclonedx-json --enrich all | jq . > $(SBOM_SYFT_CDX_FILE); \
	fi

.PHONY: sbom-cdx-trivy
sbom-cdx-trivy: $(SBOM_TRIVY_DIR)
	@if [ -f "$(SBOM_TRIVY_CDX_FILE)" ]; then \
		echo "SBOM CycloneDX (Trivy) already exists, skipping: $(SBOM_TRIVY_CDX_FILE)"; \
	else \
		echo "Generating CycloneDX SBOM with Trivy: $(IMAGE)"; \
		trivy image $(IMAGE) --format cyclonedx --scanners vuln --output $(SBOM_TRIVY_CDX_FILE); \
	fi

# Scan one CycloneDX SBOM (generator = syft|trivy) with all 4 scanners.
# Handles: scan-sbom-cdx-syft, scan-sbom-cdx-trivy
.PHONY: scan-sbom-cdx-%
scan-sbom-cdx-%: sbom-cdx-%
	@echo "Scanning $* CycloneDX SBOM with all 4 scanners"
	@SBOM=$(IMAGE_RESULTS_DIR)/sbom/$*/sbom.cdx.json; DIR=$(IMAGE_RESULTS_DIR)/sbom/$*; \
	trivy sbom $$SBOM --format json --scanners vuln --output $$DIR/trivy.cdx.json; \
	grype sbom:$$SBOM --by-cve --add-cpes-if-none -o json --file $$DIR/grype.cdx.json; \
	snyk sbom test --experimental --file=$$SBOM --json > $$DIR/snyk.cdx.json || true; \
	docker scout cves sbom://$$SBOM --format sarif --output $$DIR/docker-scout.sarif.cdx.json

# Images used for the CycloneDX control (one JVM, one native).
CDX_CONTROL_IMAGES := \
	qscan.io/vulnerable-quarkus:DOCKERFILE-jvm \
	qscan.io/vulnerable-quarkus:DOCKERFILE-native

.PHONY: scan-cyclonedx-control
scan-cyclonedx-control:
	@echo "CycloneDX vs SPDX control: 2 images x (Syft,Trivy) x 4 scanners = 16 scans"
	@for img in $(CDX_CONTROL_IMAGES); do \
		echo "== $$img =="; \
		$(MAKE) scan-sbom-cdx-syft  IMAGE=$$img; \
		$(MAKE) scan-sbom-cdx-trivy IMAGE=$$img; \
	done
	@echo "Done. Compare *.cdx.json against the SPDX results."

# ============================================================================
# BULK SCANNING TARGETS
# ============================================================================

VULN_QUARKUS_IMAGES := \
	qscan.io/vulnerable-quarkus:BUILDPACK-jvm \
	qscan.io/vulnerable-quarkus:DOCKERFILE-jvm \
	qscan.io/vulnerable-quarkus:DOCKERFILE-jvm-alpine \
	qscan.io/vulnerable-quarkus:DOCKERFILE-jvm-corretto \
	qscan.io/vulnerable-quarkus:DOCKERFILE-native \
	qscan.io/vulnerable-quarkus:DOCKERFILE-native-micro \
	qscan.io/vulnerable-quarkus:DOCKERFILE-native-sbom \
	qscan.io/vulnerable-quarkus:JIB-jvm \
	qscan.io/vulnerable-quarkus:JIB-native

.PHONY: scan-vulnerable-quarkus-local
scan-vulnerable-quarkus-local:
	@echo "Scanning all 9 supported qscan.io/vulnerable-quarkus images..."
	@for img in $(VULN_QUARKUS_IMAGES); do \
		echo "Starting full scan for: $$img"; \
		$(MAKE) scan-everything IMAGE=$$img; \
	done

# ============================================================================
# UTILITIES
# ============================================================================

.PHONY: archives
archives:
	@echo "Repacking results/ and data/ (the archives are what git tracks, not the directories)"
	python -m zipfile -c results.zip results
	python -m zipfile -c data.zip data
	@ls -lh results.zip data.zip

.PHONY: clean
clean:
	@echo "Cleaning results directory"
	rm -rf $(RESULTS_DIR)

.PHONY: help
help:
	@echo "Container Scanners Evaluation"
	@echo ""
	@echo "Usage: make <target> IMAGE=<image-name>"
	@echo ""
	@echo "Examples:"
	@echo "  make scan-everything IMAGE=python:3.4-alpine  		Run ALL scans"
	@echo "  make scan-all IMAGE=nginx:latest              		Direct image scans only"
	@echo "  make scan-vulnerable-quarkus-local                 Scan ALL local qscan.io/vulnerable-quarkus images"
	@echo ""
	@echo "=== MASTER COMMANDS ==="
	@echo "  scan-everything             		Run ALL scans for a single IMAGE"
	@echo "  scan-vulnerable-quarkus-local 		Scan ALL local qscan.io/vulnerable-quarkus images"
	@echo ""
	@echo "=== Direct Image Scanning ==="
	@echo "  scan-all           				Run all 4 scanners on the image"
	@echo "  scan-trivy         				Trivy only"
	@echo "  scan-grype         				Grype only"
	@echo "  scan-snyk          				Snyk only"
	@echo "  scan-docker-scout  				Docker Scout only"
	@echo ""
	@echo "=== SBOM Generation ==="
	@echo "  sbom-all           				Generate SBOMs with all 3 generators"
	@echo "  sbom-syft          				Generate SBOM with Syft"
	@echo "  sbom-trivy         				Generate SBOM with Trivy"
	@echo "  sbom-scout         				Generate SBOM with Docker Scout"
	@echo ""
	@echo "=== SBOM-based Scanning (by generator) ==="
	@echo "  scan-sbom-all          			Run all scanners on all SBOMs (12 scans)"
	@echo "  scan-sbom-syft-all      			Run all scanners on Syft SBOM"
	@echo "  scan-sbom-trivy-all    			Run all scanners on Trivy SBOM"
	@echo "  scan-sbom-scout-all    			Run all scanners on Docker Scout SBOM"
	@echo ""
	@echo "=== CycloneDX format control ==="
	@echo "  scan-cyclonedx-control  			SPDX vs CycloneDX on 2 images x (Syft,Trivy) x 4 scanners"
	@echo ""
	@echo "=== Utilities ==="
	@echo "  archives           				Repack results/ and data/ into results.zip, data.zip"
	@echo "  clean              				Remove all results"
	@echo "  help               				Show this help message"
