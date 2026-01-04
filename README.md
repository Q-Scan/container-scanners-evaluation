# Container Scanners Evaluation

Comparative analysis of multiple vulnerability scanners against container images. Evaluates how different SBOM generators and vulnerability scanners produce varying results.

## Scanners

| Scanner | Direct Image Scan | SBOM Scan | Output Format |
|---------|-------------------|-----------|---------------|
| **Trivy** | ✅ | ✅ | SARIF |
| **Grype** | ✅ | ✅ | SARIF |
| **Snyk** | ✅ | ✅ | SARIF/JSON |
| **Docker Scout** | ✅ | ✅ | SARIF |

## SBOM Generators

| Generator | Format | Notes |
|-----------|--------|-------|
| **Syft** | CycloneDX JSON | Best Snyk compatibility |
| **Trivy** | SPDX JSON | |
| **Docker Scout** | SPDX JSON | |

## Quick Start

```bash
# Run ALL scans (direct + SBOM-based) on an image
make scan-everything IMAGE=python:3.4-alpine

# Run only direct image scans
make scan-all IMAGE=nginx:latest

# Run only SBOM-based scans
make scan-sbom-all IMAGE=alpine:latest

# Show all available targets
make help
```

## Results Structure

```
results/
└── <image_name>/
    ├── trivy.sarif           # Direct image scans
    ├── grype.sarif
    ├── snyk.sarif
    ├── docker-scout.sarif
    └── sbom/
        ├── syft/             # Syft-generated SBOM (CycloneDX)
        │   ├── sbom.cdx.json
        │   ├── trivy.sarif
        │   ├── grype.sarif
        │   ├── snyk.json
        │   └── docker-scout.sarif
        ├── trivy/            # Trivy-generated SBOM (SPDX)
        │   ├── sbom.spdx.json
        │   ├── trivy.sarif
        │   ├── grype.sarif
        │   ├── snyk.json
        │   └── docker-scout.sarif
        └── docker-scout/     # Docker Scout-generated SBOM (SPDX)
            ├── sbom.spdx.json
            ├── trivy.sarif
            ├── grype.sarif
            ├── snyk.json
            └── docker-scout.sarif
```

## Available Make Targets

### Master Command
```bash
make scan-everything IMAGE=<image>   # Run ALL scans (4 direct + 12 SBOM-based)
```

### Direct Image Scanning
```bash
make scan-all           # Run all 4 scanners
make scan-trivy         # Trivy only
make scan-grype         # Grype only
make scan-snyk          # Snyk only
make scan-docker-scout  # Docker Scout only
```

### SBOM Generation
```bash
make sbom-all           # Generate SBOMs with all 3 generators
make sbom-syft          # Syft (CycloneDX format)
make sbom-trivy         # Trivy (SPDX format)
make sbom-docker-scout  # Docker Scout (SPDX format)
```

### SBOM-based Scanning
```bash
make scan-sbom-all          # All scanners on all SBOMs (12 scans)
make scan-sbom-syft-all     # All scanners on Syft SBOM
make scan-sbom-trivy-all    # All scanners on Trivy SBOM
make scan-sbom-scout-all    # All scanners on Docker Scout SBOM
```

### Utilities
```bash
make clean    # Remove all results
make help     # Show help
```

## Prerequisites

- Docker
- Trivy
- Grype
- Syft
- Snyk CLI (authenticated)
- Docker Scout
- jq