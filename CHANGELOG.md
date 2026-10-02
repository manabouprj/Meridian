# Changelog

All notable changes to MERIDIAN. Versions follow [semantic versioning](https://semver.org/); the tag on `main` is
the release.

## 1.0.1 - 2026-10-02

Repository review of v1.0.0 as published on GitHub. No change to the agent boundary, detection logic or Terraform
resources; one behaviour change for configuration errors (below).

### Fixed

* **Time zones on Windows and typos fail loudly.** An unknown time-zone name used to fall back to UTC silently.
  On Windows, which has no time-zone database, every IANA name (`Asia/Dubai`) was unknown, so events from those
  sources landed hours out. `tzdata` is now a dependency, an unknown zone or an out-of-range offset raises an
  error, and the configuration is checked at start-up. (PEER_REVIEW R-49)

### Changed

* **Configuration is validated at start-up:** source keys must be unique, `format` must name a known mapper, and
  every `settings.timezone` must resolve. A bad configuration stops the service instead of producing rejects later.
* **Hash-locked dependencies.** `requirements.txt` and the new `requirements-dev.txt` (from `requirements-dev.in`)
  carry SHA-256 hashes for every package; the image installs with `--require-hashes`. Regenerate with `make lock`.
* **CI hardening:** every action pinned to a full commit SHA; `persist-credentials: false` on checkouts; job
  timeouts; concurrency group; CI also runs on release tags.
* **Container image scan and SBOM in CI:** Trivy fails the build on fixable critical vulnerabilities and produces a
  CycloneDX SBOM, kept as a build artifact for 90 days.
* **LODESTAR contract test can run on GitHub:** set the repository secret `LODESTAR_READ_TOKEN` (fine-grained,
  read-only on `manabouprj/Lodestar`); without it the test still skips.
* **Dockerfile:** lists the `collect` role, exposes 6514 (TLS syslog), explains how to pin the base image by digest.
* MCP servers report the package version instead of a hard-coded string.

### Added

* `.github/dependabot.yml` (pip, GitHub Actions, Docker, Terraform for both clouds) and `.github/CODEOWNERS`.
* `docs/ROADMAP.md`, `docs/roadmap/issues.json` and `scripts/create_roadmap_issues.ps1`: the adoption phases as
  GitHub milestones and 24 issues, created with the GitHub CLI (safe to re-run).
* This changelog.

### Still open (tracked in the roadmap)

* Pin the base image by digest (the build environment could not reach Docker Hub to read it).
* Choose and add a licence.

## 1.0.0 - 2026-10-02

First release: security data lake, deterministic detection, four AI agents working only through MCP, four-eyes
containment and a hash-chained audit trail on Azure + Microsoft Foundry or AWS + Amazon Bedrock; six ingestion paths
for hybrid estates; LODESTAR integration; HLD/LLD, design, deployment runbooks, executive review and the AZ-00,
AWS-00, INT-00 and LOG-00 build documents. Review findings R-1 to R-48 are in `docs/PEER_REVIEW.md`.
