# Deptools Scan Action

GitHub Action to trigger a [Deptools](https://deptools.io) dependency scan from your CI pipeline, optionally gate the job on the result, and download the SBOM of the scan (CycloneDX 1.7 or SPDX 2.3).

## Prerequisites

1. A Deptools account with a project created
2. An API key generated from **Project Settings → API Keys**
3. Store the key as a GitHub secret: `DEPTOOLS_API_KEY`
4. Note your project UUID from the project settings: `DEPTOOLS_PROJECT_ID`

## Usage

### Fire & forget (non-blocking)

Trigger a scan without blocking the pipeline. The result will be visible in the Deptools dashboard.

```yaml
- uses: deptools-io/scan-action@v1
  with:
    project-id: ${{ vars.DEPTOOLS_PROJECT_ID }}
    api-key: ${{ secrets.DEPTOOLS_API_KEY }}
```

### Wait for result + quality gates

Block the job until the scan completes and fail if the result doesn't meet your thresholds.

```yaml
- uses: deptools-io/scan-action@v1
  with:
    project-id: ${{ vars.DEPTOOLS_PROJECT_ID }}
    api-key: ${{ secrets.DEPTOOLS_API_KEY }}
    wait-for-result: true
    fail-on-cvss: CRITICAL           # fail if any CRITICAL vulnerability is found
    min-score: 7                     # fail if overall score drops below 7/10
    fail-on-strong-copyleft: true    # fail if a strong copyleft license is detected (e.g. GPL)
    min-up-to-date: 80               # fail if less than 80% of direct deps are up-to-date
```

### Download the SBOM of every scan

Set `sbom-format` to download the SBOM once the scan completes (this implies `wait-for-result: true`), then archive it with the step of your choice. The SBOM is downloaded before the quality gates run, so a build that fails a gate still has its SBOM.

```yaml
- uses: deptools-io/scan-action@v1
  with:
    project-id: ${{ vars.DEPTOOLS_PROJECT_ID }}
    api-key: ${{ secrets.DEPTOOLS_API_KEY }}
    sbom-format: cyclonedx           # or spdx
    # version: ${{ github.ref_type == 'tag' && github.ref_name || '' }}
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: sbom
    path: deptools-sbom.cdx.json     # a fixed path: sbom-file is empty when no SBOM was downloaded
    if-no-files-found: warn
```

`version` is written in the SBOM as the version of your product. Deptools scans the branch configured on the project, not the ref of the job: on a tag build, only pass the tag as `version` when the tag points at that branch, otherwise the SBOM would describe the branch under the tag's version.

### Full example workflow

```yaml
name: Deptools Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  deptools-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: deptools-io/scan-action@v1
        with:
          project-id: ${{ vars.DEPTOOLS_PROJECT_ID }}
          api-key: ${{ secrets.DEPTOOLS_API_KEY }}
          wait-for-result: true
          fail-on-cvss: HIGH
          min-score: 6
          fail-on-strong-copyleft: true
          min-up-to-date: 75
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `project-id` | ✅ | — | Your Deptools project UUID |
| `api-key` | ✅ | — | Your Deptools API key |
| `wait-for-result` | | `false` | Block the job until the scan completes |
| `fail-on-cvss` | | — | Fail if any vulnerability at or above this severity is found (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`) |
| `min-score` | | — | Fail if the overall score is below this value (0–10) |
| `fail-on-strong-copyleft` | | `false` | Fail if any dependency has a strong copyleft license (e.g. GPL) |
| `min-up-to-date` | | — | Fail if the percentage of direct dependencies on their latest version is below this value (0–100) |
| `timeout` | | `300` | Max seconds to wait for scan completion |
| `api-url` | | `https://api.deptools.io` | Override API base URL (staging / self-hosted) |
| `version` | | — | Product version written in the SBOM (e.g. `2.4.0`). Must match the branch configured on the Deptools project |
| `sbom-format` | | — | Download the SBOM once the scan completes: `cyclonedx` or `spdx`. Implies `wait-for-result: true` |
| `sbom-path` | | `deptools-sbom.cdx.json` / `deptools-sbom.spdx.json` | Where to write the SBOM, relative to the workspace (missing directories are created) |
| `fail-on-sbom-error` | | `false` | Fail the job if the SBOM cannot be downloaded (otherwise a warning, since the scan succeeded) |

## Outputs

| Output | Description |
|---|---|
| `job-id` | The scan job UUID |
| `status` | Final scan status: `running` \| `completed` \| `failed` \| `skipped` |
| `overall-score` | Overall Deptools score (populated when `wait-for-result: true`) |
| `poll-url` | URL to poll for scan status |
| `commercial-use` | `true` if a strong copyleft license was detected (populated when `wait-for-result: true`) |
| `direct-up-to-date` | Percentage of direct dependencies on their latest version (populated when `wait-for-result: true`) |
| `sbom-file` | Absolute path of the downloaded SBOM; empty when `sbom-format` is set but no SBOM could be downloaded |

## Notes

- When your plan's scan cooldown is active, the action exits with a warning (not a failure) and sets `status: skipped`. No scan ran, so there is no SBOM for that build (`sbom-file` is empty, even with `fail-on-sbom-error: true`): once the cooldown is over, run a scan from the dashboard and download its SBOM there. It describes the branch at that time, not the skipped commit.
- An invalid `sbom-format` fails the job before any scan is triggered.
- With `sbom-format`, the job waits for the scan like `wait-for-result: true`, up to `timeout` (300 s by default). A scan still running at the timeout fails the job: raise `timeout` for large projects.
- Quality gates (`fail-on-cvss`, `min-score`, `fail-on-strong-copyleft`, `min-up-to-date`) are only evaluated when `wait-for-result: true`.
- If `min-up-to-date` is set but the project has no direct dependencies, the gate is skipped with a warning.
- The `api-key` input is automatically masked in all logs.
