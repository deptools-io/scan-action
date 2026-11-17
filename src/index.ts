import * as core from '@actions/core'
import * as http from '@actions/http-client'
import { promises as fs } from 'node:fs'
import * as path from 'node:path'

const SEVERITY_RANK: Record<string, number> = {
  LOW: 1,
  MODERATE: 2,
  HIGH: 3,
  CRITICAL: 4,
}

interface TriggerResponse {
  jobId: string
  pollUrl: string
}

interface VulnerabilitiesBySeverity {
  CRITICAL: number
  HIGH: number
  MODERATE: number
  LOW: number
}

interface ScanResult {
  overall_score: number
  dependency_number: number
  vulnerabilities_by_severity: VulnerabilitiesBySeverity
  commercial_use: boolean
  direct_up_to_date: number | null
}

interface StatusResponse {
  jobId: string
  status: 'running' | 'completed' | 'failed'
  createdAt: string
  result: ScanResult | null
  error: string | null
}

interface ApiError {
  message?: string
  code?: string
  retryAfter?: string
}

type SbomFormat = 'cyclonedx' | 'spdx'

const SBOM_FORMATS: SbomFormat[] = ['cyclonedx', 'spdx']
const DEFAULT_SBOM_PATHS: Record<SbomFormat, string> = {
  cyclonedx: 'deptools-sbom.cdx.json',
  spdx: 'deptools-sbom.spdx.json',
}
// A 409 means "not ready yet": retried after Retry-After, a few times at most. A 410 is final.
const SBOM_MAX_ATTEMPTS = 6
const SBOM_DEFAULT_RETRY_SECONDS = 10
const SBOM_MAX_RETRY_SECONDS = 60

async function run(): Promise<void> {
  const projectId = core.getInput('project-id', { required: true })
  const apiKey = core.getInput('api-key', { required: true })
  const waitInput = core.getInput('wait-for-result') === 'true'
  const failOnCvss = core.getInput('fail-on-cvss').toUpperCase()
  const minScore = parseFloat(core.getInput('min-score'))
  const failOnStrongCopyleft = core.getInput('fail-on-strong-copyleft') === 'true'
  const minUpToDate = parseFloat(core.getInput('min-up-to-date'))
  const timeout = parseInt(core.getInput('timeout'), 10)
  const apiUrl = core.getInput('api-url').replace(/\/$/, '')
  const version = core.getInput('version').trim()
  const sbomFormatInput = core.getInput('sbom-format').trim().toLowerCase()
  const sbomPathInput = core.getInput('sbom-path').trim()
  const failOnSbomError = core.getInput('fail-on-sbom-error') === 'true'

  // Mask the API key in all logs
  core.setSecret(apiKey)

  // Checked before anything is sent: a typo must not cost a scan
  if (sbomFormatInput && !SBOM_FORMATS.includes(sbomFormatInput as SbomFormat)) {
    core.setFailed(`Invalid sbom-format "${sbomFormatInput}". Valid values: cyclonedx, spdx`)
    return
  }
  const sbomFormat = (sbomFormatInput || null) as SbomFormat | null
  const sbomPath = sbomFormat
    ? path.resolve(
        process.env.GITHUB_WORKSPACE ?? process.cwd(),
        sbomPathInput || DEFAULT_SBOM_PATHS[sbomFormat]
      )
    : null

  // There is no SBOM without waiting for the analysis to complete
  const waitForResult = waitInput || sbomFormat !== null
  if (sbomFormat && !waitInput) {
    core.info('sbom-format is set: waiting for the scan result to download the SBOM.')
  }

  const client = new http.HttpClient('deptools-scan-action', [], {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
  })

  // Trigger the scan. `post` and not `postJson`: postJson rejects every status above 299, which
  // turned the cooldown 429 into a failed job instead of a skipped scan.
  core.info(`Triggering Deptools scan for project ${projectId}…`)
  if (version) core.info(`Product version: ${version}`)

  const triggerRes = await client.post(
    `${apiUrl}/v1/projects/${projectId}/scan`,
    JSON.stringify(version ? { version } : {})
  )
  const triggerStatus = triggerRes.message.statusCode ?? 0
  const triggerBody = parseJson(await triggerRes.readBody())

  if (triggerStatus === 429) {
    const retryAfter = firstError(triggerBody)?.retryAfter
    core.warning(
      `Scan cooldown active — retry after ${retryAfter ?? 'some time'}. Skipping scan.`
    )
    if (sbomFormat) {
      core.warning(
        'No SBOM for this build: no scan ran. Once the cooldown is over, run a scan from the ' +
          'Deptools dashboard and download its SBOM there. It describes the branch at that time.'
      )
      core.setOutput('sbom-file', '')
    }
    core.setOutput('status', 'skipped')
    return
  }

  const trigger = triggerBody as TriggerResponse | null
  if (triggerStatus !== 202 || !trigger?.jobId) {
    core.setFailed(`Failed to trigger scan (HTTP ${triggerStatus})${describeError(triggerBody)}`)
    return
  }

  const { jobId, pollUrl } = trigger
  const fullPollUrl = pollUrl.startsWith('http') ? pollUrl : `${apiUrl}${pollUrl}`

  core.info(`Scan triggered — job ID: ${jobId}`)
  core.setOutput('job-id', jobId)
  core.setOutput('poll-url', fullPollUrl)

  if (!waitForResult) {
    core.info('wait-for-result is false — job continues without blocking.')
    core.setOutput('status', 'running')
    return
  }

  // Poll for result
  core.info('Waiting for scan result…')
  const deadline = Date.now() + timeout * 1000
  const pollIntervalMs = 20_000

  while (Date.now() < deadline) {
    await sleep(pollIntervalMs)

    const statusRes = await client.getJson<StatusResponse>(fullPollUrl)

    if (!statusRes.result) {
      core.warning('Empty response while polling — retrying…')
      continue
    }

    const { status, result, error } = statusRes.result
    core.info(`Scan status: ${status}`)

    if (status === 'failed') {
      core.setOutput('status', 'failed')
      if (sbomFormat) core.setOutput('sbom-file', '')
      core.setFailed(`Deptools scan failed: ${error ?? 'unknown error'}`)
      return
    }

    if (status === 'completed') {
      core.setOutput('status', 'completed')

      // Before the gates: a build that fails a gate is precisely one whose SBOM is wanted
      if (sbomFormat && sbomPath) {
        const sbomError = await downloadSbom(client, apiUrl, jobId, sbomFormat, sbomPath)
        if (sbomError) {
          core.setOutput('sbom-file', '')
          if (failOnSbomError) {
            core.setFailed(sbomError)
          } else {
            core.warning(`${sbomError}. The scan succeeded, the job goes on (set fail-on-sbom-error: true to fail it).`)
          }
        }
      }

      if (!result) {
        core.warning('Scan completed but result data is unavailable — quality gates skipped.')
        return
      }
      core.setOutput('overall-score', String(result.overall_score))
      core.setOutput('commercial-use', String(result.commercial_use))
      if (result.direct_up_to_date !== null) {
        core.setOutput('direct-up-to-date', String(result.direct_up_to_date))
      }
      core.info(`Overall score: ${result.overall_score}/10`)
      core.info(`Dependencies: ${result.dependency_number}`)
      core.info(`Vulnerabilities: ${JSON.stringify(result.vulnerabilities_by_severity)}`)
      core.info(`Strong copyleft: ${result.commercial_use}`)
      core.info(`Direct deps up-to-date: ${result.direct_up_to_date !== null ? `${result.direct_up_to_date}%` : 'n/a'}`)

      evaluateGates(result, failOnCvss, minScore, failOnStrongCopyleft, minUpToDate)
      return
    }
  }

  if (sbomFormat) core.setOutput('sbom-file', '')
  core.setFailed(`Scan did not complete within ${timeout}s timeout.`)
}

/**
 * Download the SBOM of a completed scan to `target`. The HTTP status alone decides: 200 written,
 * 409 retried after Retry-After, anything else (410 for a failed scan or an unavailable result)
 * final. Written to a temporary file next to the target, then renamed, so a failed download never
 * leaves a truncated SBOM behind. Returns null on success, the reason otherwise.
 */
async function downloadSbom(
  client: http.HttpClient,
  apiUrl: string,
  jobId: string,
  format: SbomFormat,
  target: string
): Promise<string | null> {
  const url = `${apiUrl}/v1/scans/${jobId}/sbom?format=${format}`
  const partial = `${target}.part-${process.pid}`

  for (let attempt = 1; ; attempt++) {
    let statusCode: number
    let body: string
    let retryAfterHeader: string | string[] | undefined
    try {
      const res = await client.get(url)
      statusCode = res.message.statusCode ?? 0
      retryAfterHeader = res.message.headers['retry-after']
      body = await res.readBody()
    } catch (err) {
      return `Could not download the SBOM: ${err instanceof Error ? err.message : String(err)}`
    }

    if (statusCode === 200) {
      try {
        await fs.mkdir(path.dirname(target), { recursive: true })
        // 'wx': never through an existing file or a planted symlink
        await fs.writeFile(partial, body, { flag: 'wx' })
        await fs.rename(partial, target)
      } catch (err) {
        await fs.rm(partial, { force: true })
        return `Could not write the SBOM to ${target}: ${err instanceof Error ? err.message : String(err)}`
      }
      core.setOutput('sbom-file', target)
      core.info(`SBOM (${format}) written to ${target}`)
      return null
    }

    if (statusCode === 409 && attempt < SBOM_MAX_ATTEMPTS) {
      const seconds = parseInt(String(retryAfterHeader ?? ''), 10)
      const wait = Number.isFinite(seconds) && seconds > 0
        ? Math.min(seconds, SBOM_MAX_RETRY_SECONDS)
        : SBOM_DEFAULT_RETRY_SECONDS
      core.info(`SBOM not ready yet — retrying in ${wait}s…`)
      await sleep(wait * 1000)
      continue
    }

    return `SBOM not available (HTTP ${statusCode})${describeError(parseJson(body))}`
  }
}

function parseJson(text: string): unknown {
  try {
    return text ? JSON.parse(text) : null
  } catch {
    return null
  }
}

/** The first error of a `{ errors: [{ message, code }] }` body, the shape of every API error. */
function firstError(body: unknown): ApiError | undefined {
  const errors = (body as { errors?: ApiError[] } | null)?.errors
  return Array.isArray(errors) ? errors[0] : undefined
}

function describeError(body: unknown): string {
  const error = firstError(body)
  if (!error?.message) return ''
  return `: ${error.message}${error.code ? ` (${error.code})` : ''}`
}

function evaluateGates(
  result: ScanResult,
  failOnCvss: string,
  minScore: number,
  failOnStrongCopyleft: boolean,
  minUpToDate: number
): void {
  if (failOnCvss && SEVERITY_RANK[failOnCvss] === undefined) {
    core.warning(`Unknown fail-on-cvss value "${failOnCvss}" — gate skipped. Valid values: CRITICAL, HIGH, MODERATE, LOW`)
  } else if (failOnCvss && SEVERITY_RANK[failOnCvss] !== undefined) {
    const threshold = SEVERITY_RANK[failOnCvss]
    const vulns = result.vulnerabilities_by_severity

    for (const [severity, count] of Object.entries(vulns)) {
      if (count > 0 && SEVERITY_RANK[severity] >= threshold) {
        core.setFailed(
          `Gate failed: ${count} ${severity} vulnerability(ies) found (fail-on-cvss: ${failOnCvss})`
        )
        return
      }
    }
  }

  if (!isNaN(minScore) && result.overall_score < minScore) {
    core.setFailed(
      `Gate failed: score ${result.overall_score} is below the required minimum of ${minScore}`
    )
    return
  }

  if (failOnStrongCopyleft && result.commercial_use) {
    core.setFailed('Gate failed: one or more dependencies have a strong copyleft license')
    return
  }

  if (!isNaN(minUpToDate)) {
    if (result.direct_up_to_date === null) {
      core.warning('min-up-to-date gate skipped: no direct dependencies found')
    } else if (result.direct_up_to_date < minUpToDate) {
      core.setFailed(
        `Gate failed: ${result.direct_up_to_date}% of direct dependencies are up-to-date, required minimum is ${minUpToDate}%`
      )
      return
    }
  }

  core.info('All gates passed.')
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

run().catch((err: unknown) => core.setFailed(err instanceof Error ? err.message : String(err)))
