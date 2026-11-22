import * as core from '@actions/core'
import * as http from '@actions/http-client'
import { createHash } from 'node:crypto'
import { createReadStream, promises as fs } from 'node:fs'
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
const DEFAULT_VEX_PATH = 'deptools-vex.cdx.json'
// A 409 means "not ready yet": retried after Retry-After, a few times at most. A 410 is final.
// Same for both documents (SBOM, VEX)
const DOWNLOAD_MAX_ATTEMPTS = 6
const DOWNLOAD_DEFAULT_RETRY_SECONDS = 10
const DOWNLOAD_MAX_RETRY_SECONDS = 60

/** One document of a completed scan to download: the SBOM or the pre-filled VEX. */
interface DocumentDownload {
  /** In messages: SBOM, VEX */
  name: 'SBOM' | 'VEX'
  /** In the success line: `SBOM (cyclonedx)`, `VEX` */
  label: string
  url: string
  target: string
  /** The output that receives the path once written */
  output: 'sbom-file' | 'vex-file'
}

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
  const vex = core.getInput('vex') === 'true'
  const vexPathInput = core.getInput('vex-path').trim()
  const failOnVexError = core.getInput('fail-on-vex-error') === 'true'
  const artifactInput = core.getInput('artifact').trim()
  const artifactUrl = core.getInput('artifact-url').trim()

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
  const vexPath = vex
    ? path.resolve(process.env.GITHUB_WORKSPACE ?? process.cwd(), vexPathInput || DEFAULT_VEX_PATH)
    : null
  // The second download would overwrite the first
  if (sbomPath && vexPath && sbomPath === vexPath) {
    core.setFailed(`sbom-path and vex-path name the same file: ${vexPath}`)
    return
  }

  // There is no SBOM nor VEX without waiting for the analysis to complete
  const waitForResult = waitInput || sbomFormat !== null || vex
  if (sbomFormat && !waitInput) {
    core.info('sbom-format is set: waiting for the scan result to download the SBOM.')
  }
  if (vex && !waitInput) {
    core.info('vex is set: waiting for the scan result to download the VEX.')
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

  // The file this job built, for the SBOM's product: its name and SHA-512, computed here, never the
  // file itself. Optional, and never a reason to fail the job: a problem is a warning.
  const artifact = artifactInput ? await describeArtifact(artifactInput) : null
  if (artifact) core.info(`Artifact: ${artifact.artifactName} (sha512 ${artifact.artifactSha512})`)

  // Only the fields that are set: without the new inputs, the body is exactly what v1.1.0 sent
  const body = {
    ...(version && { version }),
    ...artifact,
    ...(artifactUrl && { artifactUrl }),
  }
  const triggerRes = await client.post(
    `${apiUrl}/v1/projects/${projectId}/scan`,
    JSON.stringify(body)
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
    if (vex) {
      core.warning(
        'No VEX for this build: no scan ran. Once the cooldown is over, run a scan from the ' +
          'Deptools dashboard and download its VEX there. It lists the vulnerabilities known at that time.'
      )
      core.setOutput('vex-file', '')
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
      if (vex) core.setOutput('vex-file', '')
      core.setFailed(`Deptools scan failed: ${error ?? 'unknown error'}`)
      return
    }

    if (status === 'completed') {
      core.setOutput('status', 'completed')

      // Before the gates: a build that fails a gate is precisely one whose SBOM and VEX are
      // wanted. Each on its own: a missing SBOM does not keep the VEX from being fetched
      if (sbomFormat && sbomPath) {
        const sbomError = await downloadDocument(client, {
          name: 'SBOM',
          label: `SBOM (${sbomFormat})`,
          url: `${apiUrl}/v1/scans/${jobId}/sbom?format=${sbomFormat}`,
          target: sbomPath,
          output: 'sbom-file',
        })
        if (sbomError) {
          core.setOutput('sbom-file', '')
          if (failOnSbomError) {
            core.setFailed(sbomError)
          } else {
            core.warning(`${sbomError}. The scan succeeded, the job goes on (set fail-on-sbom-error: true to fail it).`)
          }
        }
      }
      if (vexPath) {
        const vexError = await downloadDocument(client, {
          name: 'VEX',
          label: 'VEX',
          url: `${apiUrl}/v1/scans/${jobId}/vex`,
          target: vexPath,
          output: 'vex-file',
        })
        if (vexError) {
          core.setOutput('vex-file', '')
          if (failOnVexError) {
            core.setFailed(vexError)
          } else {
            core.warning(`${vexError}. The scan succeeded, the job goes on (set fail-on-vex-error: true to fail it).`)
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
  if (vex) core.setOutput('vex-file', '')
  core.setFailed(`Scan did not complete within ${timeout}s timeout.`)
}

/**
 * Download one document of a completed scan (SBOM or VEX) to its target. The HTTP status alone
 * decides: 200 written, 409 retried after Retry-After, anything else (410 for a failed scan or an
 * unavailable result) final. Written to a temporary file next to the target, then renamed, so a
 * failed download never leaves a truncated document behind. Returns null on success, the reason
 * otherwise.
 */
async function downloadDocument(
  client: http.HttpClient,
  { name, label, url, target, output }: DocumentDownload
): Promise<string | null> {
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
      return `Could not download the ${name}: ${err instanceof Error ? err.message : String(err)}`
    }

    if (statusCode === 200) {
      try {
        await fs.mkdir(path.dirname(target), { recursive: true })
        // 'wx': never through an existing file or a planted symlink
        await fs.writeFile(partial, body, { flag: 'wx' })
        await fs.rename(partial, target)
      } catch (err) {
        await fs.rm(partial, { force: true })
        return `Could not write the ${name} to ${target}: ${err instanceof Error ? err.message : String(err)}`
      }
      core.setOutput(output, target)
      core.info(`${label} written to ${target}`)
      return null
    }

    if (statusCode === 409 && attempt < DOWNLOAD_MAX_ATTEMPTS) {
      const seconds = parseInt(String(retryAfterHeader ?? ''), 10)
      const wait = Number.isFinite(seconds) && seconds > 0
        ? Math.min(seconds, DOWNLOAD_MAX_RETRY_SECONDS)
        : DOWNLOAD_DEFAULT_RETRY_SECONDS
      core.info(`${name} not ready yet — retrying in ${wait}s…`)
      await sleep(wait * 1000)
      continue
    }

    return `${name} not available (HTTP ${statusCode})${describeError(parseJson(body))}`
  }
}

function parseJson(text: string): unknown {
  try {
    return text ? JSON.parse(text) : null
  } catch {
    return null
  }
}

/**
 * Name and SHA-512 of the artifact this job built, the path relative to the workspace. The file is
 * read as a stream, whatever its size; nothing is written. Null, with a warning, when it cannot be
 * read: the scan goes on without it.
 */
async function describeArtifact(
  input: string
): Promise<{ artifactName: string; artifactSha512: string } | null> {
  const file = path.resolve(process.env.GITHUB_WORKSPACE ?? process.cwd(), input)
  try {
    const stat = await fs.stat(file)
    if (!stat.isFile()) throw new Error('not a file')
    const hash = createHash('sha512')
    for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer)
    return { artifactName: path.basename(file), artifactSha512: hash.digest('hex') }
  } catch (error) {
    core.warning(
      `Could not read the artifact ${input} (${(error as Error).message}): the scan goes on ` +
        'without it. Run this step after the step that builds the file.'
    )
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
