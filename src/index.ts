import * as core from '@actions/core'
import * as http from '@actions/http-client'

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

async function run(): Promise<void> {
  const projectId = core.getInput('project-id', { required: true })
  const apiKey = core.getInput('api-key', { required: true })
  const waitForResult = core.getInput('wait-for-result') === 'true'
  const failOnCvss = core.getInput('fail-on-cvss').toUpperCase()
  const minScore = parseFloat(core.getInput('min-score'))
  const failOnStrongCopyleft = core.getInput('fail-on-strong-copyleft') === 'true'
  const minUpToDate = parseFloat(core.getInput('min-up-to-date'))
  const timeout = parseInt(core.getInput('timeout'), 10)
  const apiUrl = core.getInput('api-url').replace(/\/$/, '')

  // Mask the API key in all logs
  core.setSecret(apiKey)

  const client = new http.HttpClient('deptools-scan-action', [], {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
  })

  // Trigger the scan
  core.info(`Triggering Deptools scan for project ${projectId}…`)

  const triggerRes = await client.postJson<TriggerResponse>(
    `${apiUrl}/v1/projects/${projectId}/scan`,
    {}
  )

  if (triggerRes.statusCode === 429) {
    const errorBody = triggerRes.result as unknown as { errors?: Array<{ retryAfter?: string }> }
    const retryAfter = errorBody?.errors?.[0]?.retryAfter
    core.warning(
      `Scan cooldown active — retry after ${retryAfter ?? 'some time'}. Skipping scan.`
    )
    core.setOutput('status', 'skipped')
    return
  }

  if (triggerRes.statusCode !== 202 || !triggerRes.result) {
    core.setFailed(`Failed to trigger scan (HTTP ${triggerRes.statusCode})`)
    return
  }

  const { jobId, pollUrl } = triggerRes.result
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
      core.setFailed(`Deptools scan failed: ${error ?? 'unknown error'}`)
      return
    }

    if (status === 'completed') {
      core.setOutput('status', 'completed')
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

  core.setFailed(`Scan did not complete within ${timeout}s timeout.`)
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
