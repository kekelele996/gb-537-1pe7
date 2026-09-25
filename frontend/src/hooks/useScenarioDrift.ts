import { useCallback, useEffect, useState } from 'react'
import { rolloverScenarioApi } from '../api/rollover-scenario'
import { errorMessage } from '../api/client'
import type { ScenarioDrift } from '../types/rollover-scenario'

interface ScenarioDriftState {
  report: ScenarioDrift | null
  loading: boolean
  error: string
  checkedAt: string
  refresh: () => Promise<void>
  clear: () => void
}

// useScenarioDrift reconciles a frozen scenario against the assets the trust
// team currently registers. Independent-review (historical) scenarios keep
// their snapshot; every other state must be refrozen before a drill starts.
export function useScenarioDrift(scenarioId: number | null | undefined): ScenarioDriftState {
  const [report, setReport] = useState<ScenarioDrift | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [checkedAt, setCheckedAt] = useState('')

  const refresh = useCallback(async () => {
    if (!scenarioId) {
      setReport(null)
      return
    }
    setLoading(true)
    setError('')
    try {
      const result = await rolloverScenarioApi.drift(scenarioId)
      setReport(result)
      setCheckedAt(new Date().toISOString())
    } catch (cause) {
      setError(errorMessage(cause))
    } finally {
      setLoading(false)
    }
  }, [scenarioId])

  const clear = useCallback(() => {
    setReport(null)
    setError('')
    setCheckedAt('')
  }, [])

  useEffect(() => {
    setReport(null)
    setError('')
    setCheckedAt('')
    if (scenarioId) void refresh()
  }, [scenarioId, refresh])

  return { report, loading, error, checkedAt, refresh, clear }
}
