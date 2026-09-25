import type { Paginated } from '../types/common'
import type { ScenarioState } from '../types/enums/scenario-state'
import type { CreateRolloverScenarioInput, RolloverScenario, SnapshotDrift } from '../types/rollover-scenario'
import { apiRequest } from './client'

export const rolloverScenarioApi = {
  list: (query = '') => apiRequest<Paginated<RolloverScenario>>(`/rollover-scenarios${query}`),
  get: (id: number) => apiRequest<RolloverScenario>(`/rollover-scenarios/${id}`),
  create: (input: CreateRolloverScenarioInput) => apiRequest<RolloverScenario>('/rollover-scenarios', { method: 'POST', body: JSON.stringify(input) }),
  simulate: (id: number, idempotencyKey: string) => apiRequest<RolloverScenario>(`/rollover-scenarios/${id}/simulate`, { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey } }),
  transition: (id: number, toState: ScenarioState, comment = '') => apiRequest<RolloverScenario>(`/rollover-scenarios/${id}/transition`, { method: 'POST', body: JSON.stringify({ to_state: toState, comment }) }),
  drift: (id: number) => apiRequest<SnapshotDrift>(`/rollover-scenarios/${id}/drift`),
  refreeze: (id: number) => apiRequest<RolloverScenario>(`/rollover-scenarios/${id}/refreeze`, { method: 'POST' }),
  replay: (id: number) => apiRequest<RolloverScenario>(`/rollover-scenarios/${id}/replay`, { method: 'POST' }),
  compare: (id: number, otherId: number) => apiRequest<Record<string, unknown>>(`/rollover-scenarios/${id}/compare/${otherId}`),
}

