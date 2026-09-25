import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { DriftPanel } from './DriftPanel'
import type { ScenarioDrift } from '../../types/rollover-scenario'

const cleanReport: ScenarioDrift = {
  scenario_id: 5,
  scenario_state: 'ready',
  historical: false,
  drifted: false,
  changes: [],
  field_changes: [],
  checked_at: '2026-09-25T08:00:00Z',
  frozen_hash: 'frozen',
  current_hash: 'frozen',
}

const driftedReport: ScenarioDrift = {
  ...cleanReport,
  drifted: true,
  blocked_action: 'start_execution',
  frozen_hash: 'frozen',
  current_hash: 'current',
  changes: [
    { entity_type: 'dependent_service', entity_id: 2, entity_code: 'PAYMENTS-API', kind: 'modified', fields: ['client_trust_refs'] },
    { entity_type: 'certificate_chain', entity_id: 9, entity_code: 'CHAIN-9', kind: 'removed', fields: ['existence'] },
  ],
  field_changes: [
    { field: 'dependent_service#2 PAYMENTS-API.client_trust_refs', before: '[1,2]', after: '[1]' },
  ],
}

describe('DriftPanel', () => {
  it('shows the clean state and no refreeze action when assets match the freeze', () => {
    render(<DriftPanel report={cleanReport} loading={false} error="" checkedAt="2026-09-25T08:00:00Z" historical={false} canRefreeze onRefresh={vi.fn()} onRefreeze={vi.fn()} refreezing={false} />)
    expect(screen.getByText(/与冻结快照一致/)).toBeInTheDocument()
    expect(screen.queryByText('按当前资产重新冻结')).not.toBeInTheDocument()
  })

  it('lists changes, explains the blocked drill start, and confirms refreeze', async () => {
    const onRefreeze = vi.fn().mockResolvedValue(undefined)
    render(<DriftPanel report={driftedReport} loading={false} error="" checkedAt="2026-09-25T08:00:00Z" historical={false} canRefreeze onRefresh={vi.fn()} onRefreeze={onRefreeze} refreezing={false} />)
    expect(screen.getByText(/已阻止“记录演练开始”/)).toBeInTheDocument()
    expect(screen.getByText('PAYMENTS-API')).toBeInTheDocument()
    expect(screen.getByText('CHAIN-9')).toBeInTheDocument()
    expect(screen.getByText('客户端信任集合')).toBeInTheDocument()

    fireEvent.click(screen.getByText('按当前资产重新冻结'))
    expect(screen.getByText('将使用当前信任锚、证书链和服务依赖重新生成冻结快照与输入哈希。旧的推演结果会被清空，场景回到草稿状态，需要重新运行离线推演。')).toBeInTheDocument()
    fireEvent.click(screen.getByText('确认重新冻结'))
    await waitFor(() => expect(onRefreeze).toHaveBeenCalledTimes(1))
  })

  it('treats verified scenarios as read-only history', () => {
    const historicalReport: ScenarioDrift = { ...driftedReport, blocked_action: '' }
    render(<DriftPanel report={historicalReport} loading={false} error="" checkedAt="2026-09-25T08:00:00Z" historical canRefreeze onRefresh={vi.fn()} onRefreeze={vi.fn()} refreezing={false} />)
    expect(screen.getByText(/原快照与推演结果作为历史记录保留/)).toBeInTheDocument()
    expect(screen.queryByText('按当前资产重新冻结')).not.toBeInTheDocument()
  })
})
