import { AcUnitRounded, DifferenceRounded, HistoryRounded, RefreshRounded } from '@mui/icons-material'
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, IconButton, Table, TableBody, TableCell, TableHead, TableRow, Tooltip, Typography } from '@mui/material'
import { useState } from 'react'
import type { ScenarioDrift, ScenarioDriftChange } from '../../types/rollover-scenario'
import { formatDateTime } from '../../utils/date'

const entityLabels: Record<ScenarioDriftChange['entity_type'], string> = {
  trust_anchor: '信任锚',
  certificate_chain: '证书链',
  dependent_service: '依赖服务',
}
const kindLabels: Record<ScenarioDriftChange['kind'], { label: string; tone: 'is-danger' | 'is-warning' | 'is-good' }> = {
  added: { label: '新增', tone: 'is-warning' },
  removed: { label: '移除', tone: 'is-danger' },
  modified: { label: '变更', tone: 'is-warning' },
}
const fieldLabels: Record<string, string> = {
  existence: '存在性',
  state: '生命周期状态',
  revoked: '吊销标记',
  not_before: '生效时间',
  not_after: '到期时间',
  anchor_id: '信任锚引用',
  leaf_subject: '叶子主题',
  validation_valid: '离线校验结果',
  valid_from: '有效期开始',
  valid_to: '有效期结束',
  chain_id: '证书链引用',
  client_trust_refs: '客户端信任集合',
  dependency_edges: '服务依赖边',
  criticality: '关键级别',
}

export function fieldLabel(field: string) {
  return fieldLabels[field] ?? field
}

interface DriftPanelProps {
  report: ScenarioDrift | null
  loading: boolean
  error: string
  checkedAt: string
  historical: boolean
  canRefreeze: boolean
  onRefresh: () => void
  onRefreeze: () => Promise<void>
  refreezing: boolean
}

export function DriftPanel({ report, loading, error, checkedAt, historical, canRefreeze, onRefresh, onRefreeze, refreezing }: DriftPanelProps) {
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const drifted = report?.drifted ?? false
  const blocked = report?.blocked_action === 'start_execution'

  const confirmRefreeze = async () => {
    setBusy(true)
    try {
      await onRefreeze()
      setConfirmOpen(false)
    } finally {
      setBusy(false)
    }
  }

  return <Box className="drift-panel">
    <Box className="drift-panel-head">
      <Box>
        <Typography className="eyebrow">FROZEN SNAPSHOT RECONCILIATION</Typography>
        <Typography variant="h3">冻结核对：当前资产 vs 冻结内容</Typography>
        {checkedAt && <Typography component="small">最近核对 {formatDateTime(checkedAt)}</Typography>}
      </Box>
      <Box className="drift-panel-actions">
        {historical && <Chip className="historical-chip" icon={<HistoryRounded />} label="历史记录 · 保留原快照" color="default" />}
        <Tooltip title="重新核对当前资产"><span><IconButton onClick={onRefresh} disabled={loading} aria-label="重新核对冻结一致性"><RefreshRounded className={loading ? 'spin' : ''} /></IconButton></span></Tooltip>
      </Box>
    </Box>
    {error && <Alert severity="error" onClose={() => undefined}>{error}</Alert>}
    {!report && loading && <Alert severity="info">正在核对信任锚、证书链与服务依赖…</Alert>}
    {report && !drifted && <Alert severity="success" icon={<AcUnitRounded fontSize="inherit" />}>当前信任锚、证书链与服务依赖与冻结快照一致，可按状态机继续演练流程。</Alert>}
    {report && drifted && <>
      <Alert
        severity={historical ? 'info' : 'error'}
        icon={historical ? <HistoryRounded fontSize="inherit" /> : <DifferenceRounded fontSize="inherit" />}
      >
        {historical
          ? '该场景已完成独立复核。冻结后资产已发生变化，原快照与推演结果作为历史记录保留，不参与新演练。'
          : blocked
            ? `检测到 ${report.changes.length} 项资产变化，已阻止“记录演练开始”。请按当前资产重新冻结后重新运行推演。`
            : `检测到 ${report.changes.length} 项资产变化；进入演练前必须重新冻结。`}
      </Alert>
      <Box className="drift-change-table">
        <Table size="small">
          <TableHead><TableRow><TableCell>资产</TableCell><TableCell>编号</TableCell><TableCell>变化类型</TableCell><TableCell>变化项</TableCell></TableRow></TableHead>
          <TableBody>
            {report.changes.map((change) => <TableRow key={`${change.entity_type}-${change.entity_id}-${change.kind}`}>
              <TableCell>{entityLabels[change.entity_type]}</TableCell>
              <TableCell><strong>{change.entity_code || `#${change.entity_id}`}</strong></TableCell>
              <TableCell><Chip size="small" className={`drift-kind ${kindLabels[change.kind].tone}`} label={kindLabels[change.kind].label} /></TableCell>
              <TableCell>{change.fields.map(fieldLabel).join('、')}</TableCell>
            </TableRow>)}
          </TableBody>
        </Table>
      </Box>
      {report.field_changes.length > 0 && <Box className="drift-field-list">
        {report.field_changes.map((item, index) => <Box key={`${item.field}-${index}`} className="drift-field-row">
          <span>{item.field}</span>
          <code>{item.before || '∅'}</code>
          <span className="drift-arrow">→</span>
          <code>{item.after || '∅'}</code>
        </Box>)}
      </Box>}
      {!historical && canRefreeze && <Box className="drift-refreeze-bar">
        <Button variant="contained" color="warning" startIcon={<AcUnitRounded />} disabled={refreezing || busy} onClick={() => setConfirmOpen(true)}>
          {refreezing || busy ? '正在重新冻结…' : '按当前资产重新冻结'}
        </Button>
        <Typography component="small">重新冻结会清空旧推演结果（断裂路径、证据、幂等键与回滚记录），场景回到草稿。</Typography>
      </Box>}
    </>}
    <Dialog open={confirmOpen} onClose={() => !busy && setConfirmOpen(false)}>
      <DialogTitle>按当前资产重新冻结？</DialogTitle>
      <DialogContent>
        <DialogContentText>
          将使用当前信任锚、证书链和服务依赖重新生成冻结快照与输入哈希。旧的推演结果会被清空，场景回到草稿状态，需要重新运行离线推演。
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setConfirmOpen(false)} disabled={busy}>取消</Button>
        <Button onClick={confirmRefreeze} color="warning" variant="contained" disabled={busy}>确认重新冻结</Button>
      </DialogActions>
    </Dialog>
  </Box>
}
