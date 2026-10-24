export const demoAuditEngine = {
  mode: 'bounded_multi_turn',
  provider: 'LLM provider contract',
  maxTurns: 6,
  concurrency: 3,
  parentTask: {
    id: 'TASK-AUDIT-0248',
    title: '支付助手权限边界审查',
    state: 'running',
    checkpoint: 'CP-AUDIT-14',
    completion: '3 / 4 contracts'
  },
  tasks: [
    { id: 'TASK-AUDIT-0248', parentId: null, lane: 'orchestrator', label: 'Parent audit task', state: 'running', turn: '4 / 6', contract: 'FinalizeAudit', checkpoint: 'CP-AUDIT-14', kind: 'parent' },
    { id: 'CHILD-WEB-031', parentId: 'TASK-AUDIT-0248', lane: 'web', label: 'Web / API audit', state: 'completed', turn: '5 / 6', contract: 'FinalizeFinding', checkpoint: 'CP-WEB-06', kind: 'child' },
    { id: 'CHILD-AGENT-032', parentId: 'TASK-AUDIT-0248', lane: 'agent', label: 'Agent security audit', state: 'running', turn: '4 / 6', contract: 'FinalizeFinding', checkpoint: 'CP-AGENT-08', kind: 'child' },
    { id: 'CHILD-SECRET-033', parentId: 'TASK-AUDIT-0248', lane: 'secret', label: 'Secrets audit', state: 'degraded', turn: '2 / 4', contract: 'FinalizeFinding', checkpoint: 'CP-SECRET-03', kind: 'child', note: 'Gitleaks adapter retry exhausted; deterministic fallback retained.' },
    { id: 'EXT-MCP', parentId: null, lane: 'mcp', label: 'MCP audit', state: 'extension', turn: '-', contract: 'Extension point', checkpoint: '-', kind: 'extension' },
    { id: 'EXT-WORKFLOW', parentId: null, lane: 'workflow', label: 'Workflow audit', state: 'extension', turn: '-', contract: 'Extension point', checkpoint: '-', kind: 'extension' }
  ],
  candidates: [
    {
      id: 'CAND-021',
      lane: 'agent',
      title: '退款工具缺少调用者权限约束',
      severity: 'critical',
      state: 'evidence_review',
      turn: 4,
      maxTurns: 6,
      signals: [
        { type: 'ToolSignal', label: 'Semgrep authorization sink', tone: 'tool' },
        { type: 'RiskHypothesis', label: 'Excessive agency path', tone: 'hypothesis' },
        { type: 'Source exploration', label: '3 files / 2 call sites', tone: 'source' }
      ],
      transcript: [
        { actor: 'AuditAgent', type: 'observe', title: 'Candidate observed', detail: '工具参数来自模型输出，影响高权限退款操作。', time: '14:25:08' },
        { actor: 'read_source', type: 'tool', title: 'Read-only tool call', detail: 'src/tools/refund.ts:62-101 · artifact://RUN-0248/SRC-41', time: '14:25:31' },
        { actor: 'surface_lookup', type: 'tool', title: 'Runtime surface lookup', detail: 'agent-core → refund_order → POST /refund', time: '14:26:02' },
        { actor: 'ReasoningGuard', type: 'guard', title: 'Completion blocked', detail: '缺少服务端所有权校验的反证或运行证据。', time: '14:26:26' },
        { actor: 'AuditAgent', type: 'reconcile', title: 'Evidence reconciled', detail: '静态证据支持边界缺失；动态影响交由 Verification child。', time: '14:27:04' }
      ],
      contract: [
        { label: 'Candidate classification', state: 'done' },
        { label: 'Evidence refs bound', state: 'done' },
        { label: 'Contradictions recorded', state: 'done' },
        { label: 'Evidence gaps declared', state: 'done' },
        { label: 'FinalizeFinding called', state: 'waiting' }
      ]
    },
    {
      id: 'CAND-018',
      lane: 'web',
      title: '客户端价格字段可直接覆盖',
      severity: 'medium',
      state: 'finalized',
      turn: 5,
      maxTurns: 6,
      signals: [
        { type: 'ToolSignal', label: 'Package audit + source sink', tone: 'tool' },
        { type: 'RiskHypothesis', label: 'Unprotected entry point', tone: 'hypothesis' },
        { type: 'Source exploration', label: '5 files / 4 call sites', tone: 'source' }
      ],
      transcript: [
        { actor: 'AuditAgent', type: 'observe', title: 'Candidate observed', detail: '客户端金额字段进入 checkout 请求。', time: '14:18:40' },
        { actor: 'read_source', type: 'tool', title: 'Cross-file trace', detail: 'checkout.ts → pricing.py → order total calculation', time: '14:19:12' },
        { actor: 'AuditAgent', type: 'reconcile', title: 'Contradiction retained', detail: '服务端存在金额一致性检查，候选降级为证据冲突。', time: '14:20:02' },
        { actor: 'FinalizeFinding', type: 'finalize', title: 'Finding finalized', detail: 'verdict=inconclusive · verification_target=L2', time: '14:20:18' }
      ],
      contract: [
        { label: 'Candidate classification', state: 'done' },
        { label: 'Evidence refs bound', state: 'done' },
        { label: 'Contradictions recorded', state: 'done' },
        { label: 'Evidence gaps declared', state: 'done' },
        { label: 'FinalizeFinding called', state: 'done' }
      ]
    },
    {
      id: 'CAND-014',
      lane: 'secret',
      title: '测试夹具中的令牌样例',
      severity: 'low',
      state: 'rejected',
      turn: 2,
      maxTurns: 4,
      signals: [
        { type: 'ToolSignal', label: 'Secret pattern match', tone: 'tool' },
        { type: 'Source exploration', label: 'Fixture provenance', tone: 'source' }
      ],
      transcript: [
        { actor: 'SecretAudit', type: 'observe', title: 'Pattern matched', detail: '测试夹具命中通用 API token 规则。', time: '14:15:07' },
        { actor: 'read_source', type: 'tool', title: 'Fixture inspected', detail: '值由固定生成器产生且仅用于离线单元测试。', time: '14:15:39' },
        { actor: 'FinalizeFinding', type: 'finalize', title: 'Candidate rejected', detail: 'verdict=false_positive · evidence retained', time: '14:15:51' }
      ],
      contract: [
        { label: 'Candidate classification', state: 'done' },
        { label: 'Evidence refs bound', state: 'done' },
        { label: 'Contradictions recorded', state: 'done' },
        { label: 'Evidence gaps declared', state: 'done' },
        { label: 'FinalizeFinding called', state: 'done' }
      ]
    }
  ],
  verificationTasks: [
    { id: 'VERIFY-F-012', parentId: 'CAND-021', title: '所有权边界动态验证', state: 'running', level: 'L3', turn: '3 / 5', contract: 'FinalizeVerification', tool: 'DockerExecutor' },
    { id: 'VERIFY-F-009', parentId: 'CAND-009', title: '间接提示注入浏览器证据', state: 'completed', level: 'L4', turn: '5 / 5', contract: 'FinalizeVerification', tool: 'BrowserExecutor' }
  ]
}

export const demoThreatModel = {
  id: 'RTM-03',
  graphVersion: 'RSG-17',
  generatedAt: '2026-07-21 14:17:42',
  deterministic: true,
  coverage: 84,
  mappedNodes: 22,
  mappedEdges: 31,
  assumptions: 6,
  evidencePredicates: 11,
  techniques: [
    { id: 'T-PI-01', label: '不可信内容提示注入', short: 'Prompt injection', state: 'modeled', hypotheses: 2, tone: 'critical' },
    { id: 'T-EA-02', label: '跨提示与工具的过度代理', short: 'Excessive agency', state: 'investigating', hypotheses: 3, tone: 'warning' },
    { id: 'T-MCP-03', label: '指令化工具描述影响选择', short: 'Tool description', state: 'modeled', hypotheses: 1, tone: 'relay' },
    { id: 'T-EP-04', label: '未保护的外部入口', short: 'External entry', state: 'partially_covered', hypotheses: 2, tone: 'focus' }
  ],
  hypotheses: [
    {
      id: 'HYP-013',
      technique: 'T-EA-02',
      title: '模型输出可直接驱动高权限退款工具',
      state: 'investigating',
      confidence: 82,
      coverage: 78,
      trustZone: 'Untrusted UI → Agent control',
      privilege: 'write · financial',
      assets: ['订单所有权', '退款额度', '支付记录'],
      threatCategories: ['Excessive agency', 'Broken authorization'],
      path: ['用户请求', 'Agent context', 'refund_order', 'POST /refund', 'Orders DB'],
      assumptions: ['refund_order 可由对话 Agent 调用', '服务端可能信任工具提供的 actor'],
      predicates: [
        { label: '非订单所有者请求被服务端拒绝', state: 'testing' },
        { label: '退款金额由服务端重新计算', state: 'missing' },
        { label: '高权限工具调用需要确认', state: 'supported' }
      ]
    },
    {
      id: 'HYP-009',
      technique: 'T-PI-01',
      title: '外部订单备注进入高权限模型上下文',
      state: 'supported',
      confidence: 91,
      coverage: 94,
      trustZone: 'External content → Model context',
      privilege: 'context influence',
      assets: ['系统指令', '工具选择策略'],
      threatCategories: ['Indirect prompt injection'],
      path: ['订单备注', '页面上下文', 'System Prompt', 'Agent decision'],
      assumptions: ['订单备注可由外部商户控制'],
      predicates: [
        { label: '外部备注被标记为不可信数据', state: 'missing' },
        { label: '恶意备注不会改变工具意图', state: 'contradicted' },
        { label: '上下文拼接路径可静态追踪', state: 'supported' }
      ]
    },
    {
      id: 'HYP-006',
      technique: 'T-MCP-03',
      title: 'MCP 工具描述包含指令式选择偏置',
      state: 'open',
      confidence: 63,
      coverage: 55,
      trustZone: 'Remote MCP metadata → Tool selector',
      privilege: 'tool selection',
      assets: ['工具路由', '网络访问策略'],
      threatCategories: ['Tool description injection'],
      path: ['MCP metadata', 'Tool registry', 'Agent selector'],
      assumptions: ['远端描述可在启动时更新'],
      predicates: [
        { label: '描述字段经过静态策略校验', state: 'missing' },
        { label: '工具选择不受描述中指令影响', state: 'testing' }
      ]
    },
    {
      id: 'HYP-003',
      technique: 'T-EP-04',
      title: '退款入口缺少明确的身份边界声明',
      state: 'supported',
      confidence: 87,
      coverage: 90,
      trustZone: 'Public API → Financial service',
      privilege: 'write · external entry',
      assets: ['退款状态机', '用户资金'],
      threatCategories: ['Unprotected entry point'],
      path: ['POST /refund', 'Refund service', 'Orders DB'],
      assumptions: ['入口对已登录客户端可达'],
      predicates: [
        { label: '路由声明鉴权依赖', state: 'missing' },
        { label: '服务层重复校验资源所有权', state: 'testing' }
      ]
    }
  ]
}

export const demoToolFabric = {
  profile: 'focused-audit-v1',
  image: 'vibesec/tools:focused',
  runtimeLocation: 'agent runtime outside container',
  permissionMode: 'read-only source + explicit verification grants',
  adapterState: 'frontend contract snapshot',
  tools: [
    { id: 'semgrep', name: 'Semgrep', category: 'SAST', enabled: true, state: 'profile_ready', mode: 'read-only', output: 'ToolSignal', artifact: 'SARIF / JSON', description: '快速规则扫描与候选定位。' },
    { id: 'gitleaks', name: 'Gitleaks', category: 'Secrets', enabled: true, state: 'profile_ready', mode: 'read-only', output: 'ToolSignal', artifact: 'JSON', description: '凭证与敏感值模式检测。' },
    { id: 'bandit', name: 'Bandit', category: 'Python SAST', enabled: true, state: 'profile_ready', mode: 'read-only', output: 'ToolSignal', artifact: 'JSON', description: 'Python 安全规则扫描。' },
    { id: 'package-audit', name: 'Package audit', category: 'SCA', enabled: true, state: 'profile_ready', mode: 'network restricted', output: 'ToolSignal', artifact: 'JSON', description: '依赖漏洞与锁文件检查。' },
    { id: 'codeql', name: 'CodeQL', category: 'Deep SAST', enabled: false, state: 'planned', mode: 'resource bounded', output: 'ToolSignal', artifact: 'SARIF', description: '深度数据流分析扩展。' },
    { id: 'trivy', name: 'Trivy', category: 'Container / SCA', enabled: false, state: 'planned', mode: 'image read-only', output: 'ToolSignal', artifact: 'JSON', description: '镜像、依赖与配置扫描扩展。' },
    { id: 'nuclei', name: 'Nuclei', category: 'Service probes', enabled: false, state: 'planned', mode: 'explicit network grant', output: 'ToolSignal', artifact: 'JSONL', description: '受控服务探测与模板执行扩展。' }
  ],
  executions: [
    { id: 'TLS-091', tool: 'Semgrep', request: 'REQ-488', state: 'completed', duration: '18.4s', signals: 7, artifacts: 2, finding: '未自动确认' },
    { id: 'TLS-088', tool: 'Gitleaks', request: 'REQ-483', state: 'degraded', duration: '30.0s', signals: 3, artifacts: 1, finding: '候选待审查' },
    { id: 'TLS-086', tool: 'Package audit', request: 'REQ-479', state: 'completed', duration: '11.2s', signals: 4, artifacts: 2, finding: '未自动确认' }
  ]
}
