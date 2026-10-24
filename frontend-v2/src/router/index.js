import { createRouter, createWebHistory } from 'vue-router'
const WorkspaceView = () => import('../views/WorkspaceView.vue')
const AuditEngineView = () => import('../views/AuditEngineView.vue')
const ThreatModelView = () => import('../views/ThreatModelView.vue')
const ToolFabricView = () => import('../views/ToolFabricView.vue')
const FindingsView = () => import('../views/FindingsView.vue')
const EvidenceView = () => import('../views/EvidenceView.vue')
const RemediationView = () => import('../views/RemediationView.vue')
const KnowledgeView = () => import('../views/KnowledgeView.vue')
const FoundationView = () => import('../views/FoundationView.vue')
const IntegrationsView = () => import('../views/IntegrationsView.vue')
const SettingsView = () => import('../views/SettingsView.vue')

const routes = [
  { path: '/', redirect: '/workspace' },
  { path: '/workspace', name: 'workspace', component: WorkspaceView, meta: { title: 'Harness 工作区' } },
  { path: '/audit-engine', name: 'audit-engine', component: AuditEngineView, meta: { title: 'Agentic Audit Engine' } },
  { path: '/threat-model', name: 'threat-model', component: ThreatModelView, meta: { title: '运行时威胁模型' } },
  { path: '/tool-fabric', name: 'tool-fabric', component: ToolFabricView, meta: { title: '安全工具织网' } },
  { path: '/findings', name: 'findings', component: FindingsView, meta: { title: '风险发现' } },
  { path: '/evidence', name: 'evidence', component: EvidenceView, meta: { title: '验证证据' } },
  { path: '/remediation', name: 'remediation', component: RemediationView, meta: { title: '返回与复测' } },
  { path: '/knowledge', name: 'knowledge', component: KnowledgeView, meta: { title: '安全知识库' } },
  { path: '/foundation', name: 'foundation', component: FoundationView, meta: { title: '运行与检查点' } },
  { path: '/integrations', name: 'integrations', component: IntegrationsView, meta: { title: 'Skill / CLI' } },
  { path: '/settings', name: 'settings', component: SettingsView, meta: { title: '系统设置' } }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 })
})

export default router
