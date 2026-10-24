import axios from 'axios'

const client = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000
})

client.interceptors.response.use(
  response => response,
  error => {
    const detail = error.response?.data?.detail || error.response?.data?.message || error.message
    error.userMessage = detail || '请求失败'
    return Promise.reject(error)
  }
)

const unwrap = response => response.data?.data ?? response.data

export const api = {
  async health() {
    return unwrap(await client.get('/health', { timeout: 5000 }))
  },

  async getProjects() {
    return unwrap(await client.get('/projects'))
  },
  async createProject(payload) {
    return unwrap(await client.post('/projects', payload))
  },
  async getProject(id) {
    return unwrap(await client.get(`/projects/${id}`))
  },

  async getAuditTasks(projectId) {
    return unwrap(await client.get('/audit-tasks', { params: projectId ? { project_id: projectId } : {} }))
  },
  async getAuditTask(id) {
    return unwrap(await client.get(`/audit-tasks/${id}`))
  },
  async createAuditTask(payload) {
    return unwrap(await client.post('/audit-tasks', payload))
  },
  async getAuditFindings(id) {
    return unwrap(await client.get(`/audit-tasks/${id}/findings`))
  },
  async getProjectFindings(id) {
    return unwrap(await client.get(`/projects/${id}/findings`))
  },
  async getAuditRemediations(id) {
    return unwrap(await client.get(`/audit-tasks/${id}/remediations`))
  },

  async buildRuntimeModel(payload) {
    return unwrap(await client.post('/vrtm/models', payload, { timeout: 120000 }))
  },
  async getLatestRuntimeModel(projectId) {
    return unwrap(await client.get('/vrtm/models/latest', { params: { project_id: projectId } }))
  },
  async getRuntimeModels(projectId) {
    return unwrap(await client.get('/vrtm/models', { params: { project_id: projectId } }))
  },

  async getHealthChecks(params = {}) {
    return unwrap(await client.get('/ai-health-checks', { params }))
  },
  async getHealthCheck(id) {
    return unwrap(await client.get(`/ai-health-checks/${id}`))
  },
  async getHealthStatistics() {
    return unwrap(await client.get('/ai-health-checks/statistics'))
  },
  async createHealthCheck(payload) {
    return unwrap(await client.post('/ai-health-checks', payload))
  },
  async runHealthCheck(id) {
    return unwrap(await client.post(`/ai-health-checks/${id}/run`))
  },
  async deleteHealthCheck(id) {
    return unwrap(await client.delete(`/ai-health-checks/${id}`))
  },

  async getTasks(params = {}) {
    return unwrap(await client.get('/tasks', { params }))
  },
  async getTask(id) {
    return unwrap(await client.get(`/tasks/${id}`))
  },
  async getTaskStatistics() {
    return unwrap(await client.get('/tasks/statistics'))
  },
  async createSourceTask(payload) {
    return unwrap(await client.post('/process-task', payload))
  },
  async resumeTask(id) {
    return unwrap(await client.post(`/tasks/${id}/resume`))
  },
  async updateTask(id, payload) {
    return unwrap(await client.put(`/tasks/${id}`, payload))
  },
  async deleteTask(id) {
    return unwrap(await client.delete(`/tasks/${id}`))
  },
  async batchDeleteTasks(ids) {
    return unwrap(await client.post('/tasks/batch-delete', { task_ids: ids }))
  },
  async getAuditResult(id) {
    return unwrap(await client.get(`/tasks/${id}/audit-result`))
  },

  async getKnowledge(params = {}) {
    return unwrap(await client.get('/vulnerability-knowledge', { params }))
  },
  async searchKnowledge(keyword) {
    return unwrap(await client.get('/vulnerability-knowledge/search', { params: { keyword } }))
  },
  async createKnowledge(payload) {
    return unwrap(await client.post('/vulnerability-knowledge', payload))
  },
  async updateKnowledge(id, payload) {
    return unwrap(await client.put(`/vulnerability-knowledge/${id}`, payload))
  },
  async deleteKnowledge(id) {
    return unwrap(await client.delete(`/vulnerability-knowledge/${id}`))
  },
  async toggleKnowledge(id, active) {
    return unwrap(await client.put(`/vulnerability-knowledge/${id}/${active ? 'activate' : 'deactivate'}`))
  },
  async updateKnowledgeReference(id, increment = true) {
    return unwrap(await client.put(`/vulnerability-knowledge/${id}/reference/${increment ? 'increment' : 'decrement'}`))
  },
  async deleteAllKnowledge() {
    return unwrap(await client.delete('/vulnerability-knowledge/all'))
  },
  async importKnowledge(file) {
    const body = new FormData()
    body.append('file', file)
    return unwrap(await client.post('/vulnerability-knowledge/import/csv', body))
  },
  async exportKnowledge() {
    return client.get('/vulnerability-knowledge/export/csv', { responseType: 'blob' })
  },

  async getModelConfigs(params = {}) {
    return unwrap(await client.get('/model-configs', { params }))
  },
  async getModelConfig(id) {
    return unwrap(await client.get(`/model-configs/${id}`))
  },
  async createModelConfig(payload) {
    return unwrap(await client.post('/model-configs', payload))
  },
  async updateModelConfig(id, payload) {
    return unwrap(await client.put(`/model-configs/${id}`, payload))
  },
  async deleteModelConfig(id) {
    return unwrap(await client.delete(`/model-configs/${id}`))
  },
  async toggleModelConfig(id, active) {
    return unwrap(await client.put(`/model-configs/${id}/${active ? 'activate' : 'deactivate'}`))
  },
  async testModelConfigConnection(id) {
    return unwrap(await client.post(`/model-configs/${id}/test-connection`, {}, { timeout: 60000 }))
  },

  async getAgentTargets(params = {}) {
    return unwrap(await client.get('/agent-targets', { params }))
  },
  async createAgentTarget(payload) {
    return unwrap(await client.post('/agent-targets', payload))
  },
  async updateAgentTarget(id, payload) {
    return unwrap(await client.put(`/agent-targets/${id}`, payload))
  },
  async deleteAgentTarget(id) {
    return unwrap(await client.delete(`/agent-targets/${id}`))
  },
  async toggleAgentTarget(id, active) {
    return unwrap(await client.put(`/agent-targets/${id}/${active ? 'activate' : 'deactivate'}`))
  },

  async getAgentScenarios(params = {}) {
    return unwrap(await client.get('/agent-scenarios', { params }))
  },
  async createAgentScenario(payload) {
    return unwrap(await client.post('/agent-scenarios', payload))
  },
  async updateAgentScenario(id, payload) {
    return unwrap(await client.put(`/agent-scenarios/${id}`, payload))
  },
  async deleteAgentScenario(id) {
    return unwrap(await client.delete(`/agent-scenarios/${id}`))
  },
  async toggleAgentScenario(id, active) {
    return unwrap(await client.put(`/agent-scenarios/${id}/${active ? 'activate' : 'deactivate'}`))
  },
  async seedAgentScenarios() {
    return unwrap(await client.post('/agent-scenarios/seed-defaults'))
  },

  async getAgentRuns(params = {}) {
    return unwrap(await client.get('/agent-test-runs', { params }))
  },
  async getAgentRunStatistics() {
    return unwrap(await client.get('/agent-test-runs/statistics'))
  },
  async getAgentRunReport(params = {}) {
    return unwrap(await client.get('/agent-test-runs/report/summary', { params }))
  },
  async createAgentRun(payload) {
    return unwrap(await client.post('/agent-test-runs', payload))
  },
  async createAgentBatch(payload) {
    return unwrap(await client.post('/agent-test-runs/batch', payload))
  },
  async deleteAgentRun(id) {
    return unwrap(await client.delete(`/agent-test-runs/${id}`))
  },
  async parseAgentTrace(payload) {
    return unwrap(await client.post('/agent-traces/parse-preview', payload))
  },
  async exportAgentRuns(params = {}) {
    return client.get('/agent-test-runs/export/csv', { params, responseType: 'blob' })
  }
}

export const saveBlob = (response, filename) => {
  const blob = response.data instanceof Blob ? response.data : new Blob([response.data])
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export default client
