// API client for the aegis control plane.

const TOKEN_KEY = 'aegis.token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(path, { ...init, headers })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    if (res.status === 401 && getToken()) {
      setToken(null) // session expired — force re-login
    }
    throw new ApiError(res.status, body.error ?? res.statusText)
  }
  return body as T
}

// --- Types mirroring the catalog ---

export interface Host {
  id: string
  name: string
  address: string
  ssh_port: number
  ssh_user: string
  mode: string
  status: string
  created_at: number
}

export interface Job {
  id: string
  host_id: string
  policy_id: string
  status: string
  started_at: number
  finished_at: number | null
  bytes_new: number
  bytes_read: number
}

export interface Me {
  id: string
  username: string
  role: string
}

// --- Endpoints ---

export async function login(username: string, password: string) {
  const res = await request<{ token: string; username: string }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
  setToken(res.token)
  return res
}

export const logout = () => request('/api/auth/logout', { method: 'POST' })
export const me = () => request<Me>('/api/auth/me')

export const listHosts = () => request<Host[]>('/api/hosts')

export interface AddHost {
  name: string
  address: string
  ssh_port: number
  ssh_user: string
  ssh_key_pem?: string
  mode?: string
}

export const addHost = (h: AddHost) =>
  request<Host>('/api/hosts', { method: 'POST', body: JSON.stringify(h) })

export const removeHost = (id: string) =>
  request<{ removed: boolean }>(`/api/hosts/${id}`, { method: 'DELETE' })

export const testHost = (id: string) =>
  request<{ reachable: boolean }>(`/api/hosts/${id}/test`, { method: 'POST' })

export const listJobs = () => request<Job[]>('/api/jobs')

export const triggerBackup = (host_id: string, paths: string[], repo: string) =>
  request<{ snapshot_id: string }>('/api/jobs/trigger', {
    method: 'POST',
    body: JSON.stringify({ host_id, paths, repo }),
  })

export interface JobEvent {
  event: 'started' | 'completed' | 'failed'
  job_id: string
  host_id: string
  policy_id: string
  bytes_new?: number
  bytes_total?: number
  error?: string
}

/// Subscribe to live job events over WebSocket. The bearer token is passed
/// as a query parameter (browsers can't set headers on WS upgrades).
export function subscribeJobs(onEvent: (e: JobEvent) => void): () => void {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken() ?? ''
  const ws = new WebSocket(`${proto}://${location.host}/api/jobs/ws?token=${encodeURIComponent(token)}`)
  ws.onmessage = (m) => {
    try {
      onEvent(JSON.parse(m.data) as JobEvent)
    } catch {
      // ignore malformed frames
    }
  }
  return () => ws.close()
}
