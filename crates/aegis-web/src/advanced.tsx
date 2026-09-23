import { useEffect, useState } from 'react'
import {
  ApiError,
  addPolicy,
  auditLog,
  listPolicies,
  removePolicy,
  rotateHostKey,
  type AuditEntry,
  type Host,
  type Policy,
} from './api'

const TABS = ['Policies', 'Audit log', 'Key rotation'] as const
type Tab = (typeof TABS)[number]

function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [name, setName] = useState('')
  const [cron, setCron] = useState('0 3 * * *')
  const [paths, setPaths] = useState('')
  const [retention, setRetention] = useState('{"keep_last": 10}')
  const [bandwidth, setBandwidth] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [ok, setOk] = useState<string | null>(null)

  const refresh = async () => {
    try {
      setPolicies(await listPolicies())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load policies')
    }
  }
  useEffect(() => { refresh() }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null); setOk(null)
    try {
      await addPolicy({
        name,
        schedule_cron: cron,
        retention_json: retention,
        paths_json: JSON.stringify(paths.split('\n').map((p) => p.trim()).filter(Boolean)),
      })
      setOk(`policy "${name}" created`)
      setName('')
      refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to add policy')
    }
  }

  const doRemove = async (id: string) => {
    try { await removePolicy(id); refresh() } catch (err) { setError(String(err)) }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="space-y-3 rounded-lg bg-neutral-900 p-5">
        <h3 className="font-medium">New policy</h3>
        <div className="flex gap-2">
          <input className="input" placeholder="name" value={name} onChange={(e) => setName(e.target.value)} required />
          <input className="input" placeholder="cron (e.g. 0 3 * * *)" value={cron} onChange={(e) => setCron(e.target.value)} required />
        </div>
        <textarea
          className="input h-16 font-mono text-xs"
          placeholder="absolute remote paths, one per line"
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          required
        />
        <div className="flex gap-2">
          <input className="input" placeholder='retention JSON ({"keep_last": 10})' value={retention} onChange={(e) => setRetention(e.target.value)} />
          <input className="input" placeholder="bandwidth limit kbps (optional)" value={bandwidth} onChange={(e) => setBandwidth(e.target.value)} />
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        {ok && <p className="text-sm text-green-400">{ok}</p>}
        <button className="rounded bg-blue-600 px-3 py-1.5 text-sm hover:bg-blue-500" disabled={!name || !paths}>
          Create policy
        </button>
      </form>

      <table className="w-full text-sm">
        <thead className="text-left text-neutral-400">
          <tr><th className="py-2">Name</th><th>Schedule</th><th>Enabled</th><th></th></tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.id} className="border-t border-neutral-800">
              <td className="py-2">{p.name}</td>
              <td><code className="text-xs">{p.schedule_cron}</code></td>
              <td>{p.enabled ? 'yes' : 'no'}</td>
              <td className="text-right">
                <button onClick={() => doRemove(p.id)} className="text-red-400 hover:underline">remove</button>
              </td>
            </tr>
          ))}
          {policies.length === 0 && (
            <tr><td colSpan={4} className="py-4 text-center text-neutral-500">no policies yet</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    auditLog().then(setEntries).catch((err) =>
      setError(err instanceof ApiError ? err.message : 'failed to load audit log'),
    )
  }, [])

  return (
    <div className="space-y-2">
      {error && <p className="text-sm text-red-400">{error}</p>}
      <table className="w-full text-sm">
        <thead className="text-left text-neutral-400">
          <tr><th className="py-2">Time</th><th>Action</th><th>Detail</th><th>User</th></tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className="border-t border-neutral-800">
              <td className="py-2 whitespace-nowrap">{new Date(e.created_at * 1000).toLocaleString()}</td>
              <td><code className="text-xs">{e.action}</code></td>
              <td className="text-neutral-400">{e.detail ?? ''}</td>
              <td className="text-neutral-500">{e.user_id?.slice(0, 8) ?? '—'}</td>
            </tr>
          ))}
          {entries.length === 0 && (
            <tr><td colSpan={4} className="py-4 text-center text-neutral-500">no audit entries</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function KeyRotation({ hosts }: { hosts: Host[] }) {
  const [hostId, setHostId] = useState('')
  const [pem, setPem] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [ok, setOk] = useState(false)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null); setOk(false)
    try {
      await rotateHostKey(hostId, pem)
      setOk(true)
      setPem('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'rotation failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="max-w-xl space-y-3 rounded-lg bg-neutral-900 p-5">
      <h3 className="font-medium">Rotate host SSH key</h3>
      <p className="text-sm text-neutral-400">
        Replaces the stored (envelope-encrypted) private key for the host. The new
        key's public half must already be in the host's authorized_keys.
      </p>
      <select className="input" value={hostId} onChange={(e) => setHostId(e.target.value)} required>
        <option value="">choose host…</option>
        {hosts.map((h) => (
          <option key={h.id} value={h.id}>{h.name}</option>
        ))}
      </select>
      <textarea
        className="input h-32 font-mono text-xs"
        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
        value={pem}
        onChange={(e) => setPem(e.target.value)}
        required
      />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {ok && <p className="text-sm text-green-400">key rotated</p>}
      <button className="rounded bg-blue-600 px-3 py-1.5 text-sm hover:bg-blue-500 disabled:opacity-50" disabled={busy || !hostId || !pem}>
        {busy ? 'Rotating…' : 'Rotate key'}
      </button>
    </form>
  )
}

export default function Advanced({ hosts }: { hosts: Host[] }) {
  const [tab, setTab] = useState<Tab>('Policies')
  return (
    <section className="space-y-4">
      <div className="flex gap-2">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded px-3 py-1.5 text-sm ${tab === t ? 'bg-neutral-700 font-medium' : 'bg-neutral-900 text-neutral-400 hover:bg-neutral-800'}`}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === 'Policies' && <Policies />}
      {tab === 'Audit log' && <AuditLog />}
      {tab === 'Key rotation' && <KeyRotation hosts={hosts} />}
    </section>
  )
}
