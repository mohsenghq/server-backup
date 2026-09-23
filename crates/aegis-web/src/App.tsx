import { useEffect, useState } from 'react'
import {
  ApiError,
  addHost,
  getToken,
  listHosts,
  listJobs,
  login,
  logout,
  me,
  removeHost,
  testHost,
  triggerBackup,
  type Host,
  type Job,
  type Me,
} from './api'

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let v = n / 1024
  let u = 0
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024
    u++
  }
  return `${v.toFixed(1)} ${units[u]}`
}

function StatusPill({ status }: { status: string }) {
  const color =
    status === 'reachable'
      ? 'bg-green-900 text-green-300'
      : status === 'unreachable'
        ? 'bg-red-900 text-red-300'
        : 'bg-neutral-800 text-neutral-400'
  return <span className={`rounded-full px-2 py-0.5 text-xs ${color}`}>{status}</span>
}

function Login({ onDone }: { onDone: (user: Me) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
      onDone(await me())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <form onSubmit={submit} className="w-80 space-y-4 rounded-lg bg-neutral-900 p-6 shadow">
        <h1 className="text-xl font-semibold">Aegis</h1>
        <input
          className="w-full rounded border border-neutral-700 bg-neutral-800 px-3 py-2"
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />
        <input
          className="w-full rounded border border-neutral-700 bg-neutral-800 px-3 py-2"
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button
          className="w-full rounded bg-blue-600 px-3 py-2 font-medium hover:bg-blue-500 disabled:opacity-50"
          disabled={busy || !username || !password}
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}

function AddHostWizard({ onAdded }: { onAdded: () => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [address, setAddress] = useState('')
  const [port, setPort] = useState('22')
  const [user, setUser] = useState('root')
  const [keyPem, setKeyPem] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await addHost({
        name,
        address,
        ssh_port: Number(port) || 22,
        ssh_user: user,
        ssh_key_pem: keyPem,
      })
      setOpen(false)
      setName(''); setAddress(''); setKeyPem('')
      onAdded()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to add host')
    } finally {
      setBusy(false)
    }
  }

  if (!open)
    return (
      <button
        onClick={() => setOpen(true)}
        className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium hover:bg-blue-500"
      >
        Add host
      </button>
    )

  return (
    <form onSubmit={submit} className="w-full max-w-md space-y-3 rounded-lg bg-neutral-900 p-5">
      <h2 className="font-semibold">Add host</h2>
      <input className="input" placeholder="name" value={name} onChange={(e) => setName(e.target.value)} required />
      <input className="input" placeholder="address" value={address} onChange={(e) => setAddress(e.target.value)} required />
      <div className="flex gap-2">
        <input className="input" placeholder="port" value={port} onChange={(e) => setPort(e.target.value)} />
        <input className="input" placeholder="ssh user" value={user} onChange={(e) => setUser(e.target.value)} />
      </div>
      <textarea
        className="input h-24 font-mono text-xs"
        placeholder="OpenSSH private key PEM (optional — empty uses AEGIS_SSH_PASSWORD on the server)"
        value={keyPem}
        onChange={(e) => setKeyPem(e.target.value)}
      />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <div className="flex gap-2">
        <button className="rounded bg-blue-600 px-3 py-1.5 text-sm hover:bg-blue-500 disabled:opacity-50" disabled={busy}>
          {busy ? 'Adding…' : 'Add'}
        </button>
        <button type="button" onClick={() => setOpen(false)} className="rounded bg-neutral-700 px-3 py-1.5 text-sm hover:bg-neutral-600">
          Cancel
        </button>
      </div>
    </form>
  )
}

function RestoreBrowser({ hosts }: { hosts: Host[] }) {
  const [hostId, setHostId] = useState('')
  const [paths, setPaths] = useState('')
  const [repo, setRepo] = useState('')
  const [snapshotId, setSnapshotId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null); setSnapshotId(null)
    try {
      const res = await triggerBackup(hostId, paths.split('\n').map((p) => p.trim()).filter(Boolean), repo)
      setSnapshotId(res.snapshot_id)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'backup failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-3">
      <h2 className="font-semibold">Run backup</h2>
      <form onSubmit={submit} className="space-y-3 rounded-lg bg-neutral-900 p-5">
        <div className="flex gap-2">
          <select className="input" value={hostId} onChange={(e) => setHostId(e.target.value)} required>
            <option value="">choose host…</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>{h.name}</option>
            ))}
          </select>
          <input className="input" placeholder="repo path or sftp://…" value={repo} onChange={(e) => setRepo(e.target.value)} required />
        </div>
        <textarea
          className="input h-20 font-mono text-xs"
          placeholder="absolute remote paths, one per line (/etc, /home/…)"
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          required
        />
        {error && <p className="text-sm text-red-400">{error}</p>}
        {snapshotId && <p className="text-sm text-green-400">snapshot {snapshotId} created</p>}
        <button className="rounded bg-blue-600 px-3 py-1.5 text-sm hover:bg-blue-500 disabled:opacity-50" disabled={busy}>
          {busy ? 'Running…' : 'Run backup'}
        </button>
      </form>
    </section>
  )
}

function Dashboard({ user, onLogout }: { user: Me; onLogout: () => void }) {
  const [hosts, setHosts] = useState<Host[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [error, setError] = useState<string | null>(null)

  const refresh = async () => {
    try {
      setHosts(await listHosts())
      setJobs(await listJobs())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load')
    }
  }

  useEffect(() => { refresh() }, [])

  const doTest = async (id: string) => {
    try { await testHost(id); refresh() } catch (err) { setError(String(err)) }
  }
  const doRemove = async (id: string) => {
    try { await removeHost(id); refresh() } catch (err) { setError(String(err)) }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Aegis</h1>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-neutral-400">{user.username}</span>
          <button onClick={onLogout} className="rounded bg-neutral-800 px-3 py-1.5 hover:bg-neutral-700">
            Sign out
          </button>
        </div>
      </header>

      {error && <p className="rounded bg-red-950 p-3 text-sm text-red-300">{error}</p>}

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">Hosts ({hosts.length})</h2>
          <AddHostWizard onAdded={refresh} />
        </div>
        <table className="w-full text-sm">
          <thead className="text-left text-neutral-400">
            <tr>
              <th className="py-2">Name</th><th>Address</th><th>User</th><th>Mode</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.id} className="border-t border-neutral-800">
                <td className="py-2">{h.name}</td>
                <td>{h.address}:{h.ssh_port}</td>
                <td>{h.ssh_user}</td>
                <td>{h.mode}</td>
                <td><StatusPill status={h.status} /></td>
                <td className="space-x-2 text-right">
                  <button onClick={() => doTest(h.id)} className="text-blue-400 hover:underline">test</button>
                  <button onClick={() => doRemove(h.id)} className="text-red-400 hover:underline">remove</button>
                </td>
              </tr>
            ))}
            {hosts.length === 0 && (
              <tr><td colSpan={6} className="py-4 text-center text-neutral-500">no hosts yet — add one</td></tr>
            )}
          </tbody>
        </table>
      </section>

      <RestoreBrowser hosts={hosts} />

      <section className="space-y-3">
        <h2 className="font-semibold">Recent jobs</h2>
        <table className="w-full text-sm">
          <thead className="text-left text-neutral-400">
            <tr><th className="py-2">Started</th><th>Host</th><th>Status</th><th>Read</th><th>New</th></tr>
          </thead>
          <tbody>
            {jobs.slice(-10).reverse().map((j) => {
              const host = hosts.find((h) => h.id === j.host_id)
              return (
                <tr key={j.id} className="border-t border-neutral-800">
                  <td className="py-2">{new Date(j.started_at * 1000).toLocaleString()}</td>
                  <td>{host?.name ?? j.host_id}</td>
                  <td>
                    <span className={j.status === 'completed' ? 'text-green-400' : j.status === 'failed' ? 'text-red-400' : 'text-yellow-400'}>
                      {j.status}
                    </span>
                  </td>
                  <td>{bytes(j.bytes_read)}</td>
                  <td>{bytes(j.bytes_new)}</td>
                </tr>
              )
            })}
            {jobs.length === 0 && (
              <tr><td colSpan={5} className="py-4 text-center text-neutral-500">no jobs yet</td></tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  )
}

export default function App() {
  const [user, setUser] = useState<Me | null>(null)
  const [checking, setChecking] = useState(!!getToken())

  useEffect(() => {
    if (!getToken()) return
    me().then(setUser).catch(() => {}).finally(() => setChecking(false))
  }, [])

  if (checking) return <div className="flex min-h-screen items-center justify-center text-neutral-500">…</div>
  if (!user) return <Login onDone={setUser} />
  return <Dashboard user={user} onLogout={async () => { try { await logout() } catch {} setUser(null) }} />
}
