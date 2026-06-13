import { useEffect, useState } from 'react'
import { api } from './api'
import type { GoEndpoint } from './api'

export function Settings() {
  const [ep, setEp] = useState<GoEndpoint | null>(null)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    api.getConfig()
      .then((c) => setEp(c.goEndpoint))
      .catch((e) => setError(e.message))
  }, [])

  if (!ep) return <div className="card">{error || 'Loading…'}</div>

  const set = (patch: Partial<GoEndpoint>) => setEp({ ...ep, ...patch })
  const setAuth = (patch: Partial<GoEndpoint['auth']>) =>
    setEp({ ...ep, auth: { ...ep.auth, ...patch } })

  const save = async () => {
    setStatus(''); setError('')
    try {
      const saved = await api.saveConfig(ep)
      setEp(saved.goEndpoint)
      setStatus('Saved to config.yaml')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="settings">
      <section className="card">
        <h2>Government Organization endpoint</h2>
        <div className="field">
          <label>Base URL</label>
          <input value={ep.baseURL} onChange={(e) => set({ baseURL: e.target.value })} />
        </div>
        <div className="field">
          <label>Presentment path</label>
          <input value={ep.presentmentPath} onChange={(e) => set({ presentmentPath: e.target.value })} />
        </div>
        <div className="field">
          <label>Update path</label>
          <input value={ep.updatePath} onChange={(e) => set({ updatePath: e.target.value })} />
        </div>
        <div className="field">
          <label>Transaction key (32 chars)</label>
          <input value={ep.transactionKey} onChange={(e) => set({ transactionKey: e.target.value })} />
        </div>
      </section>

      <section className="card">
        <h2>Authentication</h2>
        <label className="toggle">
          <input
            type="checkbox"
            checked={ep.auth.enabled}
            onChange={(e) => setAuth({ enabled: e.target.checked })}
          />
          Require auth (obtain bearer token before presentment/update)
        </label>
        {ep.auth.enabled ? (
          <>
            <div className="field">
              <label>Token path</label>
              <input value={ep.auth.tokenPath} onChange={(e) => setAuth({ tokenPath: e.target.value })} />
            </div>
            <div className="field">
              <label>Client ID</label>
              <input value={ep.auth.clientId} onChange={(e) => setAuth({ clientId: e.target.value })} />
            </div>
            <div className="field">
              <label>Client secret</label>
              <input
                type="password"
                value={ep.auth.clientSecret}
                onChange={(e) => setAuth({ clientSecret: e.target.value })}
              />
            </div>
          </>
        ) : (
          <p className="muted">
            Auth disabled — presentment and update are called with no Authorization header.
          </p>
        )}
      </section>

      <p className="muted">
        Sub-institutions and services (and their collection accounts) are configured in
        <code> config.yaml</code>.
      </p>

      <div className="actions">
        <button className="primary" onClick={save}>Save settings</button>
        {status && <span className="ok">{status}</span>}
        {error && <span className="error-inline">{error}</span>}
      </div>
    </div>
  )
}
