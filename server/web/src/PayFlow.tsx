import { useEffect, useMemo, useState } from 'react'
import { api, ApiError } from './api'
import type { PayResult, PresentmentResult, SubInstitution } from './api'
import { PresentmentObjects } from './PresentmentObjects'

const money = (n: number) =>
  n.toLocaleString('en-LK', { minimumFractionDigits: 2, maximumFractionDigits: 2 })

export function PayFlow() {
  const [subs, setSubs] = useState<SubInstitution[]>([])
  const [subId, setSubId] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [refNo, setRefNo] = useState('')

  const [presentment, setPresentment] = useState<PresentmentResult | null>(null)
  const [receipt, setReceipt] = useState<PayResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.getServices().then((s) => {
      setSubs(s.subInstitutions)
      if (s.subInstitutions[0]) {
        setSubId(s.subInstitutions[0].id)
        if (s.subInstitutions[0].services[0]) setServiceId(s.subInstitutions[0].services[0].id)
      }
    }).catch((e) => setError(e.message))
  }, [])

  const selectedSub = useMemo(() => subs.find((s) => s.id === subId), [subs, subId])
  const selectedService = useMemo(
    () => selectedSub?.services.find((s) => s.id === serviceId),
    [selectedSub, serviceId],
  )

  const reset = () => {
    setPresentment(null)
    setReceipt(null)
    setError('')
  }

  const onSubChange = (id: string) => {
    setSubId(id)
    const firstService = subs.find((s) => s.id === id)?.services[0]
    setServiceId(firstService ? firstService.id : '')
    reset()
  }

  const lookup = async () => {
    reset()
    if (!subId || !serviceId) {
      setError('Select a sub-institution and service')
      return
    }
    if (!refNo.trim()) {
      setError('Enter a reference number')
      return
    }
    setBusy(true)
    try {
      setPresentment(await api.presentment(subId, serviceId, refNo.trim()))
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status}: ${e.message}` : String(e))
    } finally {
      setBusy(false)
    }
  }

  const pay = async () => {
    if (!presentment) return
    setError('')
    setBusy(true)
    try {
      setReceipt(await api.pay(presentment.transactionId))
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status}: ${e.message}` : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="payflow">
      <section className="card">
        <h2>1 · Choose what to pay</h2>
        <div className="field">
          <label>Sub-institution</label>
          <select value={subId} onChange={(e) => onSubChange(e.target.value)}>
            {subs.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.id})
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Service</label>
          <select value={serviceId} onChange={(e) => { setServiceId(e.target.value); reset() }}>
            {selectedSub?.services.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.id})
              </option>
            ))}
          </select>
        </div>
        {selectedService && (
          <p className="muted">
            Payments for this service go to <strong>{selectedService.account.name}</strong> (
            {selectedService.account.number}).
          </p>
        )}
        <div className="field">
          <label>Reference number</label>
          <div className="lookup-row">
            <input
              type="text"
              placeholder="Reference number (e.g. TNSWN5RPLU44)"
              value={refNo}
              onChange={(e) => setRefNo(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && lookup()}
            />
            <button onClick={lookup} disabled={busy}>
              {busy && !presentment ? 'Looking up…' : 'Look up'}
            </button>
          </div>
        </div>
      </section>

      {error && <div className="error">{error}</div>}

      {presentment && !receipt && (
        <>
          <section className="card">
            <h2>2 · Payment details</h2>
            <p className="muted">
              Transaction {presentment.transactionId} · {presentment.subInstName} ·{' '}
              {presentment.serviceName} · {presentment.presentment.message}
            </p>
            <PresentmentObjects objects={presentment.presentment.presentmentData} />
          </section>

          <section className="card">
            <h2>3 · Confirm payment</h2>
            <div className="amount-row">
              <span>Amount to pay</span>
              <strong>LKR {money(presentment.amount)}</strong>
            </div>
            <p className="muted">
              Paying to {presentment.destAccount.name} ({presentment.destAccount.number})
            </p>
            <button
              className="primary"
              onClick={pay}
              disabled={busy || presentment.amount <= 0}
            >
              {busy ? 'Processing…' : `Pay LKR ${money(presentment.amount)}`}
            </button>
          </section>
        </>
      )}

      {receipt && (
        <section className="card success">
          <h2>✓ Payment successful</h2>
          <p className="muted">
            Transaction {receipt.transactionId} · {receipt.update.message}
          </p>
          <div className="amount-row">
            <span>Paid to {receipt.destAccount.name}</span>
            <strong>LKR {money(receipt.amount)}</strong>
          </div>
          <h3>Receipt</h3>
          <PresentmentObjects objects={receipt.update.paymentData} />
          <button onClick={() => { setRefNo(''); reset() }}>New payment</button>
        </section>
      )}
    </div>
  )
}
