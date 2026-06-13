import { useState } from 'react'
import { PayFlow } from './PayFlow'
import { Settings } from './Settings'

type Tab = 'pay' | 'settings'

export default function App() {
  const [tab, setTab] = useState<Tab>('pay')
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          GovPay<span>+</span> <small>Mock</small>
        </div>
        <nav>
          <button className={tab === 'pay' ? 'active' : ''} onClick={() => setTab('pay')}>
            Pay
          </button>
          <button className={tab === 'settings' ? 'active' : ''} onClick={() => setTab('settings')}>
            Settings
          </button>
        </nav>
      </header>
      <main>{tab === 'pay' ? <PayFlow /> : <Settings />}</main>
    </div>
  )
}
