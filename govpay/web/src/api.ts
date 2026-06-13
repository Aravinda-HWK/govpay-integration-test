// API types mirror the Go server's JSON responses.

export interface ComboItem {
  id: string
  data: string
}

export interface TableCell {
  dataType?: string
  value: string
  enabled?: string
}

export interface TableData {
  header: TableCell[]
  rowData: TableCell[]
}

export interface PresentmentObject {
  objType: string
  seq: string
  id: string
  placeholder: string
  initialValue: unknown
  datatype: string
  maxLength: number
  selectionType: string
  mask: string
  notNull: string
  enabled: string
  returned: string
  rows: number
  cols: number
  returnedParam: string
  returnValue: string
  isPaymentReference?: boolean
  isPaymentAmount?: boolean
  objData: ComboItem[]
  tableData?: TableData
}

export interface PresentmentResponse {
  transactionID: string
  subinstId: string
  serviceid: string
  serviceName: string
  message: string
  presentmentData: PresentmentObject[]
}

export interface UpdateResponse {
  transactionID: string
  subinstId: string
  serviceid: string
  serviceName: string
  message: string
  paymentData: PresentmentObject[]
}

export interface Account {
  number: string
  name: string
}

export interface PresentmentResult {
  transactionId: string
  refNo: string
  amount: number
  subInstName: string
  serviceName: string
  destAccount: Account
  presentment: PresentmentResponse
}

export interface ServiceDef {
  id: string
  name: string
  account: Account
}

export interface SubInstitution {
  id: string
  name: string
  services: ServiceDef[]
}

export interface ServicesView {
  subInstitutions: SubInstitution[]
}

export interface AuthConfig {
  enabled: boolean
  tokenURL: string
  tokenPath: string
  clientId: string
  clientSecret: string
}

export interface GoEndpoint {
  baseURL: string
  presentmentPath: string
  updatePath: string
  transactionKey: string
  auth: AuthConfig
}

export interface ConfigView {
  goEndpoint: GoEndpoint
}

export interface PayResult {
  transactionId: string
  amount: number
  destAccount: Account
  update: UpdateResponse
}

class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  const text = await resp.text()
  const body = text ? JSON.parse(text) : {}
  if (!resp.ok) {
    throw new ApiError(resp.status, body.message || `request failed (${resp.status})`)
  }
  return body as T
}

export const api = {
  getConfig: () => request<ConfigView>('/api/config'),
  saveConfig: (ep: GoEndpoint) =>
    request<ConfigView>('/api/config', { method: 'PUT', body: JSON.stringify(ep) }),
  getServices: () => request<ServicesView>('/api/services'),
  presentment: (subInstId: string, serviceId: string, refNo: string) =>
    request<PresentmentResult>('/api/presentment', {
      method: 'POST',
      body: JSON.stringify({ subInstId, serviceId, refNo }),
    }),
  pay: (transactionId: string) =>
    request<PayResult>('/api/pay', {
      method: 'POST',
      body: JSON.stringify({ transactionId }),
    }),
}

export { ApiError }
