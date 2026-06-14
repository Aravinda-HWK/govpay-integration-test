# GovPay+ Mock Server + UI

This is the **GovPay+ side** of the integration: a Go server with a React UI that
plays the role of the GovPay+ platform calling a Government Organization (GO) API.

It lets you:

- Select a **sub-institution** (e.g. FCAU, NPQS) and one of its **services**. Each service is
  bound to exactly one **collection account** in config — the payer cannot choose the
  destination account; it is fixed by the sub-institution + service.
- Enter a **reference number**, call the GO's **presentment** endpoint, and render the
  returned fields (label / textBox / comboBox / table) the way GovPay+ would display them.
- Pick a **source bank account** and run a **mock bank transfer** into that service's
  collection account, then call the GO's **update** endpoint to confirm the payment and show
  the receipt.
- Configure the **GO endpoint** — base URL, presentment/update paths, transaction key, and
  whether to call **with auth** (bearer token via the token endpoint) or **without auth** —
  from the **Settings** tab. Changes are persisted back to `config.yaml`.

Sub-institutions, services, and their collection accounts are configured in `config.yaml`.

The GO it talks to is the service in [`../client`](../client) (or any GO with the same
request/response shapes).

## Prerequisites

- Go 1.21+
- Node 18+ / npm (only to build the UI)

## Configuration — `config.yaml`

```yaml
server:
  addr: ":9091"               # GovPay+ server + UI port

goEndpoint:
  baseURL: "http://localhost:8080"
  presentmentPath: "/api/v1/payments/govpay/validate"
  updatePath: "/api/v1/payments/govpay/webhook"
  transactionKey: "12345678901234567890123456789012"
  auth:
    enabled: false            # true → obtain a bearer token before each call
    tokenPath: "/api/govpayplus/v1.0/generatetoken"
    clientId: "govpay"
    clientSecret: "govpay"

# Sub-institutions, each with services. Every service collects into one account
# (fixed; the payer cannot choose it).
subInstitutions:
  - id: "001"
    name: "FCAU"
    services:
      - id: "001"
        name: "Application Fee"
        account: { number: "1000200030004000", name: "FCAU Application Fee Collection" }
      - id: "002"
        name: "Renewal Fee"
        account: { number: "1000200030004001", name: "FCAU Renewal Collection" }
  - id: "002"
    name: "NPQS"
    services:
      - id: "001"
        name: "Certification Fee"
        account: { number: "2000300040005000", name: "NPQS Certification Collection" }

# Mock payer bank accounts (the source accounts a citizen pays from).
bank:
  accounts:
    - { number: "100100100100", name: "John Doe",      balance: 250000.00 }
    - { number: "200200200200", name: "Jane Smith",    balance: 1000000.00 }
    - { number: "300300300300", name: "Acme Pvt Ltd",  balance: 50000.00 }
```

The `goEndpoint` section is editable at runtime from the **Settings** tab. Sub-institutions,
services, and their collection accounts are edited directly in this file. Payer account
balances update in memory after each transfer and are persisted back here.

## Build & run (single binary)

The Go server embeds the built React app, so build the UI first, then run the server:

```bash
# 1. Build the UI (outputs to web/dist, which the Go server embeds)
cd web
npm install
npm run build
cd ..

# 2. Run the server (serves the UI and the API on :9091)
go run .
```

Open <http://localhost:9091>.

Override the port or config file with env vars:

```bash
GOVPAY_ADDR=":9095" GOVPAY_CONFIG="./config.yaml" go run .
```

## Develop the UI with hot reload

Run the Go API and the Vite dev server side by side. Vite proxies `/api` to the Go
server (see `web/vite.config.ts`):

```bash
# terminal 1 — Go API on :9091
go run .

# terminal 2 — Vite dev server on :5180 (proxies /api → :9091)
cd web
npm run dev
```

Open <http://localhost:5180>.

> The dev server uses port **5180** because **5173** is frequently held by Docker's
> proxy on this machine; a request to 5173 then returns Docker's `404 page not found`
> instead of reaching the backend, which surfaces in the UI as
> *"Unexpected non-whitespace character after JSON at position 4"*.

## With auth vs without auth

- **With auth** (`auth.enabled: true`): before each presentment/update, GovPay+ POSTs
  `grant_type=client_credentials` to `tokenPath` with HTTP Basic `clientId:clientSecret`,
  then sends `Authorization: Bearer <token>` on the GO calls.
- **Without auth** (`auth.enabled: false`): presentment/update are called with no
  `Authorization` header (only the `TransactionKey` header). Use this to point at a GO
  endpoint that does not require a token.

## API (consumed by the UI)

| Method | Path               | Purpose                                                        |
| ------ | ------------------ | -------------------------------------------------------------- |
| GET    | `/api/config`      | Current GO endpoint settings                                   |
| PUT    | `/api/config`      | Update GO endpoint/auth settings (persisted to `config.yaml`)  |
| GET    | `/api/services`    | Sub-institutions and their services (with collection accounts) |
| GET    | `/api/accounts`    | Mock payer source accounts                                     |
| POST   | `/api/presentment` | `{ "subInstId": "001", "serviceId": "001", "refNo": "TNSWN5RPLU44" }` → GO presentment + payable amount |
| POST   | `/api/pay`         | `{ "transactionId": "...", "fromAccount": "..." }` → transfer + GO update |

The `transactionId` returned by `/api/presentment` is passed back to `/api/pay`. If the
GO rejects the update, the mock transfer is refunded so balances stay consistent.
