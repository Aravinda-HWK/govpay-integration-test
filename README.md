# GovPay+ GO API (Simple)

## Run

```bash
go run ./
```

Optional environment variables:

```bash
export GOVPAY_ADDR=":8080"
export GOVPAY_BASIC_USER="govpay"          # local mock-token mode only
export GOVPAY_BASIC_PASS="govpay"          # local mock-token mode only
export GOVPAY_TOKEN_TTL_SECONDS=3600       # local mock-token mode only

# --- IDP (OAuth2) integration — set these to use a real identity provider ---
export GOVPAY_IDP_TOKEN_URL="https://apis.leco.lk/oauth2/token"   # enables token proxy
export GOVPAY_IDP_JWKS_URL="https://apis.leco.lk/oauth2/jwks"     # enables token validation
export GOVPAY_IDP_ISSUER="https://mgt.apig.leco.lk:443/oauth2/token"  # optional "iss" check
export GOVPAY_IDP_AUDIENCE="<client_id>"                          # optional "aud" check
```

## IDP / token handling

The token endpoint and token validation are driven by the IDP env vars above:

- **`/generatetoken`** — if `GOVPAY_IDP_TOKEN_URL` is set, the request is **proxied** to the
  IDP: the caller's `Authorization: Basic <client_id:client_secret>` header is forwarded and a
  `grant_type=client_credentials` body is sent, and the IDP's token response is relayed back. If
  it is not set, a local mock token is issued (validated against `GOVPAY_BASIC_USER/PASS`).
- **`/presentment` and `/update`** — if `GOVPAY_IDP_JWKS_URL` is set, the `Bearer` token is
  validated as an **RS256 JWT** against the IDP's JWKS (signature, `exp`/`nbf`, and the optional
  `iss`/`aud` claims). Invalid or expired tokens return `401`. JWKS keys are cached and refreshed
  (15-min TTL, plus on unknown `kid` for key rotation). If it is not set, any non-empty bearer
  token is accepted (local development).

Notes:
- The presentment request's `data[]` must contain exactly one item named `refNo`.
  `refNo` is **alphanumeric** (`[A-Za-z0-9]`, type `an`) with a **max length of 20**.
  Any other shape returns `400 bad_request`.
- GovPay+ sends only the `refNo`; the GO responds with the fields to display in the UI
  (looked up by `refNo`). The sample response includes the reference number, payer details,
  and the **amount to pay** (`paramName` `amount`, returned in the subsequent update request).
- Payment update response echoes request `data[]` and adds receipt/status labels.

## Endpoints

When deployed on OpenShift the service is exposed over **HTTPS** through an edge-terminated
`Route` (see [OpenShift (HTTPS)](#openshift-https) below). Set `BASE_URL` to your route host:

```bash
# Deployed on OpenShift (HTTPS):
export BASE_URL="https://$(oc get route govpay -n govpay -o jsonpath='{.spec.host}')"

# Or local development (HTTP):
# export BASE_URL="http://localhost:8080"
```

> The examples below use `curl -k` to skip cert verification, which is convenient with the
> cluster's default ingress certificate. Drop `-k` if your route uses a trusted certificate.

### Generate token

```bash
curl -k -X POST "${BASE_URL}/api/govpayplus/v1.0/generatetoken" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(printf 'govpay:govpay' | base64)" \
  --data-urlencode "grant_type=client_credentials"
```

### Payment data presentment

```bash
curl -k -X POST "${BASE_URL}/api/govpayplus/v1.0/presentment" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-token" \
  -H "TransactionKey: demo-transaction-key" \
  -d '{
    "transactionId": "60562345678995555",
    "subinstId": "001",
    "serviceId": "001",
    "serviceName": "Tax Payment",
    "data": [
      {"seq": "1", "paramName": "refNo", "value": "ABC123456"}
    ]
  }'
```

### Payment update

```bash
curl -k -X POST "${BASE_URL}/api/govpayplus/v1.0/update" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer demo-token" \
  -H "TransactionKey: demo-transaction-key" \
  -d '{
    "transactionId": "60562345678995555",
    "subinstId": "001",
    "serviceId": "001",
    "serviceName": "Tax Payment",
    "data": [
      {"seq": "1", "paramName": "tin", "value": "123456"},
      {"seq": "2", "paramName": "amount", "value": 1000.00},
      {"seq": "3", "paramName": "tenor", "value": "3"}
    ]
  }'
```

## OpenShift (HTTPS)

The Helm chart exposes the service through an OpenShift `Route` with **edge TLS
termination**, so the public endpoint is `https://`. TLS is terminated at the
router using the cluster's default ingress certificate; traffic from the router
to the pod stays plain HTTP on `service.port` (the Go app itself serves HTTP).
Plain HTTP requests are redirected to HTTPS via
`route.tls.insecureEdgeTerminationPolicy: Redirect`.

To override TLS behaviour, set values in `helm/govpay/values.yaml` under `route.tls`.
