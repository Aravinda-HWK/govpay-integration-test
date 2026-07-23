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

## Data encryption (spec §3)

Presentment/update payloads are encrypted end-to-end with GovPay+, per the
"Security Standards for Data Encryption" section of the spec. **This is always
on** — the GO needs its RSA private key to start.

```bash
export GOVPAY_RSA_PRIVATE_KEY_FILE="keys/go_private.pem"   # default; PEM (PKCS#8 or PKCS#1)
```

How a request is processed:

1. The `TransactionKey` header carries a 32-char AES-256 key, RSA-OAEP encrypted
   with **this GO's public key** (base64). The GO decrypts it with its private key.
2. **Every field** of each `data[]` element (`seq`, `paramName`, `value`) is
   AES-256-CBC encrypted with that key (base64). The GO decrypts them before
   validation.
3. **Every field** of each response object is encrypted with the same AES key so
   GovPay+ can decrypt it. Empty fields are encrypted as empty strings. Because
   the whole object is transmitted as encrypted strings, numeric/boolean fields
   (e.g. `maxLength`, `rows`, `isPaymentReference`) carry their string form
   (`"50"`, `"true"`) before encryption. The `returnedValue` field name is used
   on the response (per §3.4).

Failure modes follow §3.1.6: a request that fails validation returns **400**; a
`TransactionKey`/field that fails to decrypt returns **401**.

Algorithm standards (§3.2): RSA-OAEP(SHA-256)/MGF1(SHA-256)/2048 for the key;
AES-256-CBC with PKCS7 padding and IV = first 16 bytes of the AES key for the
payload.

### Generating the keypair

Private keys are **not** committed (`*_private.pem` and `client/keys/` are
git-ignored). Generate a local keypair before the first run — give the private
key to the GO here and the matching public key to the GovPay+ mock:

```bash
mkdir -p keys ../server/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/go_private.pem
openssl rsa -in keys/go_private.pem -pubout -out ../server/keys/go_public.pem
```

For OpenShift the private key is delivered via a `Secret` (`secretKeyRef`), not a
file — see the Helm chart's `encryption` values.

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
export BASE_URL="https://$(oc get route govpay -n nsw-infra-dev -o jsonpath='{.spec.host}')"

# Or local development (HTTP):
# export BASE_URL="http://localhost:8080"
```

> The examples below use `curl -k` to skip cert verification, which is convenient with the
> cluster's default ingress certificate. Drop `-k` if your route uses a trusted certificate.

### Generate token

The `Authorization` header is HTTP Basic auth carrying the IDP client credentials,
i.e. `Basic base64(client_id:client_secret)`. Supply your own credentials — do not
commit them.

```bash
# Build the Basic credential from your IDP client_id / client_secret:
export BASIC_AUTH="$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)"

curl -k -X POST "${BASE_URL}/api/govpayplus/v1.0/generatetoken" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  --data-urlencode "grant_type=client_credentials"
```

The response contains an `access_token`. Capture it and use it as the `Bearer`
token for the `/presentment` and `/update` calls below:

```bash
export ACCESS_TOKEN="$(curl -sk -X POST "${BASE_URL}/api/govpayplus/v1.0/generatetoken" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic ${BASIC_AUTH}" \
  --data-urlencode "grant_type=client_credentials" | jq -r '.access_token')"
```

### Payment data presentment

```bash
curl -k -X POST "${BASE_URL}/api/govpayplus/v1.0/presentment" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "TransactionKey: demo-transaction-key" \
  -d '{
    "transactionID": "60562345678995555",
    "subinstId": "001",
    "serviceid": "001",
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
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "TransactionKey: demo-transaction-key" \
  -d '{
    "transactionID": "60562345678995555",
    "subinstId": "001",
    "serviceid": "001",
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
