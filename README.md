# GovPay+ GO API (Simple)

## Run

```bash
go run ./
```

Optional environment variables:

```bash
export GOVPAY_ADDR=":8080"
export GOVPAY_BASIC_USER="govpay"
export GOVPAY_BASIC_PASS="govpay"
export GOVPAY_TOKEN_TTL_SECONDS=3600
```

## Endpoints

Base URL: http://localhost:8080

### Generate token

```bash
curl -X POST "http://localhost:8080/api/govpayplus/v1.0/generatetoken" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(printf 'govpay:govpay' | base64)" \
  --data-urlencode "grant_type=client_credentials"
```

### Payment data presentment

```bash
curl -X POST "http://localhost:8080/api/govpayplus/v1.0/presentment" \
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
      {"seq": "2", "paramName": "taxtype", "value": "20"}
    ]
  }'
```

### Payment update

```bash
curl -X POST "http://localhost:8080/api/govpayplus/v1.0/update" \
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
