# Build stage
FROM golang:1.21 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/govpay-api .

# Runtime stage
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/govpay-api /govpay-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/govpay-api"]
