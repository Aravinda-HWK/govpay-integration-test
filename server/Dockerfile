# Stage 1: build the React UI (output to web/dist, embedded by the Go binary).
FROM node:20 AS ui
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build the Go server, embedding the UI from stage 1.
FROM golang:1.21 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/govpay-server .

# Stage 3: minimal runtime. Frontend + backend run from this single binary.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/govpay-server /govpay-server
COPY --from=build /src/config.yaml /config.yaml
ENV GOVPAY_CONFIG=/config.yaml
USER nonroot:nonroot
EXPOSE 9091
ENTRYPOINT ["/govpay-server"]
