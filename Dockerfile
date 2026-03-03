FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X main.version=${VERSION}" -o /app/intelligence-api ./cmd/api/

FROM alpine:3.21

RUN apk add --no-cache chromium
RUN mkdir -p /etc/security-accelerated
COPY --from=build /app/intelligence-api /usr/local/bin/intelligence-api

# Bake in a Docker-appropriate config
RUN printf '%s\n' \
  '---' \
  'application:' \
  '  mode: docker' \
  '  port: 8080' \
  'redis:' \
  '  addr: redis:6379' \
  '  password: ""' \
  '  db: 0' \
  '  cache_ttl: 60m' \
  'auth:' \
  '  cache_ttl: 5m' \
  'screenshot:' \
  '  timeout: 15s' \
  'typosquatting:' \
  '  timeout: 30s' \
  '  max_permutations: 500' \
  '  concurrency: 20' \
  'postgres:' \
  '  host: postgres' \
  '  port: 5432' \
  '  user: intelligence' \
  '  password: intelligence' \
  '  dbname: intelligence_api' \
  '  sslmode: disable' \
  > /etc/security-accelerated/intelligence-api.yaml

EXPOSE 8080
ENTRYPOINT ["intelligence-api"]
