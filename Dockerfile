FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X main.version=${VERSION}" -o /app/intelligence-api ./cmd/api/

FROM alpine:3.21

RUN apk add --no-cache chromium
RUN adduser -D -u 1000 appuser
COPY --from=build /app/intelligence-api /usr/local/bin/intelligence-api

USER appuser
EXPOSE 8080
ENTRYPOINT ["intelligence-api"]
