FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X main.version=${VERSION}" -o /app/intelligence-api ./cmd/api/

FROM alpine:3.21

RUN apk add --no-cache su-exec
RUN adduser -D -u 1000 appuser
RUN mkdir -p /data/geoip && chown appuser:appuser /data/geoip
COPY --from=build /app/intelligence-api /usr/local/bin/intelligence-api
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# No USER directive: the entrypoint starts as root purely to chown the mounted
# volume, then execs the application as appuser via su-exec. A Fly volume mounts
# root-owned and there is no uid/gid option on mounts, so this is the only way a
# non-root process can write to its own volume.
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["intelligence-api"]
