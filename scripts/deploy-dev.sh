#!/usr/bin/env bash
# DEV ONLY — builds the API image on this machine and runs the Compose stack on
# another Docker host, reached over SSH. For a workstation that builds but does
# not run the stack. Not a production deploy: that is a `v*` tag, see RELEASE.md.
#
#   ./scripts/deploy-dev.sh <ssh-host>      or: DEV_DEPLOY_HOST=<ssh-host>
#
# Only the finished image and the files Compose bind-mounts reach the host. The
# source tree and .env stay here, which is the reason this is not a
# `docker compose up --build` against a remote context: that would send the
# whole build context, .env included, to the other machine.
set -euo pipefail

cd "$(dirname "$0")/.."

HOST="${1:-${DEV_DEPLOY_HOST:-}}"
# Relative to the SSH user's home on the host. Its last component is the Compose
# project name, so keeping it equal to this directory's name lets
# `docker --context <host> compose ps` work from the checkout.
REMOTE_DIR="${DEV_DEPLOY_DIR:-docker/intelligence-api}"
CONFIG=/etc/security-accelerated/intelligence-api.yaml
TIMEOUT="${DEPLOY_TIMEOUT:-120}"
PROBE_TIMEOUT=5

if [ -z "$HOST" ]; then
    echo "usage: $0 <ssh-host>   (or set DEV_DEPLOY_HOST)" >&2
    exit 2
fi

# Every local docker call names the `default` context, which is always this
# machine's engine. Without it, a shell where `docker context use <host>` is in
# effect would build on the remote host and ship it the source after all.
# BUILDX_BUILDER is pinned for the same reason: the context picks the engine, but
# a builder selected by that variable can be a remote one, and the build context
# (.env included, .dockerignore does not exclude it) goes wherever the build runs.
local_docker() { BUILDX_BUILDER=default docker --context default "$@"; }

# DOCKER_HOST is the remaining way to move the build: the `default` context is
# whatever that variable points at. A unix socket is still this machine (rootless
# Docker, Colima), so it is left alone rather than unset; anything else is refused.
case "${DOCKER_HOST:-}" in
    "" | unix://*) ;;
    *)
        echo "error: DOCKER_HOST=$DOCKER_HOST points at another machine's engine" >&2
        echo "       the build would send it the source and .env; unset it and run again" >&2
        exit 1
        ;;
esac

REMOTE_DIR_Q=$(printf '%q' "$REMOTE_DIR")
# The timeouts are on the ssh process itself. A limit on the command run over
# there does nothing for a connection that never completes or a session that
# stops answering, and either would outlast the readiness deadline below.
remote() {
    ssh -o BatchMode=yes -o ConnectTimeout=10 \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 "$HOST" "$@"
}

VERSION=$(git describe --tags --always --dirty)
export VERSION

echo "==> Deploying $VERSION to $HOST:~/$REMOTE_DIR"

# Checked before the build so a host that was never set up fails in a second,
# not after an image transfer. The config is not installed from here: writing
# under /etc needs root on the host, and an existing file may carry edits.
if ! remote test -r "$CONFIG"; then
    echo "error: $HOST has no readable $CONFIG" >&2
    echo "       install it once with:" >&2
    echo "       ssh $HOST 'sudo mkdir -p ${CONFIG%/*} && sudo tee $CONFIG >/dev/null' < internal/config/sample-config.yml" >&2
    exit 1
fi

# An image built for another architecture loads without complaint and then fails
# to start with an exec format error. Cross-building is not attempted here (it
# needs emulation set up on this machine), so a mismatch stops before the build.
platform='{{.Server.Os}}/{{.Server.Arch}}'
local_platform=$(local_docker version -f "$platform")
remote_platform=$(remote "docker version -f '$platform'")
if [ "$local_platform" != "$remote_platform" ]; then
    echo "error: this machine builds $local_platform images, $HOST runs $remote_platform" >&2
    echo "       cross-platform builds are not supported by this script" >&2
    exit 1
fi

echo "==> Building image locally..."
local_docker compose build api
# The tag is shared by every checkout on this machine. Remember which image this
# run built, so that a build elsewhere moving the tag is caught instead of being
# shipped and reported under this run's version.
built_id=$(local_docker image inspect -f '{{.Id}}' intelligence-api)

echo "==> Shipping image..."
local_docker save intelligence-api | remote docker load
if [ "$(local_docker image inspect -f '{{.Id}}' intelligence-api)" != "$built_id" ]; then
    echo "error: the intelligence-api tag was rebuilt while this deploy was running" >&2
    echo "       the image sent to $HOST may not be this checkout's; run the deploy again" >&2
    exit 1
fi

# From the working tree, not HEAD, so these match the image just built from it.
# Extracting over the old copy leaves a file deleted here in place over there;
# Postgres only reads migrations/ when its volume is first created, so that is
# harmless for it, and the other mounts are named files.
echo "==> Syncing compose file, migrations and deploy config..."
tar -c docker-compose.yaml migrations deploy |
    remote "mkdir -p $REMOTE_DIR_Q && tar -x -C $REMOTE_DIR_Q"

# --no-build: the host has no source to build from. Compose recreates the api
# container because the image behind its tag changed.
echo "==> Starting the stack..."
remote "cd $REMOTE_DIR_Q && docker compose up -d --no-build"

# Bounded the same way as docker-reset.sh: an overall deadline, plus a timeout on
# each probe so one that hangs cannot outlive it.
echo "==> Waiting for the API to be ready..."
deadline=$((SECONDS + TIMEOUT))
until remote "curl -sf --max-time $PROBE_TIMEOUT http://localhost:8080/v1/health" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "error: api did not become ready within ${TIMEOUT}s" >&2
        echo "       check logs with: ssh $HOST docker logs intelligence-api" >&2
        exit 1
    fi
    sleep 1
done

# A healthy answer alone could come from a container still on an older image, so
# compare what is running with what was built. By content (layers and config),
# not by image ID: every build gets a new ID because its provenance attestation
# differs, while Compose rightly keeps the container when the image inside is
# byte-for-byte the same. Comparing IDs fails a rebuild of unchanged code.
content='{{json .RootFS.Layers}} {{json .Config}}'
built=$(local_docker image inspect -f "$content" "$built_id")
running=$(remote "docker image inspect -f '$content' \$(docker inspect -f '{{.Image}}' intelligence-api)")
if [ "$built" != "$running" ]; then
    echo "error: the api container on $HOST is not running the image just built" >&2
    echo "       check with: ssh $HOST docker ps -a" >&2
    exit 1
fi

echo ""
echo "==> $VERSION is running on $HOST (http://$HOST:8080)"
