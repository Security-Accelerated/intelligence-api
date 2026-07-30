#!/bin/sh
set -e

# Fix ownership of the MaxMind data directory, then drop privileges.
#
# A Fly volume mounts root-owned and shadows the image's build-time chown, and
# Fly exposes no uid/gid option on mounts — so a container running as a non-root
# user cannot write to its own volume until ownership is corrected from inside.
# Without this the GeoIP bootstrap fails with permission denied on every boot,
# silently: the lookup reports an error in the response and nothing degrades.
#
# Done here rather than as a one-time manual chown so that a replaced volume, an
# added machine, or a scaled-out region all work without anyone remembering.
# PID 1 is root only for these few lines; the application itself runs as appuser.
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /data/maxmind 2>/dev/null || true
    exec su-exec appuser "$@"
fi

# Already unprivileged (no volume, or an image run with a USER override).
exec "$@"
