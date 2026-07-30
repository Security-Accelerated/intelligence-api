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
    # Best effort: a volume already owned by appuser needs no chown, and on a
    # read-only mount this cannot succeed. The write probe below is what decides
    # whether we are actually in business, so failures here are not interesting
    # on their own.
    chown -R appuser:appuser /data/maxmind 2>/dev/null || true

    # Probe by actually writing. This tests the condition that matters instead
    # of a proxy for it: `test -w` reports success on a read-only bind mount, so
    # it would have stayed silent in precisely the case worth warning about.
    #
    # Warn rather than exit. Unwritable storage costs us geo and asn, which the
    # API is designed to tolerate: the lookup returns an error in the response
    # and health deliberately does not degrade. Refusing to boot would convert
    # one unavailable lookup into a total outage, crash-looping the machine and
    # taking domain lookups down with it. Loud in the logs, not fatal.
    if ! su-exec appuser sh -c 'touch /data/maxmind/.write-probe 2>/dev/null && rm -f /data/maxmind/.write-probe'; then
        echo "WARNING: /data/maxmind is not writable by appuser — GeoIP databases cannot be downloaded, so geo and asn will be unavailable" >&2
    fi

    exec su-exec appuser "$@"
fi

# Already unprivileged (no volume, or an image run with a USER override).
exec "$@"
