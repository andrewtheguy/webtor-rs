#!/bin/sh
set -eu

FINGERPRINT_FILE=/var/lib/tor/fingerprint

mkdir -p /var/lib/tor
chown -R debian-tor:debian-tor /var/lib/tor
chmod 700 /var/lib/tor

# tor generates the RSA identity on first start and webtor has to be told it,
# so print it instead of making the caller go digging for the file. A named
# volume keeps it stable across runs; without one it changes every start and
# the client config goes stale.
(
    while [ ! -s "$FINGERPRINT_FILE" ]; do
        sleep 1
    done
    echo "==================================================================="
    echo "bridge fingerprint: $(awk '{print $2}' "$FINGERPRINT_FILE")"
    echo "bridge websocket:   ws://localhost:8080/"
    echo "==================================================================="
) &

# tor takes over PID 1 so the engine's `stop` reaches it directly. Held as a
# background child instead, it never sees the SIGTERM and every stop costs the
# ten second wait for SIGKILL.
exec tor -f /etc/tor/torrc
