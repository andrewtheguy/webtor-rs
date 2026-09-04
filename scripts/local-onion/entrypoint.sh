#!/bin/sh
set -eu

HOSTNAME_FILE=/var/lib/tor/onion/hostname

mkdir -p /var/lib/tor
chown -R debian-tor:debian-tor /var/lib/tor
chmod 700 /var/lib/tor

# The site, on the loopback port the torrc forwards the onion's port 80 to.
PORT=8000 bun /opt/sample/server.ts &

# tor writes the address once it has generated the service's key, and the
# tests have to be told it, so print it rather than making the caller dig.
(
    while [ ! -s "$HOSTNAME_FILE" ]; do
        sleep 1
    done
    echo "==================================================================="
    echo "sample onion: http://$(cat "$HOSTNAME_FILE")/"
    echo "==================================================================="
) &

# tor takes over PID 1 so the engine's `stop` reaches it directly; held as a
# background child it would never see the SIGTERM.
exec tor -f /etc/tor/torrc
