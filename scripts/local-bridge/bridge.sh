#!/bin/sh
# Start, stop and inspect the local test bridge. See README.md.
set -eu

IMAGE=localhost/webtor-local-bridge
CONTAINER=webtor-bridge
VOLUME=webtor-bridge-data
PORT=8080
HERE=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)

running() {
    [ "$(podman inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]
}

exists() {
    podman container exists "$CONTAINER" 2>/dev/null
}

build() {
    podman build -t "$IMAGE" "$HERE"
}

fingerprint() {
    # The identity lives in the volume, so it is readable whether or not the
    # container is up; a throwaway reader avoids having to start it just to
    # answer.
    if running; then
        podman exec "$CONTAINER" awk '{print $2}' /var/lib/tor/fingerprint
    else
        podman run --rm -v "$VOLUME:/var/lib/tor" --entrypoint awk "$IMAGE" \
            '{print $2}' /var/lib/tor/fingerprint
    fi
}

start() {
    if running; then
        echo "$CONTAINER is already running" >&2
    else
        podman image exists "$IMAGE" || build
        exists && podman rm -f "$CONTAINER" >/dev/null
        # Localhost only: this bridge has no anonymity story and no business
        # being reachable from the rest of the network.
        podman run -d --name "$CONTAINER" \
            -p "127.0.0.1:$PORT:$PORT" \
            -v "$VOLUME:/var/lib/tor" \
            "$IMAGE" >/dev/null
    fi

    printf 'waiting for the bridge identity' >&2
    while ! fingerprint >/dev/null 2>&1; do
        running || { echo; echo "$CONTAINER exited; try: $0 logs" >&2; exit 1; }
        printf . >&2
        sleep 1
    done
    echo >&2

    env_lines "export "
    echo >&2
    echo "The bridge still has to reach Bootstrapped 100% before it can serve" >&2
    echo "directory data; follow it with: $0 logs" >&2
}

# `export` so that `eval "$(bridge.sh env)"` puts these in the environment a
# test actually reads, rather than in shell variables it never sees.
#
# tor writes the identity a moment after the container starts, so this can be
# asked before there is an answer. Emitting the pair with an empty fingerprint
# would export a broken config that fails later and further away, so say what
# is missing and produce nothing.
env_lines() {
    prefix=${1:-}
    identity=$(fingerprint 2>/dev/null) || identity=
    if [ -z "$identity" ]; then
        echo "no bridge identity yet: tor has not written one to $VOLUME" >&2
        return 1
    fi
    echo "${prefix}BRIDGE_URL=ws://localhost:$PORT/"
    echo "${prefix}BRIDGE_FINGERPRINT=$identity"
}

stop() {
    exists || { echo "$CONTAINER does not exist" >&2; return 0; }
    podman stop "$CONTAINER" >/dev/null
    podman rm "$CONTAINER" >/dev/null
    echo "stopped; $VOLUME keeps the identity for next time" >&2
}

status() {
    if running; then
        if podman logs "$CONTAINER" 2>&1 | grep -q 'Bootstrapped 100%'; then
            echo "running, bootstrapped"
        else
            echo "running, still bootstrapping"
        fi
        # Status reports; it does not fail because the identity is not written
        # yet, which is a normal state in the first seconds after a start.
        env_lines || true
    else
        exists && echo "created, not running" || echo "not running"
    fi
}

case "${1:-}" in
    build) build ;;
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status) status ;;
    env) env_lines "export " ;;
    fingerprint) fingerprint ;;
    logs) podman logs -f "$CONTAINER" ;;
    *)
        echo "usage: $0 {build|start|stop|restart|status|env|fingerprint|logs}" >&2
        exit 2
        ;;
esac
