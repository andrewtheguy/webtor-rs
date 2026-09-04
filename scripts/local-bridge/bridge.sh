#!/bin/sh
# Start, stop and inspect the local test bridge. See README.md.
set -eu

IMAGE=localhost/webtor-local-bridge
CONTAINER=webtor-bridge
PORT=8080
HERE=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)

. "$HERE/../container-engine.sh"
require_local_engine "the bridge would be published on that host's loopback, where ws://localhost:$PORT/ cannot reach it."

running() {
    [ "$("$ENGINE" inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]
}

exists() {
    "$ENGINE" inspect --type container "$CONTAINER" >/dev/null 2>&1
}

image_exists() {
    "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1
}

build() {
    # -f: docker looks for a Dockerfile unless told otherwise.
    "$ENGINE" build -t "$IMAGE" -f "$HERE/Containerfile" "$HERE"
}

# Only answerable while the bridge is up: the identity lives in the container,
# which --rm takes away on stop.
fingerprint() {
    running || return 1
    "$ENGINE" exec "$CONTAINER" awk '{print $2}' /var/lib/tor/fingerprint
}

start() {
    if running; then
        echo "$CONTAINER is already running" >&2
    else
        image_exists || build
        exists && "$ENGINE" rm -f "$CONTAINER" >/dev/null
        # --rm: nothing about a test bridge is worth keeping between runs, and
        # a stale identity outliving the container it belongs to is a trap.
        # Localhost only: this bridge has no anonymity story and no business
        # being reachable from the rest of the network.
        "$ENGINE" run -d --rm --name "$CONTAINER" \
            -p "127.0.0.1:$PORT:$PORT" \
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
    echo "This identity is new: the bridge keeps nothing between runs, so a" >&2
    echo "fingerprint copied from a previous start is now wrong. It also has" >&2
    echo "to reach Bootstrapped 100% before it can serve directory data;" >&2
    echo "follow it with: $0 logs" >&2
}

# `export` so that `eval "$(bridge.sh env)"` puts these in the environment a
# test actually reads, rather than in shell variables it never sees.
#
# tor writes the identity a moment after the container starts, so this can be
# asked before there is an answer -- and there is no answer at all while the
# bridge is down. Emitting the pair with an empty fingerprint would export a
# broken config that fails later and further away, so say what is missing and
# produce nothing.
env_lines() {
    prefix=${1:-}
    identity=$(fingerprint 2>/dev/null) || identity=
    if [ -z "$identity" ]; then
        echo "no bridge identity: the bridge is down, or tor has not written" >&2
        echo "one yet. Try: $0 start" >&2
        return 1
    fi
    echo "${prefix}BRIDGE_URL=ws://localhost:$PORT/"
    echo "${prefix}BRIDGE_FINGERPRINT=$identity"
}

stop() {
    exists || { echo "$CONTAINER does not exist" >&2; return 0; }
    "$ENGINE" stop "$CONTAINER" >/dev/null
    # --rm clears it on stop; sweep up anything that lingered, such as a
    # container that was created but never ran and so never made that promise.
    if exists; then
        "$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    echo "stopped; its identity and directory cache went with it" >&2
}

status() {
    if running; then
        if "$ENGINE" logs "$CONTAINER" 2>&1 | grep -q 'Bootstrapped 100%'; then
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
    logs) "$ENGINE" logs -f "$CONTAINER" ;;
    *)
        echo "usage: $0 {build|start|stop|restart|status|env|fingerprint|logs}" >&2
        exit 2
        ;;
esac
