#!/bin/sh
# Start, stop and inspect the sample onion. See README.md.
set -eu

IMAGE=localhost/webtor-sample-onion
CONTAINER=webtor-sample-onion
HERE=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)

. "$HERE/../container-engine.sh"

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

# Only answerable while the container is up: the service's key lives in it,
# and --rm takes it away on stop.
address() {
    running || return 1
    "$ENGINE" exec "$CONTAINER" cat /var/lib/tor/onion/hostname
}

start() {
    if running; then
        echo "$CONTAINER is already running" >&2
    else
        image_exists || build
        exists && "$ENGINE" rm -f "$CONTAINER" >/dev/null
        # --rm and no volume: the address is new on every start, and nothing
        # about a test site is worth keeping between runs. No published port
        # either; the site is reached over Tor or not at all.
        "$ENGINE" run -d --rm --name "$CONTAINER" "$IMAGE" >/dev/null
    fi

    printf 'waiting for the onion address' >&2
    while ! address >/dev/null 2>&1; do
        running || { echo; echo "$CONTAINER exited; try: $0 logs" >&2; exit 1; }
        printf . >&2
        sleep 1
    done
    echo >&2

    env_lines "export "
    echo >&2
    echo "This address is new: the site keeps no key between runs. Its tor" >&2
    echo "still has to bootstrap and publish the service's descriptor before" >&2
    echo "a client can find it, which takes a minute or so; $0 status" >&2
    echo "says when tor has bootstrapped, and a client's first request may" >&2
    echo "still have to be retried for a while after that." >&2
}

# `export` so that `eval "$(onion.sh env)"` puts this in the environment a
# test reads. Nothing is printed while there is no address to print: an empty
# SAMPLE_ONION would fail later and further away.
env_lines() {
    prefix=${1:-}
    onion=$(address 2>/dev/null) || onion=
    if [ -z "$onion" ]; then
        echo "no onion address: the container is down, or tor has not written" >&2
        echo "one yet. Try: $0 start" >&2
        return 1
    fi
    echo "${prefix}SAMPLE_ONION=http://$onion"
}

stop() {
    exists || { echo "$CONTAINER does not exist" >&2; return 0; }
    "$ENGINE" stop "$CONTAINER" >/dev/null
    if exists; then
        "$ENGINE" rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    echo "stopped; the onion address went with it" >&2
}

status() {
    if running; then
        if "$ENGINE" logs "$CONTAINER" 2>&1 | grep -q 'Bootstrapped 100%'; then
            echo "running, bootstrapped"
        else
            echo "running, still bootstrapping"
        fi
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
    address) address ;;
    logs) "$ENGINE" logs -f "$CONTAINER" ;;
    *)
        echo "usage: $0 {build|start|stop|restart|status|env|address|logs}" >&2
        exit 2
        ;;
esac
