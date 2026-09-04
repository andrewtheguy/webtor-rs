# Sourced by the container scripts under scripts/: which engine to use, and a
# check that it runs on this machine. Sets ENGINE.
#
# podman or docker: the commands the scripts use are the same in both, apart
# from podman's `container exists` and `image exists`, which `inspect` stands
# in for. CONTAINER_ENGINE names one outright; otherwise the first of the two
# that answers `info` is taken, since a podman binary with no machine behind
# it is on PATH and useless on many desktops.
engine() {
    if [ -n "${CONTAINER_ENGINE:-}" ]; then
        echo "$CONTAINER_ENGINE"
        return
    fi
    for candidate in podman docker; do
        if "$candidate" info >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
    echo "neither podman nor docker is usable here; set CONTAINER_ENGINE to one that is" >&2
    exit 1
}
ENGINE=$(engine)

# Where the engine runs. An empty endpoint is the engine's own default socket;
# podman's machine and docker's desktop VM both forward from this machine's
# loopback, which is what the tcp://localhost and tcp://127.* cases allow.
endpoint() {
    case "$ENGINE" in
        docker) echo "${DOCKER_HOST:-$(docker context inspect -f '{{.Endpoints.docker.Host}}' 2>/dev/null || true)}" ;;
        *) echo "${CONTAINER_HOST:-}" ;;
    esac
}

# Whether $1 is a dotted IPv4 loopback literal, 127.x.y.z, and not merely a
# name that begins with "127.".
loopback_ipv4() {
    IFS=. read -r first second third fourth rest <<ADDRESS
$1
ADDRESS
    [ "$first" = 127 ] && [ -z "$rest" ] || return 1
    for octet in "$second" "$third" "$fourth"; do
        case "$octet" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "$octet" -le 255 ] || return 1
    done
}

# Refuse an engine on another machine. `$1` says what would go wrong there:
# a port published on that host's loopback is unreachable from this one.
require_local_engine() {
    host=$(endpoint)
    case "$host" in
        ""|unix://*|npipe://*|tcp://localhost:*|"tcp://[::1]:"*) return 0 ;;
        tcp://127.*)
            address=${host#tcp://}
            address=${address%%:*}
            loopback_ipv4 "$address" && return 0
            ;;
    esac
    echo "$ENGINE talks to $host, not to this machine: $1" >&2
    echo "Point the engine at a local endpoint." >&2
    exit 1
}
