#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
vendor_root=$script_dir
version_file=$vendor_root/UPSTREAM_VERSION
mode="names"

usage() {
    echo "Usage: $0 [--compact | --diff] [--version VERSION]"
    echo
    echo "Compare the vendored Arti crates with their pristine crates.io sources."
    echo "The default version comes from $version_file."
}

if [[ ! -f $version_file ]]; then
    echo "Missing Arti version file: $version_file" >&2
    exit 1
fi

read -r version < "$version_file"

while (($#)); do
    case $1 in
        --compact)
            mode="compact"
            shift
            ;;
        --diff)
            mode="diff"
            shift
            ;;
        --version)
            if (($# < 2)); then
                echo "--version requires a value" >&2
                exit 2
            fi
            version=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n ${CARGO_HOME:-} ]]; then
    arti_cargo_home=$CARGO_HOME
else
    arti_cargo_home=${HOME:?HOME is required when CARGO_HOME is unset}/.cargo
fi

registry_src=$arti_cargo_home/registry/src

mapfile -t crates < <(
    find "$vendor_root/crates" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
)

if ((${#crates[@]} == 0)); then
    echo "No vendored crates found under $vendor_root/crates" >&2
    exit 1
fi

locate_upstream() {
    local crate=$1
    local upstream

    upstream=$(find "$registry_src" -mindepth 2 -maxdepth 2 -type d \
        -name "$crate-$version" -print -quit 2>/dev/null || true)
    if [[ -z $upstream ]]; then
        echo "Fetching $crate@$version from crates.io..." >&2
        cargo info --quiet "$crate@$version" >/dev/null
        upstream=$(find "$registry_src" -mindepth 2 -maxdepth 2 -type d \
            -name "$crate-$version" -print -quit 2>/dev/null || true)
    fi

    if [[ -z $upstream ]]; then
        echo "Could not locate the unpacked source for $crate@$version" >&2
        return 1
    fi
    if [[ ! -f $upstream/Cargo.toml.orig ]]; then
        echo "Missing pristine manifest: $upstream/Cargo.toml.orig" >&2
        return 1
    fi

    printf '%s\n' "$upstream"
}

is_registry_metadata() {
    case $1 in
        .cargo-ok|.cargo_vcs_info.json|Cargo.lock|Cargo.toml|Cargo.toml.orig)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

compare_names() {
    local crate=$1
    local upstream=$2
    local vendored=$3
    local manifest_status=0
    local modified=0
    local removed=0
    local added=0
    local file rel
    local -a changes=()

    if ! cmp -s "$upstream/Cargo.toml.orig" "$vendored/Cargo.toml"; then
        manifest_status=1
        changes+=("M Cargo.toml")
    fi

    while IFS= read -r -d '' file; do
        rel=${file#"$upstream/"}
        if is_registry_metadata "$rel"; then
            continue
        fi
        if [[ ! -f $vendored/$rel ]]; then
            ((removed += 1))
            changes+=("D $rel")
        elif ! cmp -s "$file" "$vendored/$rel"; then
            ((modified += 1))
            changes+=("M $rel")
        fi
    done < <(find "$upstream" -type f -print0 | sort -z)

    while IFS= read -r -d '' file; do
        rel=${file#"$vendored/"}
        if [[ $rel == Cargo.toml ]]; then
            continue
        fi
        if [[ ! -f $upstream/$rel ]]; then
            ((added += 1))
            changes+=("A $rel")
        fi
    done < <(find "$vendored" -type f -print0 | sort -z)

    printf '%s: manifest=%s, source/content=%d modified, %d removed, %d added\n' \
        "$crate" "$([[ $manifest_status == 1 ]] && echo modified || echo unchanged)" \
        "$modified" "$removed" "$added"

    if [[ $mode == names ]]; then
        printf '  %s\n' "${changes[@]}"
    fi
}

compare_diff() {
    local crate=$1
    local upstream=$2
    local vendored=$3

    echo "### $crate manifest"
    diff -u \
        --label "a/crates/$crate/Cargo.toml" \
        --label "b/crates/$crate/Cargo.toml" \
        "$upstream/Cargo.toml.orig" "$vendored/Cargo.toml" || true

    echo "### $crate source/content"
    diff -ruN \
        --exclude=.cargo-ok \
        --exclude=.cargo_vcs_info.json \
        --exclude=Cargo.lock \
        --exclude=Cargo.toml \
        --exclude=Cargo.toml.orig \
        "$upstream" "$vendored" || true
}

for crate in "${crates[@]}"; do
    upstream=$(locate_upstream "$crate")
    vendored=$vendor_root/crates/$crate

    if [[ $mode == diff ]]; then
        compare_diff "$crate" "$upstream" "$vendored"
    else
        compare_names "$crate" "$upstream" "$vendored"
    fi
done
