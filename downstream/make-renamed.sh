#!/bin/bash
# Make the branch `renamed`: main with the exported functions renamed, as one commit on top of it.
#
#   downstream/make-renamed.sh [--test] [<source branch>]       (default: main)
#
# main is rustls-ffi with our changes in the names that upstream uses (rustls_*), so that it can be offered upstream
# as it is. The packages are built from `renamed`: its only commit is what downstream/rename-symbols.py makes of the
# sources, so the branch is made again, not rebased, whenever main has moved (the renaming conflicts with
# every change of a function). The tags that the packages are built from are put on this branch.
#
# --test also runs the tests of the renamed tree. Needs cbindgen (cargo install cbindgen).
set -euo pipefail

run_tests=no
if [ "${1:-}" = "--test" ]; then
    run_tests=yes
    shift
fi
source=${1:-main}
target=renamed

cd "$(git rev-parse --show-toplevel)"
command -v cbindgen >/dev/null || { echo "cbindgen is needed: cargo install cbindgen" >&2; exit 1; }
git rev-parse -q --verify "refs/heads/$source" >/dev/null || { echo "no branch $source" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the work tree is not clean" >&2; exit 1; }
[ "$source" != "$target" ] || { echo "the source cannot be $target" >&2; exit 1; }
start=$(git branch --show-current)

git switch --quiet -C "$target" "$source"
downstream/rename-symbols.py
(cd librustls && cbindgen --output src/rustls.h 2>/dev/null)
downstream/rename-symbols.py --check >/dev/null || { echo "the renaming is not stable: a second run changes something" >&2; git switch --quiet "$start"; exit 1; }
git add -A
git commit --quiet -F - <<'MESSAGE'
Rename the exported functions with a prefix of their own

A process can load this library next to upstream rustls-ffi (curl reaches its
TLS library through other libraries), and two libraries that export the same
function names would answer for each other. Every exported function is rustlsq_X
instead of rustls_X.

This commit is what downstream/rename-symbols.py makes of the sources of main
(downstream/make-renamed.sh makes it again whenever main has moved), with the
header made again by cbindgen. rustls_upstream_names.h maps the upstream names
to the new ones, so that C code written against rustls-ffi compiles unchanged.
The library is librustls_quic, the pkg-config module rustls-quic, the headers
are installed in rustls-quic/.
MESSAGE
echo "$target is $source plus one commit: $(git log -1 --format='%h %s')"
if [ "$run_tests" = yes ]; then
    echo "running the tests of the renamed tree ..."
    cargo test --features aws-lc-rs 2>&1 | grep -E '^(test result|error|test .*FAILED)' || true
fi
git switch --quiet "$start"
