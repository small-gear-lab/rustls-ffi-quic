#!/bin/bash
# Move main to a new release of rustls-ffi.
#
#   downstream/update-upstream.sh [--no-test] <upstream tag>      for example: v0.15.8
#
# main is the upstream release it stands on, then our commits. They are put on the new release: all of them, as
# main is in the names that upstream uses and the renaming is not part of it (it is the branch `renamed`, made again
# by downstream/make-renamed.sh). main itself is not touched: all of it happens on the branch update/<tag>, to be looked
# at and then made the new main by hand (the commands are printed at the end).
#
# A cherry-pick that conflicts only in librustls/src/rustls.h is settled by making the header again with cbindgen (it is
# generated), and a file that we delete but that the release changed (the CI of rustls-ffi, say) stays deleted. Any
# other conflict stops the move, with the branch left as it is, and the way back is printed.
# Needs: git, cbindgen (cargo install cbindgen), cargo for the tests.
set -euo pipefail

run_tests=yes
if [ "${1:-}" = "--no-test" ]; then
    run_tests=no
    shift
fi
tag=${1:?usage: $0 [--no-test] <upstream tag, for example v0.15.8>}
branch=update/$tag

cd "$(git rev-parse --show-toplevel)"
command -v cbindgen >/dev/null || { echo "cbindgen is needed: cargo install cbindgen" >&2; exit 1; }
[ "$(git branch --show-current)" = main ] || { echo "run this on main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the work tree is not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/heads/$branch" >/dev/null && { echo "branch $branch exists: delete it first" >&2; exit 1; } || true

git fetch --quiet upstream main
git fetch --quiet upstream "refs/tags/$tag:refs/tags/$tag" 2>/dev/null || true
new=$(git rev-parse --verify "refs/tags/$tag^{commit}") || { echo "no tag $tag in upstream" >&2; exit 1; }
old=$(git merge-base HEAD upstream/main)
# (UPDATE_UPSTREAM_ANY_DIRECTION=1 lets it move to an older release: for testing the script)
[ -n "${UPDATE_UPSTREAM_ANY_DIRECTION:-}" ] || git merge-base --is-ancestor "$old" "$new" || {
    echo "$tag does not come after $(git describe --tags --always "$old")" >&2; exit 1; }
[ "$old" != "$new" ] || { echo "main already stands on $tag" >&2; exit 1; }
echo "main stands on $(git describe --tags --always "$old") ($old); moving to $tag ($new)"

carry=$(git rev-list --reverse "$old..HEAD")
echo "carrying over $(echo "$carry" | wc -l) commits"

make_header() { (cd librustls && cbindgen --output src/rustls.h 2>/dev/null); }

git switch --quiet -c "$branch" "$new"
for c in $carry; do
    subject=$(git log -1 --format=%s "$c")
    if git cherry-pick --allow-empty "$c" >/dev/null 2>&1; then
        echo "  picked   $subject"
        continue
    fi
    # `UD`: we delete a file that the release changed; `UU` in rustls.h: the generated header
    others=$(git status --porcelain | awk '/^(UD|DU|AU|UA|AA|DD|UU)/ { print $2 }' | grep -v -x -e 'librustls/src/rustls.h' || true)
    deleted=$(git status --porcelain | awk '/^UD/ { print $2 }')
    header=$(git status --porcelain | awk '/^UU/ && $2 == "librustls/src/rustls.h" { print $2 }')
    if [ -n "$(echo "$others" | tr -d '[:space:]')" ] && [ "$others" != "$deleted" ]; then
        echo "conflict in: $(git diff --name-only --diff-filter=U | tr '\n' ' ')" >&2
        echo "stopped at: $subject" >&2
        echo "settle it by hand and go on with 'git cherry-pick --continue', or go back: git cherry-pick --abort; git switch main; git branch -D $branch" >&2
        exit 1
    fi
    note=
    if [ -n "$deleted" ]; then
        # shellcheck disable=SC2086
        git rm -q -- $deleted
        note=" ($(echo "$deleted" | wc -w) files the release changed stay deleted)"
    fi
    if [ -n "$header" ]; then
        git checkout --ours -- librustls/src/rustls.h   # "ours" is the new release here
        make_header
        git add librustls/src/rustls.h
        note="$note (rustls.h made again)"
    fi
    GIT_EDITOR=true git cherry-pick --continue >/dev/null
    echo "  picked   $subject$note"
done

# the header that the carried sources give must be the one that is committed
make_header
if ! git diff --quiet; then
    git commit --quiet -am "Make src/rustls.h again with cbindgen"
    echo "  made     src/rustls.h again (the release changed what the carried code gives)"
fi

if [ "$run_tests" = yes ]; then
    echo "running the tests (cargo test --features aws-lc-rs) ..."
    cargo test --features aws-lc-rs 2>&1 | grep -E '^(test result|error|test .*FAILED)' || true
fi

n=1
while git rev-parse -q --verify "refs/tags/$tag+quic$n" >/dev/null; do n=$((n + 1)); done
cat <<DONE

On $branch now: $(git rev-list --count "$new..HEAD") commits on $tag. Look at it (git log --oneline $new..HEAD), then:

  git switch main && git reset --hard $branch      # the new main
  downstream/make-renamed.sh --test                # the branch "renamed": main plus the renaming
  git tag $tag+quic$n renamed                      # the commit the debs are built from
  git push --force-with-lease origin main renamed $tag+quic$n

and in the APT packaging (packaging/rustls-ffi-quic): version= and srcversion= in build.sh, a changelog entry,
./build.sh fetch $tag+quic$n, ./build.sh build (see docs/design.md, "Following upstream").
DONE
