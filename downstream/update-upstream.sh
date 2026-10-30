#!/bin/bash
# Move rustls-ffi-quic to a new release of rustls-ffi.
#
#   downstream/update-upstream.sh [--no-test] <upstream tag>      for example: v0.15.8
#
# What main is: the upstream release, then our commits. The commit that renames the exported functions is not
# really ours: it is what downstream/rename-symbols.py makes of the sources. So the move takes the commits
# of main since the upstream release it stands on, except the renaming (and the commits that change nothing
# but downstream/rename-symbols.py: its latest version is used), puts them on the new release, and runs the
# renaming again. What the renaming commit has besides what the script writes (the text of docs/, say) is
# applied again as a patch. main is not touched: all of it happens on the branch update/<tag>, to be looked
# at, tested and then made the new main by hand (the commands are printed at the end).
#
# A cherry-pick that conflicts only in librustls/src/rustls.h is settled by making the header again with
# cbindgen (it is generated). Any other conflict stops the move, with the branch left as it is, and the
# way back is printed. Needs: git, cbindgen (cargo install cbindgen), cargo for the tests.
set -euo pipefail

run_tests=yes
if [ "${1:-}" = "--no-test" ]; then
    run_tests=no
    shift
fi
tag=${1:?usage: $0 [--no-test] <upstream tag, for example v0.15.8>}
branch=update/$tag
rename_subject="Rename the exported functions with a prefix of their own"

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
[ -n "${UPDATE_UPSTREAM_ANY_DIRECTION:-}" ] || git merge-base --is-ancestor "$old" "$new" || { echo "$tag does not come after $(git describe --tags --always "$old")" >&2; exit 1; }
[ "$old" != "$new" ] || { echo "main already stands on $tag" >&2; exit 1; }
echo "main stands on $(git describe --tags --always "$old") ($old); moving to $tag ($new)"

# what to carry over: every commit since $old but the renaming
carry=()
rename_commit=
for c in $(git rev-list --reverse "$old..HEAD"); do
    if [ "$(git log -1 --format=%s "$c")" = "$rename_subject" ]; then
        rename_commit=$c
    elif [ "$(git diff-tree --no-commit-id --name-only -r "$c")" = "downstream/rename-symbols.py" ]; then
        :   # a change of the renaming script: it comes with the script, which is copied below
    else
        carry+=("$c")
    fi
done
[ -n "$rename_commit" ] || { echo "no commit with the subject '$rename_subject' on main" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "HEAD:downstream/rename-symbols.py" > "$tmp/rename-symbols.py"
git log -1 --format=%B "$rename_commit" > "$tmp/rename-message"
# the hand-written part of the renaming commit: what is not in the places the script writes to
git diff "$rename_commit^" "$rename_commit" -- . ':!librustls' ':!tools' ':!website/content' \
    ':!downstream/rename-symbols.py' > "$tmp/rename-by-hand.patch"
echo "carrying over ${#carry[@]} commits, then the renaming again"

make_header() { (cd librustls && cbindgen --output src/rustls.h 2>/dev/null); }

git switch --quiet -c "$branch" "$new"
for c in "${carry[@]}"; do
    subject=$(git log -1 --format=%s "$c")
    if git cherry-pick --allow-empty "$c" >/dev/null 2>&1; then
        echo "  picked   $subject"
        continue
    fi
    conflicted=$(git diff --name-only --diff-filter=U)
    if [ "$conflicted" = "librustls/src/rustls.h" ]; then
        git checkout --ours -- librustls/src/rustls.h   # "ours" is the new release here
        make_header
        git add librustls/src/rustls.h
        GIT_EDITOR=true git cherry-pick --continue >/dev/null
        echo "  picked   $subject (rustls.h made again)"
    else
        echo "conflict in: $conflicted" >&2
        echo "stopped at: $subject" >&2
        echo "settle it by hand and go on with 'git cherry-pick --continue', or go back: git cherry-pick --abort; git switch main; git branch -D $branch" >&2
        exit 1
    fi
done

# the header that the carried sources give must be the one that is committed
make_header
if ! git diff --quiet; then
    git commit --quiet -am "Make src/rustls.h again with cbindgen"
    echo "  made     src/rustls.h again (the release changed what the carried code gives)"
fi

# the renaming: the script of main (it is in the commit that is not carried)
mkdir -p downstream
cp "$tmp/rename-symbols.py" downstream/rename-symbols.py
chmod +x downstream/rename-symbols.py
downstream/rename-symbols.py
if [ -s "$tmp/rename-by-hand.patch" ]; then
    git apply --3way "$tmp/rename-by-hand.patch" || { echo "the hand-written part of the renaming commit does not apply: $tmp/rename-by-hand.patch" >&2; exit 1; }
    echo "  applied  the hand-written part of the renaming commit ($(git apply --numstat "$tmp/rename-by-hand.patch" | awk '{print $3}' | tr '\n' ' '))"
fi
make_header
git add -A
git commit --quiet -F "$tmp/rename-message"
echo "  renamed  (downstream/rename-symbols.py, rustls.h made again)"
downstream/rename-symbols.py --check >/dev/null || { echo "the renaming is not stable: a second run changes something" >&2; exit 1; }

if [ "$run_tests" = yes ]; then
    echo "running the tests (cargo test --features aws-lc-rs) ..."
    cargo test --features aws-lc-rs 2>&1 | rg '^(test result|error|test .*FAILED)' || true
fi

n=1
while git rev-parse -q --verify "refs/tags/$tag+quic$n" >/dev/null; do n=$((n + 1)); done
cat <<DONE

On $branch now: $(git rev-list --count "$new..HEAD") commits on $tag. Look at it (git log --oneline $new..HEAD), then:

  git switch main && git reset --hard $branch      # the new main
  git tag $tag+quic$n                              # the commit the debs are built from
  git push --force-with-lease origin main $tag+quic$n

and in the APT packaging (packaging/rustls-ffi-quic): version= and srcversion= in build.sh, a changelog entry,
./build.sh fetch $tag+quic$n, ./build.sh build (see docs/design.md, "Following upstream").
DONE
