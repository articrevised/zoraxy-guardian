#!/usr/bin/env bash
# Build + test + commit + push.
# Push happens only if tests pass AND build succeeds AND there are changes.
#
# Override the auto-generated commit message by passing one as an argument:
#   ./build.sh "my commit subject"
#
# Skip the push (test+build+commit locally only):
#   SKIP_PUSH=1 ./build.sh

set -euo pipefail

cd "$(dirname "$0")"

GO=${GO:-/usr/local/go/bin/go}
# Local build artifact name. NOTE: Zoraxy requires the deployed binary
# to be named "guardian" (matching the plugin folder name) — but we
# can't use that name locally because it collides with the ./guardian/
# Go package directory. When deploying, rename to "guardian":
#   cp zoraxy-guardian <zoraxy>/plugins/guardian/guardian
BINARY=zoraxy-guardian

step() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

step "go test ./..."
"$GO" test ./... || die "tests failed — not pushing"
ok "tests passed"

step "go build"
"$GO" build -o "$BINARY" . || die "build failed — not pushing"
ok "built $BINARY"

step "introspect sanity check"
./"$BINARY" -introspect >/dev/null || die "introspect failed — binary is broken"
ok "introspect ok"

# The binary itself is gitignored; .gitignore was set up so it won't be committed.

if ! git diff --quiet HEAD -- 2>/dev/null || [ -n "$(git status --porcelain)" ]; then
    step "staging changes"
    git add -A

    if git diff --cached --quiet; then
        ok "nothing to commit"
    else
        MSG="${1:-build: $(date -u +%Y-%m-%dT%H:%M:%SZ)}"
        step "git commit"
        git commit -m "$MSG" || die "commit failed"
        ok "committed"
    fi
else
    ok "no changes to commit"
fi

if [ "${SKIP_PUSH:-0}" = "1" ]; then
    ok "SKIP_PUSH set; skipping push"
    exit 0
fi

step "git push"
git push -u origin main || die "push failed"
ok "pushed to origin/main"
