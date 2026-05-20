#!/usr/bin/env bash
# update.sh — install or update the Guardian plugin on a Zoraxy host.
#
# Run this ON THE ZORAXY HOST (the machine where the container's plugins
# directory is bind-mounted from the host filesystem).
#
# It will:
#   1. Fetch the latest binary from GitHub releases (rolling 'latest' tag).
#   2. Verify it runs (with -introspect).
#   3. Atomically swap it into <plugins-dir>/guardian/guardian.
#   4. Print a reminder to restart your Zoraxy container manually.
#
# Usage:
#   ./update.sh [--dir <plugins-dir>] [--version <tag>] [--arch <amd64|arm64|arm>]
#
# Defaults:
#   --dir       /opt/zoraxy/plugins   (override with $ZORAXY_PLUGINS_DIR)
#   --version   latest                (the rolling main-branch release)
#   --arch      auto-detected via uname -m
#
# Examples:
#   ZORAXY_PLUGINS_DIR=/srv/zoraxy/plugins ./update.sh
#   ./update.sh --dir /opt/zoraxy/plugins --version v0.2.0

set -euo pipefail

PLUGINS_DIR="${ZORAXY_PLUGINS_DIR:-/opt/zoraxy/plugins}"
VERSION="latest"
ARCH=""
REPO="articrevised/zoraxy-guardian"
PLUGIN_NAME="guardian"

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)     PLUGINS_DIR="$2"; shift 2 ;;
        --version) VERSION="$2";     shift 2 ;;
        --arch)    ARCH="$2";        shift 2 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *)         echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        armv7l|armv6l) ARCH=arm   ;;
        *) echo "unable to auto-detect architecture from $(uname -m); pass --arch" >&2; exit 1 ;;
    esac
fi

ASSET="linux_${ARCH}_guardian"
TARGET_DIR="${PLUGINS_DIR}/${PLUGIN_NAME}"
TARGET="${TARGET_DIR}/${PLUGIN_NAME}"

step() { printf "\n\033[1;34m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

step "Resolving release ${VERSION} for ${ASSET}"
if [ "$VERSION" = "latest" ]; then
    # The rolling pre-release uses tag 'latest'.
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/latest"
else
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

DOWNLOAD_URL=$(curl -fsSL "$API_URL" \
    | python3 -c "import json,sys; r=json.load(sys.stdin); [print(a['browser_download_url']) for a in r.get('assets', []) if a['name']=='${ASSET}']" \
    | head -1)
[ -n "$DOWNLOAD_URL" ] || die "asset ${ASSET} not found in release ${VERSION}. Check ${API_URL}"
ok "found ${DOWNLOAD_URL##*/}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

step "Downloading"
curl -fsSL -o "${TMP}/${PLUGIN_NAME}" "$DOWNLOAD_URL" || die "download failed"
chmod +x "${TMP}/${PLUGIN_NAME}"
ok "downloaded $(wc -c < "${TMP}/${PLUGIN_NAME}") bytes"

step "Verifying binary"
if ! "${TMP}/${PLUGIN_NAME}" -introspect >/dev/null 2>&1; then
    die "downloaded binary fails -introspect; refusing to install"
fi
ok "introspect ok"

step "Installing to ${TARGET}"
mkdir -p "$TARGET_DIR"
# Atomic swap: move into place via rename (same filesystem as $TARGET_DIR).
TMP_DEST="${TARGET}.new"
cp "${TMP}/${PLUGIN_NAME}" "$TMP_DEST"
chmod +x "$TMP_DEST"
mv -f "$TMP_DEST" "$TARGET"
ok "installed"

cat <<EOF

Done. The binary is in place at:
  $TARGET

Now restart your Zoraxy container so the new plugin is picked up. Examples:
  docker restart <zoraxy-container-name>
  docker compose -f /path/to/compose.yml restart zoraxy

After restart, open Zoraxy's web UI → Plugins → enable "Guardian" (if not
already enabled) → assign to your HTTP Proxy Rule tag(s).
EOF
