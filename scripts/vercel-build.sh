#!/usr/bin/env bash
# ============================================================
# vercel-build.sh - Vercel build step (run via vercel.json)
#
#  1. compile the C auditor to build/release/net-audit
#  2. self-test it (unit + regression suite) before shipping
#  3. copy the web UI's static assets to public/static so
#     Vercel's CDN can serve them; they are also bundled into
#     the Python function (vercel.json includeFiles) so Flask
#     serves /static/* whenever the CDN copy is not picked up
#
# Safe to run locally on Linux/macOS to reproduce the build.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== net-audit build ($(uname -sm)) ==="

if ! command -v gcc >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
    echo "Installing gcc and make..."
    dnf install -y -q gcc make
fi
echo "Compiler: $(gcc --version | head -1)"

# CI enforces -Werror; a deploy must not fail because a newer compiler on
# the build image adds a warning, so downgrade warnings to non-fatal here.
make EXTRA_CFLAGS=-Wno-error
make test EXTRA_CFLAGS=-Wno-error
build/release/net-audit --version

rm -rf public
mkdir -p public/static
cp -R frontends/web/static/. public/static/

echo "=== build complete ==="
