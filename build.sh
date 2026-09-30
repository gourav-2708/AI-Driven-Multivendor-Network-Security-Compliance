#!/bin/bash
# ============================================================
# build.sh — Render cloud build script
# Compiles the C engine on Linux (Ubuntu) automatically
# ============================================================
set -e

echo "=== net-audit Cloud Build ==="
echo "Platform: $(uname -a)"

# Install gcc if not present
if ! command -v gcc &> /dev/null; then
    echo "Installing gcc..."
    apt-get update -qq && apt-get install -y gcc
fi

echo "GCC: $(gcc --version | head -1)"

# Compile the C engine for Linux
echo "Compiling net-audit binary..."
gcc -Wall -Wextra -O2 -std=c11 \
    -Iinclude \
    src/common/safe_str.c \
    src/common/model_init.c \
    src/parser/parser_registry.c \
    src/parser/cisco_parser.c \
    src/parser/juniper_parser.c \
    src/parser/fortinet_parser.c \
    src/engine/rule_engine.c \
    src/engine/rules_table.c \
    src/report/report.c \
    src/report/report_text.c \
    src/report/report_csv.c \
    src/report/report_json.c \
    src/main.c \
    -o net-audit

echo "Binary compiled: $(ls -lh net-audit)"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r webapp/requirements.txt

echo "=== Build complete ==="
