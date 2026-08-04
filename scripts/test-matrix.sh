#!/usr/bin/env bash

# Multi-Node Test Matrix Script for WebCrypt
# Tests WebCrypt across Node.js major versions: 18, 20, 22+

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VERSIONS=("18" "20" "22")
FAILED_VERSIONS=()
PASSED_VERSIONS=()

echo "======================================================"
echo "          WebCrypt Local Multi-Node Test Matrix       "
echo "======================================================"
echo "Project Root: $PROJECT_DIR"
echo "Target Node Versions: ${VERSIONS[*]}"
echo "Current Host Node: $(node -v)"
echo "------------------------------------------------------"

# Load NVM if present
if [ -f "$HOME/.nvm/nvm.sh" ]; then
  source "$HOME/.nvm/nvm.sh"
elif [ -f "/usr/local/opt/nvm/nvm.sh" ]; then
  source "/usr/local/opt/nvm/nvm.sh"
fi

run_test_for_version() {
  local ver=$1
  echo ""
  echo ">>> [Matrix Test] Testing on Node.js v$ver..."

  if command -v nvm >/dev/null 2>&1 && nvm ls "$ver" >/dev/null 2>&1; then
    echo "Using nvm to execute Node v$ver:"
    if nvm exec "$ver" npm test; then
      PASSED_VERSIONS+=("Node v$ver (nvm)")
    else
      FAILED_VERSIONS+=("Node v$ver (nvm)")
    fi
  elif command -v docker >/dev/null 2>&1; then
    echo "Using Docker container node:$ver-alpine:"
    if docker run --rm -v "$PROJECT_DIR":/app -w /app "node:$ver-alpine" npm test; then
      PASSED_VERSIONS+=("Node v$ver (docker)")
    else
      FAILED_VERSIONS+=("Node v$ver (docker)")
    fi
  else
    echo "Executing host Node.js binary ($(node -v)):"
    if npm test; then
      PASSED_VERSIONS+=("Node $(node -v) (host)")
    else
      FAILED_VERSIONS+=("Node $(node -v) (host)")
    fi
  fi
}

# If nvm is available, run for each version; otherwise run host environment
if command -v nvm >/dev/null 2>&1; then
  for ver in "${VERSIONS[@]}"; do
    run_test_for_version "$ver"
  done
elif command -v docker >/dev/null 2>&1; then
  for ver in "${VERSIONS[@]}"; do
    run_test_for_version "$ver"
  done
else
  run_test_for_version "$(node -v | cut -d'v' -f2 | cut -d'.' -f1)"
fi

echo ""
echo "======================================================"
echo "               Matrix Test Results                    "
echo "======================================================"

if [ ${#PASSED_VERSIONS[@]} -gt 0 ]; then
  echo "PASSED:"
  for p in "${PASSED_VERSIONS[@]}"; do
    echo "  - $p"
  done
fi

if [ ${#FAILED_VERSIONS[@]} -gt 0 ]; then
  echo "FAILED:"
  for f in "${FAILED_VERSIONS[@]}"; do
    echo "  - $f"
  done
  exit 1
fi

echo ""
echo "✅ All Node matrix test targets passed cleanly!"
exit 0
