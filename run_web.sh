#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Starting DPI Web Dashboard on http://localhost:3000..."
cd "$SCRIPT_DIR/web" || exit 1
npm run dev
