#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"
export CI=true
# Home has a pnpm workspace; isolate this project.
pnpm --ignore-workspace install --frozen-lockfile --ignore-scripts --config.confirmModulesPurge=false
pnpm --ignore-workspace run build
echo "frontend dist ready: $ROOT/frontend/dist"
