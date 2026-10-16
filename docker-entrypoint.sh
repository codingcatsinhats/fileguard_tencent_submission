#!/usr/bin/env bash
# One container runs the whole demo: 4 platform simulators + unified index
# sync + the web app. State is regenerated fresh on every container start
# (mount ./data as a volume to persist the audit log across restarts).
set -e
cd "$(dirname "$0")"

python3 demo-seed/reset-demo.py
python3 scripts/sync_demo.py

# single worker — the chat harness state is in-process
exec python3 -m uvicorn ui.web:app --host 0.0.0.0 --port 8000
