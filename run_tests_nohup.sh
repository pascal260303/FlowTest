#!/bin/bash
LOG="logs/nohup.out"
mkdir -p "$(dirname ${LOG})"

echo "📋 Starting tests with nohup... output in ${LOG}"
set -x
nohup /bin/bash -c '. .venv/bin/activate && pytest "$@"' bash "$@" > "${LOG}" 2>&1 &
set +x
sleep 1  # Give it a moment to start
tail -f "${LOG}"