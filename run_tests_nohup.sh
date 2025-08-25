#!/bin/bash
LOG="logs/nohup.out"
mkdir -p "$(dirname ${LOG})"

if [ -z "$NOHUP_STARTED" ]; then
  export NOHUP_STARTED=1
  nohup "$0" "$@" > "${LOG}" 2>&1 &
  tail -f "${LOG}"
fi

echo "📋 Starting tests with nohup... output in ${LOG}"
. .venv/bin/activate && pytest "$@" &
wait %1 # wait for pytest to finish
NEWEST_DIR=$(ls -d logs/[0-9]*/ | sort -r | head -n1)
if ! [ -e "${NEWEST_DIR}/report.html" ]; then
  mv "logs/report.html" "${NEWEST_DIR}"
fi