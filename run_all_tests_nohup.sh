#!/bin/bash
LOG="logs/nohup.out"
mkdir -p "$(dirname ${LOG})"

if [ -z "$NOHUP_STARTED" ]; then
	export NOHUP_STARTED=1
	nohup "$0" "$@" >"${LOG}" 2>&1 &
	tail -f "${LOG}"
fi

. .venv/bin/activate || (
	echo "no venv found"
	exit 1
)

PROBES=(
	"ipfixprobe-raw"
	"ipfixprobe-dpdk"
	"nprobe-pcap"
	"nprobe-pfring"
	"nprobe-zc"
	"cento-pcap"
	"cento-pfring"
	"cento-zc"
	"yaf-pcap"
	"yaf-pfring"
	"yaf-zc"
)

declare -A PROBES_PROTOCOLS
PROBES_PROTOCOLS=(
	"ipfixprobe-raw" "tcp"
	"ipfixprobe-dpdk" "tcp"
	"nprobe-pcap" "udp"
	"nprobe-pfring" "udp"
	"nprobe-zc" "udp"
	"cento-pcap" "tcp"
	"cento-pfring" "tcp"
	"cento-zc" "tcp"
	"yaf-pcap" "tcp"
	"yaf-pfring" "tcp"
	"yaf-zc" "tcp"
)

for probe in ${PROBES[@]}; do
	ARGS=(
		"--config-path=/home/student/2025-bsc-kuppler-flowmeter/flowtest-configs"
		"--replicator=kuppler-2-xdp-zc"
		"--collector=ipfixcol-1:protocol=${PROBES_PROTOCOLS[$probe]}"
		"--probe=${probe}"
		"--disable-ansible"
		"--html=logs/report.html"
		"--self-contained-html"
		"--continue-on-collection-errors"
		"--capture=tee-sys"
		"-m"
		"simulation and hospitals and sim_threshold"
	)

	echo "📋 Starting tests with nohup... output in ${LOG} for $probe"
	pytest "${ARGS[@]}"
	NEWEST_DIR=$(ls -d logs/[0-9]*/ | sort -r | head -n1)
	if ! [ -e "${NEWEST_DIR}/report.html" ]; then
		mv "logs/report.html" "${NEWEST_DIR}"
	fi
done
