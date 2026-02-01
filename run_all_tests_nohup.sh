#!/bin/bash
LOG="logs/nohup.out"
mkdir -p "$(dirname ${LOG})"

if [ -z "$NOHUP_STARTED" ]; then
	export NOHUP_STARTED=1
	nohup "$0" "$@" >"${LOG}" 2>&1 &
	tail -f "${LOG}" &
	wait %1
	kill %2
fi

. .venv/bin/activate || (
	echo "no venv found"
	exit 1
)

PROBES=(
	#	"ipfixprobe-raw"
	#	"ipfixprobe-raw-4"
	#	"ipfixprobe-pcap"
	#	"ipfixprobe-pcap-4"
	#	"ipfixprobe-dpdk-1"
	#	"ipfixprobe-dpdk-2"
	#	"ipfixprobe-dpdk-4"
	#	"ipfixprobe-dpdk-16"
	#	"nprobe-pcap"
	#	"nprobe-pcap-4"
	#	"nprobe-pfring"
	#	"nprobe-zc"
	#	"cento-pcap"
	#	"cento-pcap-4"
	#	"cento-pfring"
	#	"cento-zc"
	#	"yaf-pcap"
	#	"yaf-pcap-4"
	#"yaf-pfring"
	#	"yaf-pfring-pcap"
	"yaf-pfring-pcap-4"
	#"yaf-zc"
)

declare -A PROBE_PROTOCOLS
PROBE_PROTOCOLS=(
	"ipfixprobe-raw" "tcp"
	"ipfixprobe-raw-4" "tcp"
	"ipfixprobe-pcap" "tcp"
	"ipfixprobe-pcap-4" "tcp"
	"ipfixprobe-dpdk-1" "tcp"
	"ipfixprobe-dpdk-2" "tcp"
	"ipfixprobe-dpdk-4" "tcp"
	"ipfixprobe-dpdk-16" "tcp"
	"nprobe-pcap" "udp"
	"nprobe-pcap-4" "udp"
	"nprobe-pfring" "udp"
	"nprobe-zc" "udp"
	"cento-pcap" "tcp"
	"cento-pcap-4" "tcp"
	"cento-pfring" "tcp"
	"cento-zc" "tcp"
	"yaf-pcap" "tcp"
	"yaf-pcap-4" "tcp"
	"yaf-pfring" "tcp"
	"yaf-pfring-pcap" "tcp"
	"yaf-pfring-pcap-4" "tcp"
	"yaf-zc" "tcp"
)

for probe in ${PROBES[@]}; do
	ARGS=(
		"--config-path=/home/student/2025-bsc-kuppler-flowmeter/flowtest-configs"
		"--replicator=kuppler-2-dpdk"
		"--collector=ipfixcol-1:protocol=${PROBE_PROTOCOLS[$probe]}"
		"--probe=${probe}"
		"--disable-ansible"
		"--html=logs/report.html"
		"--self-contained-html"
		"--continue-on-collection-errors"
		"--capture=tee-sys"
		"-m"
		"simulation and university and precise"
	)

	echo "📋 Starting tests with nohup... output in ${LOG} for $probe"
	pytest "${ARGS[@]}"
	NEWEST_DIR=$(ls -d logs/[0-9]*/ | sort -r | head -n1)
	if ! [ -e "${NEWEST_DIR}/report.html" ]; then
		mv "logs/report.html" "${NEWEST_DIR}"
	fi
done
