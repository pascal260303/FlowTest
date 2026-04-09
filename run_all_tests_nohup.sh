#!/bin/bash
LOG="logs/nohup.out"
mkdir -p "$(dirname ${LOG})"

if [ -z "$NOHUP_STARTED" ]; then
	export NOHUP_STARTED=1
	nohup "$0" "$@" >"${LOG}" 2>&1 &
	tail -f "${LOG}" &
	wait %1
	kill %2
	exit
fi

. .venv/bin/activate || (
	echo "no venv found"
	exit 1
)

PROBES=(
	#"ipfixprobe-raw"
	"ipfixprobe-raw-4"
	#"ipfixprobe-pcap"
	"ipfixprobe-pcap-4"
	#"ipfixprobe-dpdk-1"
	#"ipfixprobe-dpdk-2"
	"ipfixprobe-dpdk-4"
	#"ipfixprobe-dpdk-16"
	"nprobe-pfring"
	#"nprobe-pcap"
	#"nprobe-pcap-4"
	"nprobe-mlx"
	"cento-pfring"
	#"cento-pcap"
	#"cento-pcap-4"
	"cento-mlx"
	#"yaf-pcap"
	"yaf-pcap-4"
	"yaf-pfring"
	#"yaf-pfring-pcap"
	#"yaf-pfring-pcap-4"
	"yaf-mlx"
	#"manual"
	#"mikrotik-nic"
	"mikrotik-flowmeter"
	"pmacct-pcap"
	"pmacct-pfring-pcap"
)

get_collector() {
	case $1 in
	mikrotik-flowmeter)
		echo ipfixcol-kuppler-3
		;;
	*)
		echo ipfixcol-1
		;;
	esac
}

get_protocol() {
	case $1 in
	nprobe*)
		echo "udp"
		;;
	*)
		#echo "tcp"
		echo "udp"
		;;
	esac
}

get_replicator() {
	case $1 in
	mikrotik-flowmeter)
		echo "kuppler-2-dpdk-2"
		;;
	*)
		echo "kuppler-2-dpdk"
		;;
	esac
}

for probe in ${PROBES[@]}; do
	ARGS=(
		"--config-path=/home/student/2025-bsc-kuppler-flowmeter/flowtest-configs"
		"--replicator=$(get_replicator ${probe})"
		"--collector=$(get_collector ${probe}):protocol=$(get_protocol ${probe})"
		"--probe=${probe}"
		"--disable-ansible"
		"--html=logs/report.html"
		"--self-contained-html"
		"--continue-on-collection-errors"
		"--capture=tee-sys"
		"-m"
		"simulation and cpr and 100M-ACTIVE"
	)

	echo "Starting tests with nohup... output in ${LOG} for $probe"
	pytest "${ARGS[@]}"
	NEWEST_DIR=$(ls -d logs/[0-9]*/ | sort -r | head -n1)
	if ! [ -e "${NEWEST_DIR}/report.html" ]; then
		mv "logs/report.html" "${NEWEST_DIR}"
	fi
done
