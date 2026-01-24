#!/bin/bash

# Verzeichnisse
CSV_DIR="/home/student/2025-bsc-kuppler-flowmeter"
YML_DIR="/opt/FlowTest/testing/simulation"

# Finde alle cbr*.csv Dateien
for csv_file in "$CSV_DIR"/cbr*.csv; do
	# Extrahiere den Basisnamen ohne Pfad und Endung
	basename=$(basename "$csv_file" .csv)

	# Info-Datei und Ziel-YML-Datei
	info_file="${CSV_DIR}/${basename}.info"
	yml_file="${YML_DIR}/${basename}.yml"

	# Prüfe ob Info-Datei existiert
	if [[ ! -f "$info_file" ]]; then
		echo "WARNUNG: Keine .info Datei für $basename gefunden, überspringe..."
		continue
	fi

	# Extrahiere MTU aus .info Datei
	mtu=$(grep "^MTU:" "$info_file" | awk '{print $2}' | cut -d. -f1)

	if [[ -z "$mtu" ]]; then
		echo "WARNUNG: Konnte MTU nicht aus $info_file extrahieren, überspringe..."
		continue
	fi

	# Berechne MTU + 14
	mtu_plus_14=$((mtu + 14))

	# Extrahiere Paketrate aus .info Datei
	pps=$(grep "^packetrate:" "$info_file" | awk '{print $2}' | cut -d. -f1)

	if [[ -z "$pps" ]]; then
		echo "WARNUNG: Konnte packetrate nicht aus $info_file extrahieren, verwende Default..."
		pps=666666
	fi

	# Extrahiere Komponenten für marks aus dem Dateinamen
	# Format: cbr_<speed>_<packets>_<duration>_<flows>_<active_flows>
	# z.B. cbr_10Gb_40KP_60s_1KF_1A
	speed=$(echo "$basename" | cut -d_ -f2)
	duration=$(echo "$basename" | cut -d_ -f4)
	flows=$(echo "$basename" | cut -d_ -f5)
	active_flows=$(echo "$basename" | cut -d_ -f6)

	# Erstelle die YML-Datei
	cat >"$yml_file" <<EOF
# Profile information which cannot be modified by the orchestration tool.
name: ${basename}
description: Custom created profiles with predictable traffic
marks: [cbr, ${speed}, ${duration}, ${flows}, ${active_flows}]
requirements:
  speed: 100
profile: ${csv_file}
mtu: 2048
sampling: 1.0

# default configuration describing the setup during profile collection
default:
  pps: ${pps}
  mbps: 10000
  generator:
    packet_size_probabilities:
      "64-$((mtu_plus_14 - 1))": .0
      "${mtu_plus_14}-${mtu_plus_14}": 1 # für konstante paketgröße von ${mtu}, wird als MTU (+14) von create_network_profile.py berechnet
  probe:
    protocols: []
    active_timeout: 300
    inactive_timeout: 30

# individual tests for general simulation scenario
sim_general:
  - id: ${basename}_precise
    marks: [precise]
    speed_multiplier: 1.0
    loops: 1
    analysis:
      model: "precise"
      use_statistic_counter: true
EOF

	echo "Erstellt: $yml_file (MTU: $mtu -> $mtu_plus_14)"
done

echo ""
echo "Fertig! Alle YML-Dateien wurden erstellt."
