#!/bin/bash

# --- Environment Configuration ---
# Values are resolved in this order (highest priority first):
#   1. Command-line arguments  (-m, -u, -p)
#   2. Environment variables   (NSX_MANAGER, NSX_USER, NSX_PASS)
#   3. Hard-coded defaults below (optional; leave empty when sharing)
DEFAULT_NSX_MANAGER=""
DEFAULT_NSX_USER="admin"
DEFAULT_NSX_PASS=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [-m nsx_manager] [-u username] [-p password] [-f file] [-n entry]...

Options:
  -m  NSX Manager hostname or IP   (env: NSX_MANAGER)
  -u  NSX username                 (env: NSX_USER, default: admin)
  -p  NSX password                 (env: NSX_PASS; prompted if not set)
  -f  File of networks, one per line (use - for stdin). May be repeated.
  -n  Single network entry, e.g. -n "192.0.2.0/24 192.0.2.1". May be repeated.
  -h  Show this help

Network entry format: "<network>/<prefix> <gateway>" or "<network> <prefix> <gateway>"
In a file, blank lines and lines starting with '#' are ignored.

Note: passing -p exposes the password in the process list and shell history.
Prefer the NSX_PASS environment variable or the interactive prompt.
EOF
}

NSX_MANAGER="${NSX_MANAGER:-$DEFAULT_NSX_MANAGER}"
NSX_USER="${NSX_USER:-$DEFAULT_NSX_USER}"
NSX_PASS="${NSX_PASS:-$DEFAULT_NSX_PASS}"

NETWORK_FILES=()
NETWORK_ARGS=()

while getopts ":m:u:p:f:n:h" opt; do
  case "$opt" in
    m) NSX_MANAGER="$OPTARG" ;;
    u) NSX_USER="$OPTARG" ;;
    p) NSX_PASS="$OPTARG" ;;
    f) NETWORK_FILES+=("$OPTARG") ;;
    n) NETWORK_ARGS+=("$OPTARG") ;;
    h) usage; exit 0 ;;
    :) echo "Error: option -$OPTARG requires an argument" >&2; usage >&2; exit 1 ;;
    *) echo "Error: unknown option -$OPTARG" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$NSX_MANAGER" ]]; then
  echo "Error: NSX Manager not specified (use -m, set NSX_MANAGER env variable or hard-code it)." >&2
  usage >&2
  exit 1
fi

if [[ -z "$NSX_PASS" ]]; then
  read -r -s -p "Password for ${NSX_USER}@${NSX_MANAGER}: " NSX_PASS
  echo
fi

# --- Network definitions ---
# Networks are collected from (all are combined):
#   1. Hard-coded entries in the HARDCODED_NETWORKS array below (optional)
#   2. A file given with -f (use "-f -" to read from stdin)
#   3. One or more -n arguments
#
# Entry format (either form works):
#   "<network>/<prefix> <gateway>"    e.g. "192.0.2.0/24 192.0.2.1"
#   "<network> <prefix> <gateway>"    e.g. "192.0.2.0 24 192.0.2.1"
# In a file, use one entry per line; blank lines and '#' comments are ignored.
HARDCODED_NETWORKS=(
  # "192.0.2.0/24 192.0.2.1"
)
NETWORKS=("${HARDCODED_NETWORKS[@]}")

load_networks_from_file() {
  local file="$1" line
  if [[ "$file" != "-" && ! -r "$file" ]]; then
    echo "Error: cannot read networks file: $file" >&2
    exit 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"                                   # strip comments
    line="$(echo "$line" | tr -d '\r' | xargs)"          # trim whitespace / CR
    [[ -n "$line" ]] && NETWORKS+=("$line")
  done < <(if [[ "$file" == "-" ]]; then cat; else cat "$file"; fi)
}

for f in "${NETWORK_FILES[@]}"; do
  load_networks_from_file "$f"
done
NETWORKS+=("${NETWORK_ARGS[@]}")

if [[ ${#NETWORKS[@]} -eq 0 ]]; then
  echo "Error: no networks specified (use -f <file>, -n <entry>, or hard-code HARDCODED_NETWORKS)." >&2
  usage >&2
  exit 1
fi


OVERLAY_TZ_ID=$(curl -k -s -X GET "https://${NSX_MANAGER}/policy/api/v1/infra/sites/default/enforcement-points/default/transport-zones/" \
    -u "${NSX_USER}:${NSX_PASS}" \
    -H "Content-Type: application/json" | \
    jq -r '.results[] | select(.is_default == true and ((.tz_type // .transport_zone_type // "") | contains("OVERLAY"))) | .id')

echo "Default Overlay Transport Zone ID: ${OVERLAY_TZ_ID}"

# --- Main Loop ---
for NET_CONFIG in "${NETWORKS[@]}"; do

  # Read space-separated values into individual variables
  read -r NET PREFIX GW <<< "${NET_CONFIG//\// }"
  if [[ -z "$NET" || -z "$PREFIX" || -z "$GW" ]]; then
    echo "Skipping invalid entry: '${NET_CONFIG}'" >&2
    continue
  fi

  SEGMENT_ID="net_${NET}_${PREFIX}"
  API_PATH="/policy/api/v1/infra/segments/${SEGMENT_ID}"

  echo "Creating segment: ${SEGMENT_ID}..."

  curl -k -s -X PATCH "https://${NSX_MANAGER}${API_PATH}" \
    -u "${NSX_USER}:${NSX_PASS}" \
    -H "Content-Type: application/json" \
    -d '{
      "type": "DISCONNECTED",
      "subnets": [
        {
          "gateway_address": "'"${GW}/${PREFIX}"'",
          "network": "'"${NET}/${PREFIX}"'"
        }
      ],
      "transport_zone_path": "/infra/sites/default/enforcement-points/default/transport-zones/'${OVERLAY_TZ_ID}'",
      "replication_mode": "MTEP",
      "resource_type": "Segment",
      "display_name": "'"${SEGMENT_ID}"'"
    }'

  echo -e "\n----------------------------------------"
done