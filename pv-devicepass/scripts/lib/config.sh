# config.sh — DevicePass paths and defaults
# Sourced by devicepass-cli

DEVICEPASS_DIR="${DEVICEPASS_DIR:-/var/lib/devicepass}"
DEVICEPASS_KEY="${DEVICEPASS_DIR}/device.key"
DEVICEPASS_PUB="${DEVICEPASS_DIR}/device.pub.hex"
DEVICEPASS_ADDR="${DEVICEPASS_DIR}/device.address"
DEVICEPASS_ID="${DEVICEPASS_DIR}/device.id"
DEVICEPASS_CHAIN_ID="${DEVICEPASS_CHAIN_ID:-8453}"
DEVICEPASS_CONTRACT="${DEVICEPASS_CONTRACT:-0x0000000000000000000000000000000000000000}"

# Check required binaries
check_deps() {
	for cmd in keccak256sum ethsign; do
		if ! command -v "$cmd" >/dev/null 2>&1; then
			log_error "Required command not found: $cmd"
			exit 1
		fi
	done
}

# Check if identity exists
identity_exists() {
	[ -f "$DEVICEPASS_KEY" ] && [ -f "$DEVICEPASS_ADDR" ]
}
