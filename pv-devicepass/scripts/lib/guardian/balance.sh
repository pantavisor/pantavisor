# balance.sh — Check device wallet balance
# Sourced by devicepass-cli

cmd_guardian_balance() {
	_parse_guardian_flags "$@"
	set -- $GUARDIAN_ARGS

	device="${1:-}"
	if [ -z "$device" ]; then
		log_error "Usage: devicepass-cli guardian balance <DEVICE_ADDRESS>"
		exit 1
	fi

	balance=$($CAST balance \
		--rpc-url "$DEVICEPASS_RPC" \
		"$device" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Failed to query balance"
		printf "%s\n" "$balance" >&2
		exit 1
	fi

	# Also try ether conversion
	balance_eth=$($CAST balance \
		--rpc-url "$DEVICEPASS_RPC" \
		--ether \
		"$device" 2>/dev/null)

	printf "Device:  %s\n" "$device"
	if [ -n "$balance_eth" ]; then
		printf "Balance: %s ETH\n" "$balance_eth"
	else
		printf "Balance: %s wei\n" "$balance"
	fi
}
