# status.sh — Show on-chain passport and balance for a device
# Sourced by devicepass-cli

cmd_guardian_status() {
	_parse_guardian_flags "$@"
	_require_contract
	set -- $GUARDIAN_ARGS

	device="${1:-}"
	json_output=0
	for arg in "$@"; do
		case "$arg" in
			--json) json_output=1 ;;
			0x*) device="$arg" ;;
		esac
	done

	if [ -z "$device" ]; then
		log_error "Usage: devicepass-cli guardian status <DEVICE_ADDRESS>"
		exit 1
	fi

	# Query passport
	passport=$($CAST call \
		--rpc-url "$DEVICEPASS_RPC" \
		"$DEVICEPASS_CONTRACT" \
		"passports(address)(address,address,uint256,bool)" \
		"$device" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Failed to query passport"
		printf "%s\n" "$passport" >&2
		exit 1
	fi

	p_device=$(_strip_cast "$(printf '%s' "$passport" | sed -n '1p')")
	p_guardian=$(_strip_cast "$(printf '%s' "$passport" | sed -n '2p')")
	p_created=$(_strip_cast "$(printf '%s' "$passport" | sed -n '3p')")
	p_active=$(_strip_cast "$(printf '%s' "$passport" | sed -n '4p')")

	# Query device balance
	balance=$($CAST balance \
		--rpc-url "$DEVICEPASS_RPC" \
		"$device" 2>&1)

	if [ "$json_output" = "1" ]; then
		printf '{"device":"%s","guardian":"%s","createdAt":%s,"active":%s,"balance":"%s"}\n' \
			"$p_device" "$p_guardian" "$p_created" "$p_active" "$balance"
	else
		printf "Device Passport\n"
		printf "  Device:    %s\n" "$p_device"
		printf "  Guardian:  %s\n" "$p_guardian"
		printf "  Created:   %s\n" "$p_created"
		printf "  Active:    %s\n" "$p_active"
		printf "  Balance:   %s\n" "$balance"
	fi
}
