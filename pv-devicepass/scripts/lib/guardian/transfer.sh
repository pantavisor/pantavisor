# transfer.sh — Transfer device ownership to a new guardian
# Sourced by devicepass-cli

cmd_guardian_transfer() {
	_parse_guardian_flags "$@"
	_require_contract
	set -- $GUARDIAN_ARGS

	device=""
	new_guardian=""
	for arg in "$@"; do
		case "$arg" in
			0x*)
				if [ -z "$device" ]; then
					device="$arg"
				else
					new_guardian="$arg"
				fi
				;;
		esac
	done

	if [ -z "$device" ] || [ -z "$new_guardian" ]; then
		log_error "Usage: devicepass-cli guardian transfer <DEVICE_ADDRESS> <NEW_GUARDIAN_ADDRESS>"
		exit 1
	fi

	guardian=$(_guardian_address)
	log_info "Transferring device $device"
	log_info "  From: $guardian"
	log_info "  To:   $new_guardian"

	auth_flags=$(_cast_auth_flags)
	result=$($CAST send \
		--rpc-url "$DEVICEPASS_RPC" \
		$auth_flags \
		"$DEVICEPASS_CONTRACT" \
		"transferDevice(address,address)" \
		"$device" "$new_guardian" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Transfer transaction failed"
		printf "%s\n" "$result" >&2
		exit 1
	fi

	log_success "Device transferred"
	printf "  Device:       %s\n" "$device"
	printf "  New guardian: %s\n" "$new_guardian"
}
