# revoke.sh — Deactivate a device passport
# Sourced by devicepass-cli

cmd_guardian_revoke() {
	_parse_guardian_flags "$@"
	_require_contract
	set -- $GUARDIAN_ARGS

	device="${1:-}"
	if [ -z "$device" ]; then
		log_error "Usage: devicepass-cli guardian revoke <DEVICE_ADDRESS>"
		exit 1
	fi

	guardian=$(_guardian_address)
	log_warn "Revoking device passport (this deactivates the device)"
	log_info "  Device:   $device"
	log_info "  Guardian: $guardian"

	auth_flags=$(_cast_auth_flags)
	result=$($CAST send \
		--rpc-url "$DEVICEPASS_RPC" \
		$auth_flags \
		"$DEVICEPASS_CONTRACT" \
		"revokeDevice(address)" \
		"$device" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Revoke transaction failed"
		printf "%s\n" "$result" >&2
		exit 1
	fi

	log_success "Device passport revoked"
	printf "  Device: %s\n" "$device"
}
