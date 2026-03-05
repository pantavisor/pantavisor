# fund.sh — Send ETH to a device wallet
# Sourced by devicepass-cli

cmd_guardian_fund() {
	_parse_guardian_flags "$@"
	set -- $GUARDIAN_ARGS

	device=""
	amount=""
	for arg in "$@"; do
		case "$arg" in
			0x*) device="$arg" ;;
			*)   amount="$arg" ;;
		esac
	done

	if [ -z "$device" ] || [ -z "$amount" ]; then
		log_error "Usage: devicepass-cli guardian fund <DEVICE_ADDRESS> <AMOUNT>"
		log_info "  Amount in ETH (e.g. 0.01)"
		exit 1
	fi

	guardian=$(_guardian_address)
	log_info "Funding device $device"
	log_info "  From:   $guardian"
	log_info "  Amount: $amount ETH"

	auth_flags=$(_cast_auth_flags)
	result=$($CAST send \
		--rpc-url "$DEVICEPASS_RPC" \
		$auth_flags \
		--value "${amount}ether" \
		"$device" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Fund transaction failed"
		printf "%s\n" "$result" >&2
		exit 1
	fi

	# Show new balance
	balance=$($CAST balance \
		--rpc-url "$DEVICEPASS_RPC" \
		"$device" 2>&1)

	log_success "Funded successfully"
	printf "  Device balance: %s\n" "$balance"
}
