# claim.sh — Submit a device claim blob to the on-chain registry
# Sourced by devicepass-cli

cmd_guardian_claim() {
	_parse_guardian_flags "$@"
	_require_contract
	set -- $GUARDIAN_ARGS

	blob_file=""
	blob_json=""
	for arg in "$@"; do
		case "$arg" in
			--blob=*) blob_file="${arg#--blob=}" ;;
			--json=*) blob_json="${arg#--json=}" ;;
			*) blob_file="$arg" ;;
		esac
	done

	# Read claim blob
	if [ -n "$blob_file" ]; then
		if [ ! -f "$blob_file" ]; then
			log_error "Claim file not found: $blob_file"
			exit 1
		fi
		blob_json=$(cat "$blob_file")
	elif [ -z "$blob_json" ]; then
		# Try reading from stdin
		if [ -t 0 ]; then
			log_error "Usage: devicepass-cli guardian claim --blob=FILE"
			log_info "  Or pipe claim JSON: devicepass-cli dev onboard --quiet | devicepass-cli guardian claim"
			exit 1
		fi
		blob_json=$(cat)
	fi

	# Parse fields from claim JSON
	device=$(printf '%s' "$blob_json" | jq -r '.device')
	nonce=$(printf '%s' "$blob_json" | jq -r '.nonce')
	signature=$(printf '%s' "$blob_json" | jq -r '.signature')
	# Guardian from blob (default to zero address for v1 blobs without guardian field)
	guardian_in_blob=$(printf '%s' "$blob_json" | jq -r '.guardian // "0x0000000000000000000000000000000000000000"')

	if [ "$device" = "null" ] || [ "$nonce" = "null" ] || [ "$signature" = "null" ]; then
		log_error "Invalid claim blob — missing device, nonce, or signature"
		exit 1
	fi

	guardian=$(_guardian_address)
	log_info "Claiming device $device as guardian $guardian"
	log_info "  Contract: $DEVICEPASS_CONTRACT"
	log_info "  RPC:      $DEVICEPASS_RPC"
	log_info "  Nonce:    $nonce"
	log_info "  Bound to: $guardian_in_blob"

	# Submit claimDevice(address,address,uint256,bytes)
	auth_flags=$(_cast_auth_flags)
	result=$($CAST send \
		--rpc-url "$DEVICEPASS_RPC" \
		$auth_flags \
		"$DEVICEPASS_CONTRACT" \
		"claimDevice(address,address,uint256,bytes)" \
		"$device" "$guardian_in_blob" "$nonce" "$signature" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Claim transaction failed"
		printf "%s\n" "$result" >&2
		exit 1
	fi

	# Verify on-chain
	passport=$($CAST call \
		--rpc-url "$DEVICEPASS_RPC" \
		"$DEVICEPASS_CONTRACT" \
		"passports(address)(address,address,uint256,bool)" \
		"$device" 2>&1)

	log_success "Device claimed successfully"
	printf "  Device:   %s\n" "$device"
	printf "  Guardian: %s\n" "$guardian"
	printf "  Passport: %s\n" "$passport"
}
