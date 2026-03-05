# signing.sh — Claim blob construction and signing
# Sourced by devicepass-cli

# Encode uint256 as 64 hex chars (32 bytes big-endian, zero-padded)
_encode_uint256() {
	printf "%064x" "$1"
}

# Encode address as 40 hex chars (20 bytes, zero-padded, no 0x prefix)
_encode_address() {
	printf "%s" "$1" | sed 's/^0x//' | tr '[:upper:]' '[:lower:]'
}

# Zero address (40 hex chars)
ZERO_ADDRESS="0000000000000000000000000000000000000000"

cmd_onboard() {
	quiet=0
	outfile=""
	guardian_addr=""
	for arg in "$@"; do
		case "$arg" in
			--quiet) quiet=1 ;;
			--out=*) outfile="${arg#--out=}" ;;
			--guardian=*) guardian_addr="${arg#--guardian=}" ;;
			*) log_error "Unknown option: $arg"; exit 1 ;;
		esac
	done

	check_deps

	# Ensure identity exists
	if ! identity_exists; then
		log_info "No identity found, generating..."
		cmd_init
	fi

	address=$(cat "$DEVICEPASS_ADDR")
	# Strip 0x prefix for encoding
	addr_hex=$(_encode_address "$address")

	# Guardian address: zero-padded if omitted (open claim)
	if [ -n "$guardian_addr" ]; then
		guardian_hex=$(_encode_address "$guardian_addr")
	else
		guardian_hex="$ZERO_ADDRESS"
		guardian_addr="0x${ZERO_ADDRESS}"
	fi

	nonce=$(date +%s)
	chain_id="$DEVICEPASS_CHAIN_ID"
	contract="$DEVICEPASS_CONTRACT"

	[ "$quiet" = "0" ] && log_info "Building onboard claim..."

	# ABI encodePacked(address, guardian, nonce, chain_id)
	# address:  20 bytes (40 hex)
	# guardian: 20 bytes (40 hex)
	# nonce:    32 bytes (64 hex) big-endian
	# chain_id: 32 bytes (64 hex) big-endian
	nonce_hex=$(_encode_uint256 "$nonce")
	chain_hex=$(_encode_uint256 "$chain_id")
	packed="${addr_hex}${guardian_hex}${nonce_hex}${chain_hex}"

	# Inner hash: keccak256(packed)
	inner_hash=$(printf "%s" "$packed" | keccak256sum --hex)
	if [ $? -ne 0 ]; then
		log_error "Failed to compute inner hash"
		exit 1
	fi

	# Ethereum signed message prefix:
	# "\x19Ethereum Signed Message:\n32" + inner_hash
	# The prefix is 28 bytes, encode as hex
	prefix_hex="19457468657265756d205369676e6564204d6573736167653a0a3332"
	msg_data="${prefix_hex}${inner_hash}"

	# Message hash: keccak256(prefix + inner_hash)
	msg_hash=$(printf "%s" "$msg_data" | keccak256sum --hex)
	if [ $? -ne 0 ]; then
		log_error "Failed to compute message hash"
		exit 1
	fi

	# Sign the message hash
	signature=$(ethsign sign --key "$DEVICEPASS_KEY" "$msg_hash")
	if [ $? -ne 0 ]; then
		log_error "Signing failed"
		exit 1
	fi

	# Build claim JSON (includes guardian field)
	claim=$(printf '{"version":2,"device":"%s","guardian":"%s","nonce":%s,"chain_id":%s,"contract":"%s","signature":"0x%s"}' \
		"$address" "$guardian_addr" "$nonce" "$chain_id" "$contract" "$signature")

	if [ -n "$outfile" ]; then
		printf "%s\n" "$claim" > "$outfile"
		log_success "Claim written to $outfile"
	elif [ "$quiet" = "1" ]; then
		printf "%s\n" "$claim"
	else
		log_success "Onboard claim generated"
		printf "%s\n" "$claim"
	fi
}
