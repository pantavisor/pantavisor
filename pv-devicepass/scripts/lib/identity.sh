# identity.sh — Device identity generation
# Sourced by devicepass-cli

cmd_init() {
	force=0
	for arg in "$@"; do
		case "$arg" in
			--force) force=1 ;;
			*) log_error "Unknown option: $arg"; exit 1 ;;
		esac
	done

	check_deps

	if identity_exists && [ "$force" != "1" ]; then
		log_warn "Identity already exists at $DEVICEPASS_DIR"
		log_warn "Use --force to regenerate (destroys existing identity)"
		exit 1
	fi

	log_info "Generating device identity..."

	# Create directory with restricted permissions
	mkdir -p "$DEVICEPASS_DIR"
	chmod 700 "$DEVICEPASS_DIR"

	# Generate secp256k1 keypair
	ethsign genkey --dir "$DEVICEPASS_DIR"
	if [ $? -ne 0 ]; then
		log_error "Key generation failed"
		exit 1
	fi

	# Derive Ethereum address from public key
	# Address = last 20 bytes of Keccak-256(uncompressed_pubkey)
	pubhash=$(keccak256sum --hex < "$DEVICEPASS_PUB")
	if [ $? -ne 0 ] || [ -z "$pubhash" ]; then
		log_error "Failed to hash public key"
		exit 1
	fi

	# Take last 40 hex chars (20 bytes) as address
	# Strip trailing whitespace, then remove first 24 chars (shell pattern)
	pubhash=$(printf "%s" "$pubhash" | tr -d '[:space:]')
	addr=${pubhash#????????????????????????}
	printf "0x%s\n" "$addr" > "$DEVICEPASS_ADDR"

	# Generate short device ID: dp- + first 12 hex chars of address
	short=$(printf "%.12s" "$addr")
	printf "dp-%s\n" "$short" > "$DEVICEPASS_ID"

	log_success "Device identity created"
	log_info "Address: 0x$addr"
	log_info "ID:      dp-$short"
	log_info "Key dir: $DEVICEPASS_DIR"
}
