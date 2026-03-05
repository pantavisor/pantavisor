# deploy.sh — Deploy DevicePassRegistry contract via forge
# Sourced by devicepass-cli

cmd_guardian_deploy() {
	_parse_guardian_flags "$@"

	# Find forge binary
	if command -v forge >/dev/null 2>&1; then
		FORGE="forge"
	elif [ -x "$HOME/.foundry/bin/forge" ]; then
		FORGE="$HOME/.foundry/bin/forge"
	else
		log_error "forge not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
		exit 1
	fi

	# Find contract sources
	contracts_dir=""
	if [ -n "${DEVICEPASS_CONTRACTS_DIR:-}" ]; then
		contracts_dir="$DEVICEPASS_CONTRACTS_DIR"
	else
		# LIB_DIR is set by devicepass-cli (pv-devicepass/lib/devicepass)
		# Contracts are at pv-devicepass/contracts
		candidate="${LIB_DIR}/../../contracts"
		if [ -d "$candidate" ]; then
			contracts_dir=$(cd "$candidate" && pwd)
		fi
	fi

	if [ -z "$contracts_dir" ] || [ ! -f "$contracts_dir/script/Deploy.s.sol" ]; then
		log_error "Contract sources not found"
		log_info "Set DEVICEPASS_CONTRACTS_DIR or run from the pv-devicepass directory"
		exit 1
	fi

	# Require auth
	auth_flags=$(_cast_auth_flags)
	# Extract just the private key value for forge
	priv_key=""
	if [ -n "$DEVICEPASS_PRIVATE_KEY" ]; then
		priv_key="$DEVICEPASS_PRIVATE_KEY"
	else
		log_error "forge deploy requires --private-key (cast accounts not supported for forge)"
		exit 1
	fi

	log_info "Deploying DevicePassRegistry..."
	log_info "  RPC:       $DEVICEPASS_RPC"
	log_info "  Contracts: $contracts_dir"

	result=$(cd "$contracts_dir" && $FORGE script script/Deploy.s.sol \
		--rpc-url "$DEVICEPASS_RPC" \
		--private-key "$priv_key" \
		--broadcast 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Deployment failed"
		printf "%s\n" "$result" >&2
		exit 1
	fi

	# Parse deployed address from forge output
	deployed=$(printf '%s\n' "$result" | grep -i "DevicePassRegistry deployed at:" | sed 's/.*: //')
	if [ -z "$deployed" ]; then
		# Try alternate parsing from forge broadcast output
		deployed=$(printf '%s\n' "$result" | grep -i "Contract Address:" | head -1 | sed 's/.*: //' | tr -d '[:space:]')
	fi

	if [ -n "$deployed" ]; then
		log_success "DevicePassRegistry deployed at: $deployed"
	else
		log_success "Deployment completed"
		printf "%s\n" "$result"
	fi
}
