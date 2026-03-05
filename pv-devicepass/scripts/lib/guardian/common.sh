# common.sh — Guardian shared helpers (cast wrappers, config)
# Sourced by guardian subcommands

# Guardian-specific config (extends config.sh)
DEVICEPASS_RPC="${DEVICEPASS_RPC:-http://localhost:8545}"
DEVICEPASS_ACCOUNT="${DEVICEPASS_ACCOUNT:-}"
DEVICEPASS_PRIVATE_KEY="${DEVICEPASS_PRIVATE_KEY:-}"

# Resolve cast binary (may not be in PATH)
_find_cast() {
	if command -v cast >/dev/null 2>&1; then
		echo "cast"
	elif [ -x "$HOME/.foundry/bin/cast" ]; then
		echo "$HOME/.foundry/bin/cast"
	else
		log_error "cast not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
		exit 1
	fi
}

CAST=$(_find_cast)

# Build cast auth flags from --account or --private-key
_cast_auth_flags() {
	if [ -n "$DEVICEPASS_PRIVATE_KEY" ]; then
		echo "--private-key $DEVICEPASS_PRIVATE_KEY"
	elif [ -n "$DEVICEPASS_ACCOUNT" ]; then
		echo "--account $DEVICEPASS_ACCOUNT"
	else
		log_error "No signing identity. Set --account=NAME, --private-key=KEY, or DEVICEPASS_ACCOUNT/DEVICEPASS_PRIVATE_KEY env"
		exit 1
	fi
}

# Get guardian address from account or private key
_guardian_address() {
	if [ -n "$DEVICEPASS_PRIVATE_KEY" ]; then
		$CAST wallet address --private-key "$DEVICEPASS_PRIVATE_KEY"
	elif [ -n "$DEVICEPASS_ACCOUNT" ]; then
		$CAST wallet address --account "$DEVICEPASS_ACCOUNT"
	fi
}

# Parse common guardian flags from args, return remaining args via GUARDIAN_ARGS
_parse_guardian_flags() {
	GUARDIAN_ARGS=""
	for arg in "$@"; do
		case "$arg" in
			--rpc=*)         DEVICEPASS_RPC="${arg#--rpc=}" ;;
			--account=*)     DEVICEPASS_ACCOUNT="${arg#--account=}" ;;
			--private-key=*) DEVICEPASS_PRIVATE_KEY="${arg#--private-key=}" ;;
			--contract=*)    DEVICEPASS_CONTRACT="${arg#--contract=}" ;;
			--chain-id=*)    DEVICEPASS_CHAIN_ID="${arg#--chain-id=}" ;;
			*)               GUARDIAN_ARGS="${GUARDIAN_ARGS:+$GUARDIAN_ARGS }$arg" ;;
		esac
	done
}

# Strip cast's annotation suffix: "1234 [1.234e3]" → "1234"
_strip_cast() {
	printf '%s' "$1" | sed 's/ \[.*\]$//' | tr -d '[:space:]'
}

# Validate contract is set
_require_contract() {
	if [ "$DEVICEPASS_CONTRACT" = "0x0000000000000000000000000000000000000000" ] || [ -z "$DEVICEPASS_CONTRACT" ]; then
		log_error "Contract address not set. Use --contract=0x... or DEVICEPASS_CONTRACT env"
		exit 1
	fi
}
