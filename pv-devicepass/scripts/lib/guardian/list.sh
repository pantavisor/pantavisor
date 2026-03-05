# list.sh — List devices owned by this guardian
# Sourced by devicepass-cli

cmd_guardian_list() {
	_parse_guardian_flags "$@"
	_require_contract
	set -- $GUARDIAN_ARGS

	json_output=0
	for arg in "$@"; do
		case "$arg" in
			--json) json_output=1 ;;
		esac
	done

	guardian=$(_guardian_address)

	# Get device count
	count=$($CAST call \
		--rpc-url "$DEVICEPASS_RPC" \
		"$DEVICEPASS_CONTRACT" \
		"guardianDeviceCount(address)(uint256)" \
		"$guardian" 2>&1)

	if [ $? -ne 0 ]; then
		log_error "Failed to query device count"
		printf "%s\n" "$count" >&2
		exit 1
	fi

	# cast returns values with possible annotation; normalize
	count=$(_strip_cast "$count")
	count=$(printf "%d" "$count" 2>/dev/null || echo "$count")

	if [ "$count" = "0" ]; then
		if [ "$json_output" = "1" ]; then
			printf '[]\n'
		else
			log_info "No devices found for guardian $guardian"
		fi
		return
	fi

	if [ "$json_output" = "0" ]; then
		printf "Guardian: %s\n" "$guardian"
		printf "Devices:  %s\n\n" "$count"
		printf "%-4s  %-44s  %-8s  %s\n" "#" "Device" "Active" "Created"
		printf "%-4s  %-44s  %-8s  %s\n" "---" "--------------------------------------------" "--------" "----------"
	fi

	json_items=""
	i=0
	while [ "$i" -lt "$count" ]; do
		device=$($CAST call \
			--rpc-url "$DEVICEPASS_RPC" \
			"$DEVICEPASS_CONTRACT" \
			"guardianDeviceAt(address,uint256)(address)" \
			"$guardian" "$i" 2>&1)

		passport=$($CAST call \
			--rpc-url "$DEVICEPASS_RPC" \
			"$DEVICEPASS_CONTRACT" \
			"passports(address)(address,address,uint256,bool)" \
			"$device" 2>&1)

		# Parse passport fields (cast returns one per line, strip annotations)
		p_device=$(_strip_cast "$(printf '%s' "$passport" | sed -n '1p')")
		p_guardian=$(_strip_cast "$(printf '%s' "$passport" | sed -n '2p')")
		p_created=$(_strip_cast "$(printf '%s' "$passport" | sed -n '3p')")
		p_active=$(_strip_cast "$(printf '%s' "$passport" | sed -n '4p')")

		if [ "$json_output" = "1" ]; then
			item=$(printf '{"device":"%s","guardian":"%s","createdAt":%s,"active":%s}' \
				"$p_device" "$p_guardian" "$p_created" "$p_active")
			if [ -z "$json_items" ]; then
				json_items="$item"
			else
				json_items="$json_items,$item"
			fi
		else
			printf "%-4s  %-44s  %-8s  %s\n" "$i" "$p_device" "$p_active" "$p_created"
		fi

		i=$((i + 1))
	done

	if [ "$json_output" = "1" ]; then
		printf '[%s]\n' "$json_items"
	fi
}
