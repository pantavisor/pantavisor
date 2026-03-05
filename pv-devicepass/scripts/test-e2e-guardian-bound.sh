#!/bin/bash
# test-e2e-guardian-bound.sh — End-to-end test for guardian-bound claims
#
# Full device-to-guardian flow:
#   Part A: Contract tests (forge)
#   Part B: Host-side infra (anvil, deploy, version)
#   Part C: Device-side commands in container (init, status, onboard)
#   Part D: Device→Guardian claim flow (real device blob → host guardian claim)
#   Part E: Guardian-bound claims (matching, mismatch)
#   Part F: Guardian management (list, status, balance, fund, transfer, revoke)
#
# Prerequisites:
#   - Foundry (forge, cast, anvil) installed on host
#   - Appengine running: docker ps | grep pva-test
#   - pv-devicepass-container RUNNING in appengine
#
# Usage: ./test-e2e-guardian-bound.sh

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CONTRACTS_DIR="${SCRIPT_DIR}/../contracts"
CLI="${SCRIPT_DIR}/devicepass-cli"
CONTAINER="pv-devicepass-container"
DOCKER_EXEC="docker exec pva-test"

# Anvil pre-funded accounts
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
GUARDIAN1_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
GUARDIAN1_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
GUARDIAN2_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
GUARDIAN2_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

ZERO_ADDR="0x0000000000000000000000000000000000000000"

ANVIL_PORT=8547
RPC="http://localhost:${ANVIL_PORT}"
CONTRACT=""
ANVIL_PID=""

PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'
TEST_NUM=0

log_test() {
    TEST_NUM=$((TEST_NUM + 1))
    printf "\n${BOLD}=== Test %d: %s ===${NC}\n" "$TEST_NUM" "$1"
}

log_section() {
    printf "\n${BOLD}────────────────────────────────────────────────${NC}\n"
    printf "${BOLD}  %s${NC}\n" "$1"
    printf "${BOLD}────────────────────────────────────────────────${NC}\n"
}

pass() {
    PASS=$((PASS + 1))
    printf "${GREEN}  PASS: %s${NC}\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf "${RED}  FAIL: %s${NC}\n" "$1"
}

skip() {
    printf "${YELLOW}  SKIP: %s${NC}\n" "$1"
}

cleanup() {
    if [ -n "$ANVIL_PID" ]; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
    rm -f /tmp/e2e-claim-*.json
}
trap cleanup EXIT

# Run command inside device container, capture stdout (stderr discarded)
pv_exec() {
    $DOCKER_EXEC pventer -c "$CONTAINER" "$*" 2>/dev/null
}

# Copy a file from host into the device container
pv_copy() {
    local src="$1"
    local dest="$2"
    docker exec -i pva-test pventer -c "$CONTAINER" "sh -c 'cat > $dest'" < "$src"
}

# Build a claim blob JSON using cast (for host-only tests without container)
make_claim_blob() {
    local dev_key="$1" guard_addr="$2" nonce="$3" contract="$4"
    local dev_addr packed inner_hash msg_hash sig
    dev_addr=$(cast wallet address --private-key "$dev_key")
    packed=$(cast abi-encode --packed "(address,address,uint256,uint256)" \
        "$dev_addr" "$guard_addr" "$nonce" 31337)
    inner_hash=$(cast keccak "$packed")
    local prefix_hex="19457468657265756d205369676e6564204d6573736167653a0a3332"
    msg_hash=$(cast keccak "0x${prefix_hex}${inner_hash#0x}")
    sig=$(cast wallet sign --private-key "$dev_key" --no-hash "$msg_hash")
    printf '{"version":2,"device":"%s","guardian":"%s","nonce":%s,"chain_id":31337,"contract":"%s","signature":"%s"}\n' \
        "$dev_addr" "$guard_addr" "$nonce" "$contract" "$sig"
}

# ===== Pre-flight checks =====

printf "${BOLD}DevicePass E2E Test — Guardian-Bound Claims${NC}\n"
printf "================================================\n\n"

for tool in forge cast anvil jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf "${RED}Required tool not found: %s${NC}\n" "$tool"
        exit 1
    fi
done

# Check appengine is running
HAVE_CONTAINER=0
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q pva-test; then
    container_status=$($DOCKER_EXEC lxc-ls -f 2>/dev/null | grep "$CONTAINER" || true)
    if echo "$container_status" | grep -q RUNNING; then
        HAVE_CONTAINER=1
        printf "  Appengine: running, %s: RUNNING\n" "$CONTAINER"
    else
        printf "${YELLOW}  %s not running — device-side tests will be skipped${NC}\n" "$CONTAINER"
    fi
else
    printf "${YELLOW}  pva-test not running — device-side tests will be skipped${NC}\n"
fi

# ============================================================
log_section "Part A: Contract Unit Tests"
# ============================================================

log_test "Forge unit tests"

output=$(cd "$CONTRACTS_DIR" && forge test -vv 2>&1)
if echo "$output" | grep -q "0 failed"; then
    test_count=$(echo "$output" | grep -oP '\d+ passed' | grep -oP '\d+')
    pass "All $test_count contract tests passed"
else
    fail "Some contract tests failed"
    echo "$output"
fi

# ============================================================
log_section "Part B: Host Infrastructure"
# ============================================================

log_test "Start Anvil"

anvil --chain-id 31337 --port "$ANVIL_PORT" --silent &
ANVIL_PID=$!
sleep 2

if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
    pass "Anvil running on port $ANVIL_PORT, chain-id=31337"
else
    fail "Anvil not responding"
    exit 1
fi

log_test "Deploy contract via CLI"

deploy_output=$("$CLI" guardian deploy \
    --rpc="$RPC" \
    --private-key="$DEPLOYER_KEY" 2>&1) || true

CONTRACT=$(echo "$deploy_output" | grep -ioP '0x[0-9a-fA-F]{40}' | tail -1)

if [ -n "$CONTRACT" ]; then
    pass "Deployed at $CONTRACT"
else
    fail "Deploy failed"
    echo "$deploy_output"
    exit 1
fi

code=$(cast code "$CONTRACT" --rpc-url "$RPC" 2>/dev/null)
if [ "$code" != "0x" ] && [ -n "$code" ]; then
    pass "Bytecode verified on chain"
else
    fail "No bytecode"
    exit 1
fi

log_test "CLI --version"

version_output=$("$CLI" --version 2>&1)
if echo "$version_output" | grep -q "devicepass-cli"; then
    pass "$version_output"
else
    fail "Version failed: $version_output"
fi

# ============================================================
log_section "Part C: Device-Side Commands (in container)"
# ============================================================

if [ "$HAVE_CONTAINER" = "1" ]; then

    # Push updated scripts into the running container
    printf "  Syncing updated scripts into container...\n"
    pv_copy "${SCRIPT_DIR}/devicepass-cli" "/usr/bin/devicepass-cli"
    for f in signing.sh config.sh display.sh identity.sh; do
        pv_copy "${SCRIPT_DIR}/../lib/devicepass/$f" "/usr/lib/devicepass/$f"
    done
    for f in claim.sh common.sh; do
        pv_copy "${SCRIPT_DIR}/../lib/devicepass/guardian/$f" "/usr/lib/devicepass/guardian/$f"
    done

    log_test "Device init (identity generation)"

    # Reset identity for clean test
    pv_exec "rm -f /var/lib/devicepass/device.*" || true
    init_output=$(pv_exec "devicepass-cli dev init" 2>&1)

    if echo "$init_output" | grep -qi "identity created\|Address:"; then
        pass "Identity generated"
    else
        fail "Init failed"
        echo "$init_output"
    fi

    # Verify files
    files_output=$(pv_exec "ls /var/lib/devicepass/")
    for f in device.key device.pub.hex device.address device.id; do
        if echo "$files_output" | grep -q "$f"; then
            pass "File exists: $f"
        else
            fail "Missing file: $f"
        fi
    done

    # Check key permissions
    perms=$(pv_exec "ls -la /var/lib/devicepass/device.key" | awk '{print $1}')
    if echo "$perms" | grep -q "rw-------"; then
        pass "device.key permissions are 600"
    else
        fail "device.key permissions wrong: $perms"
    fi

    log_test "Device status"

    status_output=$(pv_exec "devicepass-cli dev status")
    if echo "$status_output" | grep -qi "Address:.*0x"; then
        pass "Status shows address"
    else
        fail "Status missing address"
        echo "$status_output"
    fi

    if echo "$status_output" | grep -qi "ID:.*dp-"; then
        pass "Status shows device ID"
    else
        fail "Status missing device ID"
    fi

    log_test "Device export-key"

    pubhex=$(pv_exec "devicepass-cli dev export-key")
    publen=${#pubhex}
    # 128 hex chars + possible newline
    if [ "$publen" -ge 128 ] && [ "$publen" -le 130 ]; then
        pass "Public key is 128 hex chars ($publen)"
    else
        fail "Public key unexpected length: $publen"
    fi

    log_test "Device onboard (open claim)"

    DEVICE_ADDR=$(pv_exec "cat /var/lib/devicepass/device.address" | tr -d '[:space:]')
    open_blob=$(pv_exec "env DEVICEPASS_CHAIN_ID=31337 DEVICEPASS_CONTRACT=$CONTRACT devicepass-cli dev onboard --quiet")

    if echo "$open_blob" | jq -e '.device' >/dev/null 2>&1; then
        pass "Open claim blob is valid JSON"
    else
        fail "Open claim blob invalid"
        echo "$open_blob"
    fi

    blob_version=$(echo "$open_blob" | jq -r '.version')
    if [ "$blob_version" = "2" ]; then
        pass "Blob version is 2"
    else
        fail "Blob version is $blob_version (expected 2)"
    fi

    blob_guardian=$(echo "$open_blob" | jq -r '.guardian')
    if [ "$blob_guardian" = "$ZERO_ADDR" ]; then
        pass "Open blob has zero guardian"
    else
        fail "Open blob guardian: $blob_guardian (expected zero)"
    fi

    sig_len=$(echo "$open_blob" | jq -r '.signature' | wc -c)
    # 0x + 130 hex + newline = 133
    if [ "$sig_len" -ge 132 ] && [ "$sig_len" -le 134 ]; then
        pass "Signature is 65 bytes (130 hex)"
    else
        fail "Signature unexpected length: $sig_len"
    fi

    log_test "Device onboard (guardian-bound)"

    bound_blob=$(pv_exec "env DEVICEPASS_CHAIN_ID=31337 DEVICEPASS_CONTRACT=$CONTRACT devicepass-cli dev onboard --quiet --guardian=$GUARDIAN1_ADDR")

    bound_guardian=$(echo "$bound_blob" | jq -r '.guardian')
    if echo "$bound_guardian" | grep -qi "$GUARDIAN1_ADDR"; then
        pass "Bound blob has correct guardian"
    else
        fail "Bound blob guardian: $bound_guardian"
    fi

    log_test "Device init refuses re-init"

    reinit_output=$($DOCKER_EXEC pventer -c "$CONTAINER" "devicepass-cli dev init" 2>&1) || true
    if echo "$reinit_output" | grep -qi "already exists"; then
        pass "Re-init rejected"
    else
        fail "Re-init should have been rejected"
        echo "$reinit_output"
    fi

    # ============================================================
    log_section "Part D: Real Device → Guardian Claim Flow"
    # ============================================================

    log_test "Guardian claims real device open blob"

    echo "$open_blob" > /tmp/e2e-claim-device-open.json

    claim_output=$("$CLI" guardian claim \
        --rpc="$RPC" \
        --contract="$CONTRACT" \
        --private-key="$GUARDIAN1_KEY" \
        /tmp/e2e-claim-device-open.json 2>&1) || true

    if echo "$claim_output" | grep -qi "claimed successfully"; then
        pass "Real device open claim succeeded"
    else
        fail "Real device open claim failed"
        echo "$claim_output"
    fi

    passport=$(cast call --rpc-url "$RPC" "$CONTRACT" \
        "passports(address)(address,address,uint256,bool)" "$DEVICE_ADDR" 2>/dev/null)
    if echo "$passport" | grep -qi "true"; then
        pass "Real device passport active on chain"
    else
        fail "Real device passport not active"
        echo "$passport"
    fi

    # Revoke so we can re-claim with guardian-bound blob
    cast send --rpc-url "$RPC" --private-key "$GUARDIAN1_KEY" \
        "$CONTRACT" "revokeDevice(address)" "$DEVICE_ADDR" >/dev/null 2>&1

    log_test "Guardian claims real device guardian-bound blob"

    # Device generates a new bound blob (needs new identity since nonce was used)
    pv_exec "rm -f /var/lib/devicepass/device.*"
    pv_exec "devicepass-cli dev init" >/dev/null

    DEVICE_ADDR2=$(pv_exec "cat /var/lib/devicepass/device.address" | tr -d '[:space:]')
    bound_blob2=$(pv_exec "env DEVICEPASS_CHAIN_ID=31337 DEVICEPASS_CONTRACT=$CONTRACT devicepass-cli dev onboard --quiet --guardian=$GUARDIAN1_ADDR")
    echo "$bound_blob2" > /tmp/e2e-claim-device-bound.json

    claim_output=$("$CLI" guardian claim \
        --rpc="$RPC" \
        --contract="$CONTRACT" \
        --private-key="$GUARDIAN1_KEY" \
        /tmp/e2e-claim-device-bound.json 2>&1) || true

    if echo "$claim_output" | grep -qi "claimed successfully"; then
        pass "Real device guardian-bound claim succeeded"
    else
        fail "Real device guardian-bound claim failed"
        echo "$claim_output"
    fi

    passport=$(cast call --rpc-url "$RPC" "$CONTRACT" \
        "passports(address)(address,address,uint256,bool)" "$DEVICE_ADDR2" 2>/dev/null)
    if echo "$passport" | grep -qi "$GUARDIAN1_ADDR"; then
        pass "Guardian matches bound address on chain"
    else
        fail "Guardian mismatch on chain"
        echo "$passport"
    fi

    log_test "Guardian-bound blob rejected by wrong guardian (real device)"

    # New device for this test
    pv_exec "rm -f /var/lib/devicepass/device.*"
    pv_exec "devicepass-cli dev init" >/dev/null

    DEVICE_ADDR3=$(pv_exec "cat /var/lib/devicepass/device.address" | tr -d '[:space:]')
    mismatch_blob=$(pv_exec "env DEVICEPASS_CHAIN_ID=31337 DEVICEPASS_CONTRACT=$CONTRACT devicepass-cli dev onboard --quiet --guardian=$GUARDIAN1_ADDR")
    echo "$mismatch_blob" > /tmp/e2e-claim-device-mismatch.json

    # Submit with WRONG guardian (guardian2 instead of guardian1)
    claim_output=$("$CLI" guardian claim \
        --rpc="$RPC" \
        --contract="$CONTRACT" \
        --private-key="$GUARDIAN2_KEY" \
        /tmp/e2e-claim-device-mismatch.json 2>&1) || true

    if echo "$claim_output" | grep -qi "failed\|revert\|error"; then
        pass "Wrong guardian correctly rejected"
    else
        fail "Wrong guardian was NOT rejected"
        echo "$claim_output"
    fi

    passport=$(cast call --rpc-url "$RPC" "$CONTRACT" \
        "passports(address)(address,address,uint256,bool)" "$DEVICE_ADDR3" 2>/dev/null)
    if echo "$passport" | grep -qi "false"; then
        pass "Device remains unclaimed"
    else
        fail "Device was unexpectedly claimed"
    fi

else
    skip "Device-side tests (no container)"
    skip "Real device claim flow (no container)"
fi

# ============================================================
log_section "Part E: Host-Only Guardian-Bound Claims (cast-simulated)"
# ============================================================

log_test "Open claim (cast-simulated device)"

SYNTH_KEY1=$(cast wallet new --json 2>/dev/null | jq -r '.[0].private_key')
SYNTH_ADDR1=$(cast wallet address --private-key "$SYNTH_KEY1")

make_claim_blob "$SYNTH_KEY1" "$ZERO_ADDR" 5000001 "$CONTRACT" > /tmp/e2e-claim-synth-open.json

claim_output=$("$CLI" guardian claim \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN1_KEY" \
    /tmp/e2e-claim-synth-open.json 2>&1) || true

if echo "$claim_output" | grep -qi "claimed successfully"; then
    pass "Synthetic open claim succeeded"
else
    fail "Synthetic open claim failed"
    echo "$claim_output"
fi

log_test "Guardian-bound claim (cast-simulated, matching)"

SYNTH_KEY2=$(cast wallet new --json 2>/dev/null | jq -r '.[0].private_key')
SYNTH_ADDR2=$(cast wallet address --private-key "$SYNTH_KEY2")

make_claim_blob "$SYNTH_KEY2" "$GUARDIAN1_ADDR" 6000001 "$CONTRACT" > /tmp/e2e-claim-synth-bound.json

claim_output=$("$CLI" guardian claim \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN1_KEY" \
    /tmp/e2e-claim-synth-bound.json 2>&1) || true

if echo "$claim_output" | grep -qi "claimed successfully"; then
    pass "Synthetic bound claim matched"
else
    fail "Synthetic bound claim failed"
    echo "$claim_output"
fi

log_test "Guardian-bound claim (cast-simulated, mismatch)"

SYNTH_KEY3=$(cast wallet new --json 2>/dev/null | jq -r '.[0].private_key')

make_claim_blob "$SYNTH_KEY3" "$GUARDIAN1_ADDR" 7000001 "$CONTRACT" > /tmp/e2e-claim-synth-mismatch.json

claim_output=$("$CLI" guardian claim \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN2_KEY" \
    /tmp/e2e-claim-synth-mismatch.json 2>&1) || true

if echo "$claim_output" | grep -qi "failed\|revert\|error"; then
    pass "Synthetic mismatch rejected"
else
    fail "Synthetic mismatch was NOT rejected"
    echo "$claim_output"
fi

# ============================================================
log_section "Part F: Guardian Management Commands"
# ============================================================

log_test "Guardian list"

list_output=$("$CLI" guardian list \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN1_KEY" 2>&1) || true

# Count devices on chain
count=$(cast call --rpc-url "$RPC" "$CONTRACT" \
    "guardianDeviceCount(address)(uint256)" "$GUARDIAN1_ADDR" 2>/dev/null | tr -d '[:space:]' | sed 's/\[.*\]//')

if [ "$count" -ge 2 ] 2>/dev/null; then
    pass "Guardian has $count devices on chain"
else
    fail "Expected >=2 devices, got: $count"
fi

if echo "$list_output" | grep -qi "device\|0x"; then
    pass "List CLI output shows devices"
else
    fail "List CLI output unexpected"
    echo "$list_output"
fi

log_test "Guardian balance + fund"

# Pick one of our claimed devices for balance/fund test
FUND_DEVICE="$SYNTH_ADDR1"

bal_output=$("$CLI" guardian balance \
    --rpc="$RPC" --private-key="$GUARDIAN1_KEY" "$FUND_DEVICE" 2>&1) || true

if echo "$bal_output" | grep -qi "0\|balance\|ETH"; then
    pass "Balance command works"
else
    fail "Balance command failed"
    echo "$bal_output"
fi

fund_output=$("$CLI" guardian fund \
    --rpc="$RPC" --private-key="$GUARDIAN1_KEY" "$FUND_DEVICE" 0.01 2>&1) || true

if echo "$fund_output" | grep -qi "fund\|success\|sent\|tx"; then
    pass "Fund command works"
else
    # Verify balance changed
    new_bal=$(cast balance "$FUND_DEVICE" --rpc-url "$RPC" 2>/dev/null)
    if [ "$new_bal" != "0" ]; then
        pass "Fund verified via balance check ($new_bal wei)"
    else
        fail "Fund failed"
        echo "$fund_output"
    fi
fi

log_test "Guardian status"

status_output=$("$CLI" guardian status \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN1_KEY" \
    "$SYNTH_ADDR2" 2>&1) || true

if echo "$status_output" | grep -qi "true\|active"; then
    pass "Status shows device info"
else
    fail "Status failed"
    echo "$status_output"
fi

log_test "Guardian transfer + revoke"

transfer_output=$("$CLI" guardian transfer \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN1_KEY" \
    "$SYNTH_ADDR2" "$GUARDIAN2_ADDR" 2>&1) || true

passport=$(cast call --rpc-url "$RPC" "$CONTRACT" \
    "passports(address)(address,address,uint256,bool)" "$SYNTH_ADDR2" 2>/dev/null)
if echo "$passport" | grep -qi "$GUARDIAN2_ADDR"; then
    pass "Transfer verified on chain"
else
    fail "Transfer failed"
    echo "$passport"
fi

revoke_output=$("$CLI" guardian revoke \
    --rpc="$RPC" --contract="$CONTRACT" --private-key="$GUARDIAN2_KEY" \
    "$SYNTH_ADDR2" 2>&1) || true

passport=$(cast call --rpc-url "$RPC" "$CONTRACT" \
    "passports(address)(address,address,uint256,bool)" "$SYNTH_ADDR2" 2>/dev/null)
if echo "$passport" | grep -qi "false"; then
    pass "Revoke verified on chain (active=false)"
else
    fail "Revoke failed"
    echo "$passport"
fi

# ===== Summary =====

printf "\n${BOLD}================================================${NC}\n"
printf "${BOLD}Results: %d passed, %d failed${NC}\n" "$PASS" "$FAIL"
printf "${BOLD}================================================${NC}\n"

if [ "$FAIL" -gt 0 ]; then
    printf "${RED}SOME TESTS FAILED${NC}\n"
    exit 1
else
    printf "${GREEN}ALL TESTS PASSED${NC}\n"
    exit 0
fi
