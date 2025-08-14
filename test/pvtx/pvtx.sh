#!/bin/sh

# set -x

err() {
	echo >&2 "Error> ${1}"
}

check_path() {
	if [ ! -e "${1}" ]; then
		err "couldn't find ${1}; test aborting"
		exit 1
	fi
}

create_path() {
	if ! mkdir -p "${1}" >/dev/null 2>&1; then
		err "couldn't create ${1}; test aborting"
		exit 1
	fi
}

CURRENT_SRC_DIR="${1}"
CURRENT_BIN_DIR="${2}"

PVTX_TMP_DIR=$(mktemp -d "${CURRENT_BIN_DIR}/pvtx.test.XXXXXX")
check_path "${PVTX_TMP_DIR}"

PVTX_TEST_DATA="${CURRENT_SRC_DIR}/test/pvtx"
check_path "${PVTX_TEST_DATA}"

PVTX_DIR="${PVTX_TMP_DIR}/pvtxdir"
create_path "${PVTX_DIR}"
export PVTXDIR="${PVTX_DIR}"

PVTX_OBJECTS="${PVTX_TMP_DIR}/objects"
create_path "${PVTX_OBJECTS}"

pvtx_app() {
	"${CURRENT_BIN_DIR}/pvtx" "${@}"
}

pvtx_null() {
	if [ -n "${PVTX_TEST_PRINT_ALL}" ]; then
		"${CURRENT_BIN_DIR}/pvtx" "${@}"
	else
		"${CURRENT_BIN_DIR}/pvtx" "${@}" >/dev/null 2>&1
	fi
}

create_tar() {
	src="${1}"
	pkg="${2}"
	(
		cd "${PVTX_TMP_DIR}" || exit 1
		cp "${src}" ./json
		tar -czf "${pkg}" json
		rm -f json
	)
}

compare_json() {
	test_name="${1}"
	orig_proc="${2}"
	orig_exp="${3}"
	proc="${PVTX_TMP_DIR}/${test_name}.process.json"
	expected="${PVTX_TMP_DIR}/${test_name}.expected.json"

	jq --sort-keys . <"${orig_proc}" >"${proc}"
	jq --sort-keys . <"${orig_exp}" >"${expected}"

	if ! diff=$(diff -u "${proc}" "${expected}") || [ -n "${diff}" ]; then
		echo
		err "${test_name} [FAILED]"
		err "result was stored at:"
		err "* ${proc}"
		err "* ${expected}"
		return 1
	fi

	printf "%-50s %s\n" "${test_name}" "[OK]"

	rm -f "${proc}"
	rm -f "${expected}"

	return 0
}

test_create_empty_transaction() {
	name="test_create_empty_transaction"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	base="${PVTX_TEST_DATA}/expected/state-empty.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${base}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_process_json_keys_with_spaces() {
	name="test_process_json_keys_with_spaces"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	base="${PVTX_TEST_DATA}/resources/state_with_spaces.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${base}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${base}"; then
		exit 1
	fi

	rm -rf "${result}"
}

remove_base_test() {
	name="${1}"
	part="${2}"
	base="${3}"
	expected="${4}"
	result="${PVTX_TMP_DIR}/result_${name}.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${base}"
	pvtx_null remove "${part}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_signature_removal() {
	name="test_signature_removal"
	part="_sigs/awconnect.json"
	base="${PVTX_TEST_DATA}/resources/initial_state.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_remove.json"

	remove_base_test "${name}" "${part}" "${base}" "${expected}"
}

test_signature_removal2() {
	name="test_signature_removal2"
	part="awconnect"
	base="${PVTX_TEST_DATA}/resources/initial_state.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_remove.json"

	remove_base_test "${name}" "${part}" "${base}" "${expected}"
}

test_signature_removal3() {
	name="test_signature_removal3"
	part="_config/awconnect"
	base="${PVTX_TEST_DATA}/resources/initial_state.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_remove.json"

	remove_base_test "${name}" "${part}" "${base}" "${expected}"
}

test_removal_config_pkg() {
	name="test_removal_config_pkg"
	part="_sigs/nginx-config.json"
	base="${PVTX_TEST_DATA}/resources/state-1.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_remove_config_pkg.json"

	remove_base_test "${name}" "${part}" "${base}" "${expected}"
}

test_package_update() {
	name="test_package_update"
	update="${PVTX_TEST_DATA}/resources/awconnect.json"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_adding_existing.json"
	pkg="${name}_$(basename ${update}).tar.gz"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/initial_state.json"

	create_tar "${update}" "${pkg}"
	pvtx_null add "${PVTX_TMP_DIR}/${pkg}"

	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${PVTX_TMP_DIR}/${pkg:?}"
	rm -rf "${result}"
}

test_add_package_from_tar() {
	name="test_add_package_from_tar"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_add_from_tar.json"

	pvtx_null abort
	pvtx_null begin empty "${PVTX_OBJECTS}"
	pvtx_null add "${PVTX_TEST_DATA}/resources/watchdog_pinger.tar"
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_add_new_package() {
	name="test_add_new_package"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	update="${PVTX_TEST_DATA}/resources/vaultwarden.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_new_package.json"
	pkg="${name}_$(basename ${update}).tar.gz"

	create_tar "${update}" "${pkg}"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/initial_state.json"
	pvtx_null add "${PVTX_TMP_DIR}/${pkg}"

	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${PVTX_TMP_DIR}/${pkg:?}"
	rm -rf "${result}"
}

test_add_new_package_from_cat() {
	name="test_add_new_package_from_cat"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_pvwificonnect.json"

	pvtx_null abort
	pvtx_null begin empty "${PVTX_OBJECTS}"
	pvtx_null add "${PVTX_TEST_DATA}/resources/initial_state.json"

	# code is disabled because this is the way how is used in production
	# shellcheck disable=SC2002
	cat "${PVTX_TEST_DATA}/resources/pvwificonnect.tgz" | pvtx_null add -

	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_update_bsp() {
	name="test_update_bsp"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_bsp_update.json"
	update="${PVTX_TEST_DATA}/resources/bsp_update.json"
	pkg="${name}_$(basename ${update}).tar.gz"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/bsp_init.json"

	create_tar "${update}" "${pkg}"
	pvtx_null add "${PVTX_TMP_DIR}/${pkg}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${PVTX_TMP_DIR}/${pkg:?}"
	rm -rf "${result}"
}

test_update_bsp_with_groups() {
	name="test_update_bsp_with_groups"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_bsp_update.json"
	update="${PVTX_TEST_DATA}/resources/bsp_update.json"
	pkg="${name}_$(basename ${update}).tar.gz"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/bsp_init_groups.json"

	create_tar "${update}" "${pkg}"
	pvtx_null add "${PVTX_TMP_DIR}/${pkg}"

	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${PVTX_TMP_DIR}/${pkg:?}"
	rm -rf "${result}"
}

test_install_from_tgz() {
	name="test_install_from_tgz"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_os_install.json"
	update="${PVTX_TEST_DATA}/resources/os.json"
	pkg="${name}_$(basename ${update}).tar.gz"

	pvtx_null abort
	pvtx_null begin empty

	create_tar "${update}" "${pkg}"

	pvtx_null add "${PVTX_TMP_DIR}/${pkg}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${PVTX_TMP_DIR}/${pkg:?}"
	rm -rf "${result}"
}

test_two_package_signing_same_files() {
	
	name="test_two_package_signing_same_files"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_install_config_b_remove_config_a.json"
	pkg="${PVTX_TEST_DATA}/resources/config_b.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/config_a.json"
	pvtx_null add "${pkg}"
	pvtx_null remove _sigs/config_a.json
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_two_package_signing_same_files_with_globs() {
	name="test_two_package_signing_same_files_with_globs"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_after_install_config_b_remove_config_a_with_glob.json"
	pkg="${PVTX_TEST_DATA}/resources/config_b_glob.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${PVTX_TEST_DATA}/resources/config_a_glob.json"
	pvtx_null add "${pkg}"
	pvtx_null remove _sigs/config_a.json
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_removal_of_signed_config() {
	name="test_removal_of_signed_config"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	pkg1="${PVTX_TEST_DATA}/resources/pvws_with_config.json"
	pkg2="${PVTX_TEST_DATA}/resources/pvws_without_config.json"
	expected1="${PVTX_TEST_DATA}/expected/state_pvws_with_config.json"
	expected2="${PVTX_TEST_DATA}/expected/state_pvws_without_config.json"

	pvtx_null abort
	pvtx_null begin empty
	pvtx_null add "${pkg1}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}_1" "${result}" "${expected1}"; then
		exit 1
	fi

	pvtx_null add "${pkg2}"
	pvtx_app show >"${result}"

	if ! compare_json "${name}_2" "${result}" "${expected2}"; then
		exit 1
	fi

	rm -rf "${result}"
}

read_int() {
	hex=$(xxd -u -c4 -g4 -l4 -e -s+"${1}" "${2}" | cut -d ' ' -f2)
	echo "ibase=16;obase=A;${hex}" | bc
}

read_string() {
	# 4096 is PATH_MAX which is used to stored the paths
	xxd -u -l4096 -g4 -c4 -s+"${1}" "${2}" |
		awk '{print $3}' |
		grep -v '\.\.\.\.' |
		xargs |
		sed 's/ //g' | sed 's/\.*$//'
}

test_queue_new() {
	name="test_queue_new"
	queue="${PVTX_TMP_DIR}/queue"
	rm -rf "${queue}"
	pvtx_null abort
	pvtx_null queue new "${queue}" "${PVTX_OBJECTS}"

	status_file="${PVTXDIR}/.status"
	offset=0
	status=$(read_int ${offset} "${status_file}")
	is_local=$(read_int $((offset + 4)) "${status_file}")
	object_path=$(read_string $((offset + 4 + 4)) "${status_file}")
	queue_path=$(read_string $((offset + 4 + 4 + 4096)) "${status_file}")

	if [ "${status}" -ne 1 ]; then
		err "${name} [FAILED]"
		err "status should be 1 found: ${status};"
		exit 1
	fi

	if [ "${is_local}" -ne 1 ]; then
		err "${name} [FAILED]"
		err "is_local should be 1 found: ${is_local};"
		exit 1
	fi

	if [ "${object_path}" != "${PVTX_OBJECTS}" ]; then
		err "${name} [FAILED]"
		err "object path differ"
		err "expected: ${PVTX_OBJECTS}"
		err "found   : ${object_path}"
		exit 1
	fi

	if [ "${queue_path}" != "${queue}" ]; then
		err "${name} [FAILED]"
		err "queue path differ"
		err "expected: ${queue}"
		err "found   : ${queue_path}"
		exit 1
	fi

	printf "%-50s %s\n" "${name}" "[OK]"
}

test_queue_actions() {
	name="test_queue_actions"
	queue="${PVTX_TMP_DIR}/queue"

	rm -rf "${queue}"

	pvtx_null queue new "${queue}" "${PVTX_OBJECTS}"
	pvtx_null queue remove "nginx"
	pvtx_null queue remove "_config/nginx"
	pvtx_null queue remove "_sigs/nginx-config.json"
	pvtx_null queue unpack "${PVTX_TEST_DATA}/resources/pvwificonnect.tgz"

	expected="000__nginx.remove  001___config%2Fnginx.remove  002___sigs%2Fnginx-config.json.remove"

	for file in ${expected}; do
		if [ -f "${queue}/${file}" ]; then
			continue
		fi
		err "${name} [FAILED]"
		exit 1
	done

	printf "%-50s %s\n" "${name}" "[OK]"
}

test_queue_process() {
	name="test_queue_process"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	expected="${PVTX_TEST_DATA}/expected/state_queue_process.json"
	queue="${PVTX_TMP_DIR}/queue"
	pvwifi_url="https://gitlab.com/pantacor/pvwificonnect/-/package_files/129853072/download"

	rm -rf "${queue}"

	pvtx_null abort
	pvtx_null queue new "${queue}" "${PVTX_OBJECTS}"
	pvtx_null queue remove "_sigs/nginx.json"

	# Download directly from gitlab
	# pvwificonnect-v1.0.0-g82ca1d7.arm32v6.tgz
	curl --silent --location "${pvwifi_url}" | pvtx_null queue unpack -

	pvtx_null begin "${PVTX_TEST_DATA}/resources/state-1.json"
	pvtx_null queue process
	pvtx_app show >"${result}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -f "${result}"
}

test_deploy() {
	name="test_deploy"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	queue="${PVTX_TMP_DIR}/queue"
	deploy="${PVTX_TMP_DIR}/deploy"
	expected="${deploy}/.pvr/json"

	rm -rf "${queue}"
	create_path "${deploy}"

	pvtx_null abort
	pvtx_null queue new "${queue}" "${PVTX_OBJECTS}"
	pvtx_null queue unpack "${PVTX_TEST_DATA}/resources/pvwificonnect.tgz"
	pvtx_null begin empty
	pvtx_null queue process
	pvtx_app show >"${result}"
	pvtx_null deploy "${deploy}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_process_queue_without_begin() {
	name="test_process_queue_without_begin"
	result="${PVTX_TMP_DIR}/result_${name}.json"
	queue="${PVTX_TMP_DIR}/queue"
	deploy="${PVTX_TMP_DIR}/deploy"
	expected="${deploy}/.pvr/json"

	rm -rf "${queue}"
	create_path "${deploy}"

	pvtx_null queue new "${queue}" "${PVTX_OBJECTS}"
	pvtx_null queue unpack "${PVTX_TEST_DATA}/resources/watchdog_pinger.tar"
	pvtx_null queue process empty
	pvtx_app show >"${result}"
	pvtx_null deploy "${deploy}"

	if ! compare_json "${name}" "${result}" "${expected}"; then
		exit 1
	fi

	rm -rf "${result}"
}

test_local_transaction() {
	name="test_local_transaction"
	expected=12

	pvtx_null abort
	pvtx_null begin empty "${PVTX_OBJECTS}"

	if [ -n "${PVTX_TEST_PRINT_ALL}" ]; then
		echo "+----NOTE: next error about local trasaction is part of the test ----------"
		echo "|"
	fi
	if pvtx_null commit; then
		result=0
	else
		result="${?}"
	fi

	if [ -n "${PVTX_TEST_PRINT_ALL}" ]; then
		echo "|"
		echo "+--------------------------------------------------------------------------"
	fi

	if [ ${result} -ne ${expected} ]; then
		err "wrong status code; expected ${expected} got ${result}"
		err "${name} [FAILED]"
		exit 1
	fi

	printf "%-50s %s\n" "${name}" "[OK]"
}

test_create_empty_transaction
test_process_json_keys_with_spaces
test_signature_removal
test_signature_removal2
test_signature_removal3
test_removal_config_pkg
test_package_update
test_add_package_from_tar
test_add_new_package
test_add_new_package_from_cat
test_update_bsp
test_update_bsp_with_groups
test_install_from_tgz
test_two_package_signing_same_files
test_two_package_signing_same_files_with_globs
test_removal_of_signed_config
test_queue_new
test_queue_actions
test_queue_process
test_deploy
test_process_queue_without_begin
test_local_transaction
