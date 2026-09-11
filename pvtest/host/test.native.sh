#!/bin/bash

# Native counterpart of test.docker.sh: runs the pvtest tester on this host
# instead of in a container. See docs/testing/native.md.

PVTEST_LOG_SOURCE=test.native.sh
PVTEST_LOG_HOST="$(hostname 2>/dev/null || echo host)"

_pvtest_root="$(dirname "$0")"
[ -r "$_pvtest_root/pvtest/common" ] || _pvtest_root="$_pvtest_root/.."
. "$_pvtest_root/pvtest/common" || exit 1
. "$_pvtest_root/pvtest/host-common" || exit 1

usage() {
	echo ""
	echo "Usage: $0 [options] <command> [arguments]"
	echo "Run pvtests against a real device with no container runtime"
	echo ""
	echo "Options:"
	echo "  -h, --help    Display this help message"
	echo "  -v, --verbose Print debug logs"
	echo ""
	echo "Commands:"
	echo "  add <scope/category/name>            Create a new test"
	echo "  check                                Report host readiness and exit"
	echo "  install-scripts [prefix]             Install the runner scripts system-wide"
    echo "                                       (default prefix: /usr/local). Optional:"
    echo "                                       'run' uses the in-tree copies."
	echo "  install-tarballs <target> [path]...  Install container tarballs for"
    echo "                                       a target"
	echo "  ls                                   List all tests"
	echo "  run [path]                           Run one to many tests"
	echo ""
	echo "Arguments for 'run' command:"
	echo "  --device NAME|FILE    Required. Device manifest, as for test.docker.sh:"
    echo "                        NAME is ~/.config/pvtest/devices/NAME.txt, FILE is"
    echo "                        a path to the manifest"
	echo "  -i, --interactive     Open a tester shell wired to the device"
	echo "  -m, --manual          Open a shell on the device itself through exec="
	echo "  -o, --overwrite       Create or overwrite the test golden output"
	echo "  --fail-on-skip        Exit non-zero if any test is SKIPPED, for any"
    echo "                        reason"
	echo "  --hub URL             Hub the run targets (default:"
    echo "                        https://api.pantahub.com)"
	echo "  --model MODEL         persistent (default) or volatile, which flashes"
    echo "                        the board before every test and needs flash="
    echo "                        in the manifest"
	echo "  -w, --work PATH       Set workspace path for logs (default: mktemp)"
	echo ""
	echo "Path selectors for 'run' command:"
	echo "  (none)              Run all tests"
	echo "  local               Run all local scope tests"
	echo "  local/lifecycle     Run all lifecycle category tests"
	echo "  local/lifecycle/foo Run a specific test"
	echo ""
	echo "Environments:"
	echo "  PVTEST_SCRIPTS_DIR  Runner scripts to use (default: <distro>/pvtest)"
	echo "  PVTEST_DEVICE_TYPE  Target class matched against a test's"
    echo "                      \"devices\" array"
	echo "  PVTEST_HUB_URL      Same as --hub"
	echo ""
	echo "The appengine pool needs a container runtime; use test.docker.sh for it."
	echo ""
	echo "See README.md and docs/testing/native.md."
	echo ""
}

# --- runner scripts ---------------------------------------------------------

# Absolute dir holding pvtest-run, utils and common
_scripts_dir() {
	local d="${PVTEST_SCRIPTS_DIR:-$_pvtest_root/pvtest}"
	[ -d "$d" ] || return 1
	( cd "$d" && pwd )
}

# True when the runner in $1 honours the relocation override named in $2
_scripts_support() {
	grep -q "^$2=" "$1/pvtest-run" 2>/dev/null
}

# Tools the tester half needs on this host. pvcontrol/pventer/pvcurl/pvtx are
# NOT among them: with a device manifest every target command is forwarded
# through exec=, so they run on the board.
_NATIVE_TOOLS="bash jq curl ssh script flock timeout mktemp sed tar stty"

# pvr is the one dependency no distro packages, so the tarball may carry a
# static build of it. A pvr on PATH always wins; the bundled one is used only
# if it actually executes here (it is built for the tarball's architecture).
_bundled_pvr() {
	local d
	d=$(_scripts_dir) || return 1
	printf '%s/bin/pvr' "$d"
}

_pvr_usable() { [ -x "$1" ] && "$1" --version > /dev/null 2>&1; }

# Echo a directory to prepend to PATH so the runner finds a pvr, or nothing
_pvr_path_prefix() {
	local b
	command -v pvr > /dev/null 2>&1 && return 0
	b=$(_bundled_pvr) || return 0
	_pvr_usable "$b" && printf '%s' "${b%/pvr}"
	return 0
}

# Presence is not enough: busybox ships most of these but not the flags the
# runner needs, and the difference only shows up mid-run. Each probe is the
# exact usage from the runner or from host-common.
_probe_tool() {
	local what="$1"; shift
	"$@" > /dev/null 2>&1 && return 0
	pvtest_log ERROR "host tool lacks required behaviour: $what"
	return 1
}

_check_host() {
	local missing="" t rc=0
	for t in $_NATIVE_TOOLS; do
		command -v "$t" > /dev/null 2>&1 || missing="${missing:+$missing }$t"
	done
	if [ -n "$missing" ]; then
		pvtest_log ERROR "missing host tool(s): $missing"
		rc=1
	fi

	if [ -z "$missing" ]; then
		# timeout --foreground: every forwarded command and each test's bound
		_probe_tool "timeout --foreground (need coreutils, not busybox)" \
			timeout --foreground 1 true || rc=1
		# sed -u: streams the serial console into <device>.log
		_probe_tool "sed -u (need GNU sed, not busybox)" \
			sh -c 'echo x | sed -u s/x/y/' || rc=1
		# script -q -c: wraps every test script, and its pty is why goldens are CRLF
		_probe_tool "script -q -c (need util-linux)" \
			script -q -c true /dev/null || rc=1
		# cp -as: builds the suite symlink farm
		_probe_tool "cp -as (need GNU coreutils)" \
			sh -c 't=$(mktemp -d) || exit 1
			       mkdir -p "$t/src" && : > "$t/src/f"
			       cp -as "$t/src" "$t/dst"; r=$?
			       [ "$r" = 0 ] && [ -L "$t/dst/f" ] || r=1
			       rm -rf "$t"; exit $r' || rc=1
	fi

	local _b
	if command -v pvr > /dev/null 2>&1; then
		pvtest_log INFO "pvr: $(command -v pvr) (host)"
	elif _b=$(_bundled_pvr) && [ -e "$_b" ]; then
		if _pvr_usable "$_b"; then
			pvtest_log INFO "pvr: $_b (bundled, static)"
		else
			pvtest_log ERROR "bundled pvr at $_b does not run here (wrong architecture?)"
			pvtest_log ERROR "  install pvr on PATH, or use the scripts tarball built for this host's arch"
			rc=1
		fi
	else
		pvtest_log ERROR "no pvr on PATH and none bundled — install the Pantacor pvr binary"
		rc=1
	fi

	local sdir
	if ! sdir=$(_scripts_dir) || [ ! -f "$sdir/pvtest-run" ]; then
		pvtest_log ERROR "runner scripts not found (looked in ${PVTEST_SCRIPTS_DIR:-$_pvtest_root/pvtest})"
		return 1
	fi
	pvtest_log INFO "runner scripts: $sdir"

	local o
	for o in PVTEST_LIBDIR PVTEST_ROOT; do
		if _scripts_support "$sdir" "$o"; then
			pvtest_log INFO "  $o override: yes"
		else
			pvtest_log WARN "  $o override: no — falling back to a mount namespace"
		fi
	done

	if ! _scripts_support "$sdir" PVTEST_LIBDIR || ! _scripts_support "$sdir" PVTEST_ROOT; then
		if ! unshare -Um --map-root-user true > /dev/null 2>&1; then
			pvtest_log ERROR "unprivileged user namespaces unavailable, and the runner needs the fallback"
			rc=1
		fi
		if ! _scripts_support "$sdir" PVTEST_ROOT && [ ! -d /work ]; then
			pvtest_log ERROR "this runner predates PVTEST_ROOT and /work does not exist"
			pvtest_log ERROR "  either use a newer pantavisor-pvtest, or: sudo mkdir /work"
			rc=1
		fi
	fi

	[ "$rc" -eq 0 ] && pvtest_log INFO "host is ready for native runs"
	return $rc
}

install_scripts() {
	local prefix="${1:-/usr/local}" sdir
	sdir=$(_scripts_dir) || { pvtest_log ERROR "no runner scripts to install"; exit 1; }

	local bindir="$prefix/bin" libdir="$prefix/share/pantavisor/pvtest"
	local sudo=
	[ -w "$prefix" ] || sudo=sudo

	$sudo install -d "$bindir" "$libdir" || exit 1
	$sudo install -m 0755 "$sdir/pvtest-run" "$bindir/pvtest-run" || exit 1
	$sudo install -m 0644 "$sdir/utils" "$sdir/common" "$libdir/" || exit 1

	pvtest_log INFO "installed $bindir/pvtest-run and $libdir/{utils,common}"
	if [ "$libdir" != "/usr/share/pantavisor/pvtest" ]; then
		pvtest_log INFO "export PVTEST_LIBDIR=$libdir to use them outside this script"
	fi
}

# --- suite farm -------------------------------------------------------------

# The suites are one shared tree and the tarballs vary per target, which the
# container run resolves with a bind mount over <scope>/common/tarballs. With no
# mounts, mirror the tree as symlinks in the workspace and point that one
# directory at the target's tarballs. Writes (a regenerated golden) follow the
# symlink back to the real file, exactly as the bind mount does.
_build_suite_farm() {
	local farm="$1" targets="$2" scope

	mkdir -p "$farm" || return 1
	for scope in local remote; do
		[ -d "$test_dir/$scope" ] || continue
		cp -as "$(cd "$test_dir/$scope" && pwd)" "$farm/$scope" || return 1
		rm -rf "$farm/$scope/common/tarballs"
		if [ -d "$targets/$scope" ]; then
			ln -s "$targets/$scope" "$farm/$scope/common/tarballs" || return 1
		fi
	done
	return 0
}

# --- launching the tester ---------------------------------------------------

# Run pvtest-run with the env the tester container would have been given.
# $@ is passed through to the runner.
_run_tester() {
	local sdir farm_root
	sdir=$(_scripts_dir) || return 1
	farm_root="$1"; shift

	# Exported, not passed in env_args: the legacy namespace branch below runs
	# through a plain `env`, so it has to be on the inherited environment.
	local _pvrdir
	_pvrdir=$(_pvr_path_prefix)
	[ -n "$_pvrdir" ] && export PATH="$_pvrdir:$PATH"

	local -a env_args=(
		"PVTEST_LIBDIR=$sdir"
		"PVTEST_ROOT=$farm_root"
	)

	if _scripts_support "$sdir" PVTEST_LIBDIR && _scripts_support "$sdir" PVTEST_ROOT; then
		env "${env_args[@]}" "$@" bash "$sdir/pvtest-run"
		return $?
	fi

	# Legacy runner: put the scripts and the suites where it still expects them,
	# in a private mount namespace so the host keeps no trace of either.
	local ns_tmp
	ns_tmp=$(mktemp -d -t pvtest_ns.XXXXXX) || return 1
	mkdir -p "$ns_tmp/upper" "$ns_tmp/work" || return 1

	pvtest_log WARN "runner predates the relocation overrides; using a mount namespace"
	local rc=0
	env "$@" unshare -Um --map-root-user bash -c '
		set -e
		mount -t overlay overlay \
			-olowerdir=/usr/share,upperdir="$1/upper",workdir="$1/work" /usr/share
		mkdir -p /usr/share/pantavisor/pvtest
		mount --bind "$2" /usr/share/pantavisor/pvtest
		mount --bind "$3" /work
		exec bash /usr/share/pantavisor/pvtest/pvtest-run
	' _ "$ns_tmp" "$sdir" "$farm_root" || rc=$?
	rm -rf "$ns_tmp"
	return $rc
}

# --- run --------------------------------------------------------------------

_native_cleanup() {
	trap - INT TERM
	local p
	[ -n "$ctrl_dir" ] && touch "$ctrl_dir/stop" 2>/dev/null
	for p in $(jobs -p); do kill -TERM "$p" > /dev/null 2>&1 || true; done
	[ -n "$_dev_name" ] && _release_device
	release_slot
}

_abort_native() {
	pvtest_log WARN "interrupted — releasing device and stopping the ctrl service"
	_native_cleanup
	exit 130
}

run_test() {
	local target_path=
	local overwrite="false"
	local interactive="false"
	local manual="false"
	local work_path=
	local fail_on_skip="false"
	local device_file= hub_url= model="persistent"
	local ctrl_dir=
	local _logtee_pid=

	if [ -n "$1" ] && [ "$(printf '%s' "$1" | cut -c1)" != "-" ]; then
		target_path="$1"
		shift
	fi

	[ "$target_path" = "all" ] && target_path=

	while [ $# -gt 0 ]; do
		case "$1" in
			-o|--overwrite) overwrite="true"; shift ;;
			-i|--interactive) interactive="true"; shift ;;
			-m|--manual) interactive="true"; manual="true"; shift ;;
			-w|--work) work_path="$2"; shift 2 ;;
			--fail-on-skip) fail_on_skip="true"; shift ;;
			--device)
				case "${2:-}" in
					""|-*)
						pvtest_log ERROR "--device needs a manifest NAME or FILE"
						usage
						exit 1
						;;
				esac
				device_file="$2"
				shift 2
				;;
			--hub)
				case "${2:-}" in
					""|-*)
						pvtest_log ERROR "--hub needs a URL"
						usage
						exit 1
						;;
				esac
				hub_url="$2"
				shift 2
				;;
			--model)
				case "${2:-}" in
					persistent|volatile) model="$2"; shift 2 ;;
					*)
						pvtest_log ERROR "invalid --model '${2:-}' (expected persistent or volatile)"
						usage
						exit 1
						;;
				esac
				;;
			*)
				pvtest_log ERROR "Unknown argument: $1"
				usage
				exit 1
				;;
		esac
	done

	# The appengine pool is the one thing that genuinely needs a container
	# runtime: its targets ARE containers. Everything below this point is
	# target-agnostic, so growing a native pool means adding a retype mechanism
	# that boots the appengine rootfs under unshare and replying 'ready' on the
	# same ctrl protocol — no other part of this script changes.
	if [ -z "$device_file" ]; then
		pvtest_log ERROR "--device is required: the native runner drives a real device"
		pvtest_log ERROR "  the appengine pool needs a container runtime — use test.docker.sh"
		exit 1
	fi

	if [ -n "$PVTEST_EXEC" ] || [ -n "$PVTEST_HOST" ]; then
		pvtest_log ERROR "--device is incompatible with pre-set PVTEST_EXEC/PVTEST_HOST"
		exit 1
	fi

	_resolve_device_file || exit 1
	_resolve_hub_url "$hub_url" || exit 1

	if [ "$interactive" = "true" ] && [ "$overwrite" = "true" ]; then
		pvtest_log ERROR "Cannot use overwrite and interactive at the same time"
		usage
		exit 1
	fi

	if [ "$interactive" = "true" ] && [ "$manual" = "false" ]; then
		if [ -z "$target_path" ] || [ ! -f "$test_dir/$target_path/test.json" ]; then
			pvtest_log ERROR "Interactive mode requires a specific test path"
			usage
			exit 1
		fi
	fi

	_check_host || exit 1

	[ -n "$work_path" ] || work_path=$(mktemp -d -t pv_native.XXXXXX)
	mkdir -p "$work_path"

	{
	pvtest_log DEBUG "workspace=$work_path"
	pvtest_log DEBUG "run log=$work_path/run.log"
	pvtest_log DEBUG "test log=$work_path/results/<scope>/<category>/<name>/test.log"
	pvtest_log DEBUG "diff=$work_path/results/<scope>/<category>/<name>/diff"
	} | tee -a "$work_path/run.log"

	allocate_slot || return 1
	trap '_abort_native' INT TERM

	_parse_device_manifest "$device_file" || { release_slot; return 1; }
	local PVTEST_LOG_TAG="$_dev_name"
	if [ "$model" = "volatile" ]; then
		if [ "$interactive" = "true" ]; then
			pvtest_log ERROR "--model does not apply to -i/-m"
			release_slot
			return 1
		fi
		if [ -z "$_dev_flash" ]; then
			pvtest_log ERROR "--model volatile needs flash= in '$device_file'; use --model persistent"
			release_slot
			return 1
		fi
	fi

	_lock_device "$_dev_name" || { release_slot; return 1; }
	_start_device_capture "$_dev_name" "$_dev_tty" "$_dev_baud" \
		|| pvtest_log ERROR "failed to start tty capture for device '$_dev_name'"

	local retype_mech=none
	if [ "$model" = "volatile" ]; then
		retype_mech=flash
	elif [ -n "$_dev_setbootconfig" ]; then
		retype_mech=setbootconfig
	fi

	local target_type
	target_type="${PVTEST_DEVICE_TYPE:-${_dev_type:-appengine}}"
	if [ ! -d "$test_dir/targets/$target_type" ]; then
		pvtest_log ERROR "no container tarballs for target type '$target_type'"
		pvtest_log ERROR "  expected: $test_dir/targets/$target_type/{local,remote}"
		pvtest_log ERROR "  available: $(ls "$test_dir/targets" 2>/dev/null | tr '\n' ' ')"
		pvtest_log ERROR "  add one with: $0 install-tarballs $target_type <exports>"
		_native_cleanup
		return 1
	fi
	local abs_targets
	abs_targets="$(cd "$test_dir/targets/$target_type" && pwd)"
	pvtest_log INFO "target type: $target_type (tarballs from targets/$target_type)" \
		| tee -a "$work_path/run.log"

	if [ "$manual" = "true" ]; then
		pvtest_log INFO "manual: entering device '$_dev_name' as it is (test config.env not applied)"
		$_dev_exec
		_native_cleanup
		return 0
	fi

	local farm="$work_path/suites"
	if ! _build_suite_farm "$farm" "$abs_targets"; then
		pvtest_log ERROR "failed to stage the suite tree at $farm"
		_native_cleanup
		return 1
	fi

	local -a dev_env=(
		"PVTEST_EXEC=$_dev_exec"
		"PVTEST_HOST=$_dev_ip"
		"PVTEST_DEVICE_TYPE=$target_type"
		"PVTEST_DEVICE_NAME=$_dev_name"
		"PVTEST_RETYPE=$retype_mech"
		"PH_USER=$PH_USER"
		"PH_PASS=$PH_PASS"
		"PVTEST_HUB_URL=$PVTEST_HUB_URL"
		"PVR_DISABLE_SELF_UPGRADE=true"
		"PV_LOG_SERVER_OUTPUTS=filetree,stdout_direct"
		"PV_LOG_TIMESTAMP=absolute"
		"VERBOSE=$verbose"
		"OVERWRITE=$overwrite"
		"NETSIM=false"
	)

	if [ "$interactive" = "true" ]; then
		_run_tester "$farm" "${dev_env[@]}" \
			"TEST_PATH=$farm/$target_path" \
			"INTERACTIVE=true"
		_native_cleanup
		return $?
	fi

	local pvtest_queue="" _json _findroot="$farm" _qfile
	[ -n "$target_path" ] && _findroot="$farm/$target_path"
	# A plain file, not `done < <(find ...)`: process substitution needs /dev/fd,
	# which a mount namespace (e.g. a lab DUT container) need not provide.
	_qfile=$(mktemp) || { pvtest_log ERROR "mktemp failed"; _native_cleanup; return 1; }
	find "$_findroot" -name test.json 2>/dev/null | sort > "$_qfile"
	while IFS= read -r _json; do
		[ -n "$_json" ] || continue
		pvtest_queue="${pvtest_queue:+$pvtest_queue }$_json"
	done < "$_qfile"
	rm -f "$_qfile"

	if [ -z "$pvtest_queue" ]; then
		pvtest_log WARN "no tests found under '${target_path:-<all>}'"
		_native_cleanup
		return 0
	fi

	ctrl_dir="$work_path/ctrl"
	mkdir -p "$ctrl_dir/req" "$ctrl_dir/resp" "$ctrl_dir/state" "$work_path/results"

	local _nq
	_nq=$(printf '%s\n' $pvtest_queue | grep -c .)
	pvtest_log INFO "=== ${model} pool: ${_nq} test(s) on device '$_dev_name' ==="

	# A board flash takes minutes where a re-type returns as soon as the reboot starts
	local retype_timeout="${PVTEST_RETYPE_TIMEOUT:-300}"
	[ "$retype_mech" = "flash" ] && retype_timeout="${PVTEST_RETYPE_TIMEOUT:-3600}"

	# A fifo, not `exec > >(tee ...)`: process substitution needs /dev/fd, which
	# a mount namespace need not provide — and if it fails, run.log stays empty
	# and _print_summary has nothing to summarise.
	local _logfifo="$work_path/.runlog.fifo"
	rm -f "$_logfifo"
	if mkfifo "$_logfifo" 2>/dev/null; then
		tee -a "$work_path/run.log" < "$_logfifo" &
		_logtee_pid=$!
		exec 9>&1                 # keep the real stdout to restore later
		exec > "$_logfifo" 2>&1
	else
		pvtest_log WARN "mkfifo failed; logging to run.log only"
		exec >> "$work_path/run.log" 2>&1
	fi

	# Same lifecycle service the container run uses: it answers the tester's
	# re-type requests by running the manifest's setbootconfig= or flash=, or 'unsupported'.
	_retype_service "$ctrl_dir" "$retype_mech" &
	local svc_pid=$!

	local res=0
	_run_tester "$farm" "${dev_env[@]}" \
		"TEST_PATH=$farm/$target_path" \
		"INTERACTIVE=false" \
		"PVTEST_QUEUE=$pvtest_queue" \
		"PVTEST_MODEL=$model" \
		"PVTEST_RETYPE_TIMEOUT=$retype_timeout" \
		"PVTEST_SLOTS=1" \
		"PVTEST_CTRL=$ctrl_dir" \
		"PVTEST_TESTER_NAME=pantavisor-native-${USER}-${slot}" \
		"PVTEST_TEST_TIMEOUT=${PVTEST_TEST_TIMEOUT:-1800}" \
		"APPENGINE_LOGS=$work_path" \
		"RUN_DIR=$work_path/results" \
		|| res=1

	touch "$ctrl_dir/stop"
	wait "$svc_pid" 2>/dev/null || true

	trap - INT TERM
	_release_device
	release_slot

	local skip_fail=0
	_print_summary "$work_path/run.log" || skip_fail=1

	# Summary is written, so close the log fifo and drain the tee. Restores the
	# real stdout from fd 9 rather than guessing /dev/tty, which does not exist
	# in a detached run.
	if [ -n "$_logtee_pid" ]; then
		exec 1>&9 2>&1 9>&-
		wait "$_logtee_pid" 2>/dev/null || true
		rm -f "$_logfifo"
		_logtee_pid=
	fi

	[ "${CI:-false}" = "true" ] && cp "$work_path/run.log" ./run.log

	cp "$_pvtest_root/workspace-README.md" "$work_path/README.md" 2>/dev/null \
		|| pvtest_log WARN "workspace-README.md not found beside $0"

	if [ $res -ne 0 ] || [ "$skip_fail" -ne 0 ]; then
		return 1
	fi
	return 0
}

verbose="false"
command=
test_dir=.

while [ $# -gt 0 ]; do
	case "$1" in
		-h|--help)
		usage
		exit 0
		;;
		-v|--verbose)
		set -x
		verbose="true"
		shift
		;;
	*)
		break
		;;
	esac
done

if [ $# -eq 0 ]; then
	pvtest_log ERROR "Missing command"
	usage
	exit 1
fi

command="$1"
shift

case "$command" in
	add)
		add_test "$@"
		;;
	check)
		_check_host
		;;
	install-scripts)
		install_scripts "$@"
		;;
	install-tarballs)
		install_tarballs "$@"
		;;
	ls)
		list_tests
		;;
	run)
		run_test "$@"
		;;
	*)
		pvtest_log ERROR "Unknown command: $command"
		usage
		exit 1
		;;
esac
