#!/bin/bash

PVTEST_LOG_SOURCE=test.docker.sh
PVTEST_LOG_HOST="$(hostname 2>/dev/null || echo host)"

_pvtest_root="$(dirname "$0")"
[ -r "$_pvtest_root/pvtest/common" ] || _pvtest_root="$_pvtest_root/.."
. "$_pvtest_root/pvtest/common" || exit 1
. "$_pvtest_root/pvtest/host-common" || exit 1

# distinct per job on a shared docker daemon, so a neighbour's cleanup can't untag our images
PVTEST_IMAGE_TAG="${PVTEST_IMAGE_TAG:-latest}"

usage() {
	echo ""
	echo "Usage: $0 [options] <command> [arguments]"
	echo "Run and create Pantavisor tests"
	echo ""
	echo "Options:"
	echo "  -h, --help    Display this help message"
	echo "  -v, --verbose Print debug logs"
	echo ""
	echo "Commands:"
	echo "  add <scope/category/name>            Create a new test"
	echo "  install-deps                         Install dependencies (and"
    echo "                                       docker)"
	echo "  install-docker                       Install docker"
	echo "  clean-docker                         Remove this install containers"
    echo "                                       and untag its images"
	echo "  install-tarballs <target> [path]...  Install container tarballs for"
    echo "                                       a target"
	echo "  ls                                   List all tests"
	echo "  run [path]                           Run one to many tests"
	echo ""
	echo "Arguments for 'run' command:"
	echo "  -i, --interactive     Open tester container console to execute a"
    echo "                        test interactively"
	echo "  -m, --manual          Open worker container console to execute"
    echo "                        Pantavisor manually"
	echo "  -n, --netsim          Run network simulator in parallel"
	echo "  -o, --overwrite       Create or overwrite the test golden output"
	echo "  -p, --parallel N      Cap on concurrent appengine worker container"
    echo "                        slots (default: 1)"
	echo "  --device NAME|FILE    Run against a real device defined at device"
    echo "                        manifest file. NAME is"
	echo "                        ~/.config/pvtest/devices/NAME.txt, FILE is a"
    echo "                        path to the manifest"
	echo "  --hub URL             Hub the run targets (default:"
    echo "                        https://api.pantahub.com)"
	echo "  --model MODEL         persistent (default) or volatile storage"
    echo "                        between tests for each worker slot"
	echo "  --fail-on-skip        Exit non-zero if any test is SKIPPED, for any"
    echo "                        reason"
	echo "  -V, --valgrind        Run Pantavisor with valgrind"
	echo "  -w, --work PATH       Set workspace path for logs/storage (default:"
    echo "                        mktemp)"
	echo ""
	echo "Path selectors for 'run' command:"
	echo "  (none)              Run all tests"
	echo "  local               Run all local scope tests"
	echo "  local/lifecycle     Run all lifecycle category tests"
	echo "  local/lifecycle/foo Run a specific test"
	echo ""
	echo "Environments:"
	echo "  NETSIM_PATH      Path to docker load for netsim container"
	echo "  TESTER_PATH      Path to docker load for tester container"
	echo "  APPENGINE_PATH   Path to docker load for appengine container"
	echo "  PVTEST_IMAGE_TAG Tag the loaded images (default: latest)"
    echo "                   for concurrency"
	echo ""
	echo "Target overrides:"
	echo "  PVTEST_EXEC         Command prefix to reach the target (e.g. \"ssh"
    echo "                      root@<ip>\")"
	echo "  PVTEST_HOST         Host/IP for pvr HTTP calls (default: localhost)"
	echo "  PVTEST_DEVICE_TYPE  Target class matched against a test's"
    echo "                      \"devices\" array"
	echo "  PVTEST_HUB_URL      Same as --hub"
	echo ""
	echo "See README.md and docs/testing/."
	echo ""
}


install_docker() {
	NETSIM_PATH=${NETSIM_PATH:-"pantavisor-appengine-netsim-docker.tar"}
	if [ -f "$NETSIM_PATH" ]; then
		docker load -i "$NETSIM_PATH"
		[ "$PVTEST_IMAGE_TAG" = "latest" ] \
			|| docker tag pantavisor-appengine-netsim:latest "pantavisor-appengine-netsim:$PVTEST_IMAGE_TAG"
	fi
	TESTER_PATH=${TESTER_PATH:-"pantavisor-appengine-tester-docker.tar"}
	if [ -f "$TESTER_PATH" ]; then
		docker load -i "$TESTER_PATH"
		[ "$PVTEST_IMAGE_TAG" = "latest" ] \
			|| docker tag pantavisor-appengine-tester:latest "pantavisor-appengine-tester:$PVTEST_IMAGE_TAG"
	fi
	APPENGINE_PATH=${APPENGINE_PATH:-"pantavisor-appengine-docker.tar"}
	if [ -f "$APPENGINE_PATH" ]; then
		docker load -i "$APPENGINE_PATH"
		[ "$PVTEST_IMAGE_TAG" = "latest" ] \
			|| docker tag pantavisor-appengine:latest "pantavisor-appengine:$PVTEST_IMAGE_TAG"
	fi
}

clean_docker() {
	local names="pantavisor-appengine pantavisor-appengine-netsim pantavisor-appengine-tester"

	local cid img n match
	while IFS= read -r cid; do
		[ -n "$cid" ] || continue
		img=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null) || continue
		match=false
		for n in $names; do
			[ "$img" = "$n:$PVTEST_IMAGE_TAG" ] && { match=true; break; }
		done
		[ "$match" = true ] && docker rm -f "$cid" > /dev/null 2>&1
	done < <(docker ps -aq)

	# no -f: untagging is enough, the image itself goes once its last tag does
	for n in $names; do
		docker rmi "$n:$PVTEST_IMAGE_TAG" > /dev/null 2>&1 || true
	done
}


install_deps() {
echo "This will install some packages in your system. Do you want to continue? [y/N]"
    if [[ "$CI_MODE" == "true" ]]; then
       answer="y"
    else
       read -n1 answer
    fi
    case "$answer" in
        y|Y)
            ;;
        *)
			exit 0
            ;;
    esac

	sudo -v

	# install and setup apt dependencies
	sudo apt update
	sudo apt install binfmt-support \
		docker.io \
		git \
		jq \
		iw \
		bc \
		linux-modules-`uname -r` \
		linux-modules-extra-`uname -r`
	sudo groupadd docker
	sudo usermod -aG docker $USER

	# install and setup qemu
	sudo apt remove qemu-user-static
	mkdir ~/bin
	wget https://pantavisor-ci.s3.amazonaws.com/qemu/1303841432/qemu-arm -O ~/bin/qemu-arm
	wget https://pantavisor-ci.s3.amazonaws.com/qemu/1303841432/qemu-aarch64 -O ~/bin/qemu-aarch64
	chmod +x ~/bin/qemu-arm
	chmod +x ~/bin/qemu-aarch64
	sudo update-binfmts --install qemu-arm ~/bin/qemu-arm --offset 0 --magic "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00" --mask "\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff" --fix-binary yes
	sudo update-binfmts --install qemu-aarch64 ~/bin/qemu-aarch64 --offset 0 --magic "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00" --mask "\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff" --fix-binary yes

	install_docker

	pvtest_log INFO "Dependency installation complete"

	exit 0
}

setup_network0() {
	# flock serializes inspect/create so concurrent callers don't race on docker network create.
	local lockfile=/tmp/pv_appengine.network0.lock
	NET0_FD=
	# a failed exec leaves NET0_FD empty; check it explicitly or flock/close below run on '' and wreck fd 1
	if ! exec {NET0_FD}>"$lockfile"; then
		pvtest_log ERROR "cannot open lock file '$lockfile' (owned by another user under /tmp with fs.protected_regular=1, or /tmp not writable)"
		return 1
	fi
	flock "$NET0_FD"

	if ! docker network inspect test-appengine-net >/dev/null 2>&1; then
		docker network create --driver=bridge --opt com.docker.network.container_iface_prefix=lxcbrdock test-appengine-net >/dev/null 2>&1 || :
	fi

	eval "exec ${NET0_FD}>&-"
}


# INT/TERM handler for run_test once the slot is allocated
_abort_run() {
	trap - INT TERM
	pvtest_log WARN "interrupted — tearing down slot ${slot}"

	local p
	for p in $(jobs -p); do kill -TERM "$p" > /dev/null 2>&1 || true; done

	# anchored so slot 1 never reaps slot 10's containers ("-p" runs share a host)
	docker ps -aq \
		--filter "name=pantavisor-tester-${USER}-${slot}$" \
		--filter "name=pantavisor-tester-${USER}-${slot}-" \
		--filter "name=pantavisor-appengine-${USER}-${slot}-" \
		| xargs -r docker rm -f > /dev/null 2>&1 || true
	docker rm -f "pantavisor-netsim-${USER}-${slot}" > /dev/null 2>&1 || true

	exit 130
}

setup_network() {
	local tester_name="${1:-pantavisor-tester}"
	local netsim_name="${2:-pantavisor-netsim}"
	sleep 1
	sudo -n modprobe -r mac80211_hwsim

	local before_phy=$(iw dev | grep -oP '(?<=phy#)\d+')
	sudo -n modprobe mac80211_hwsim radios=3
	local after_phy=$(iw dev | grep -oP '(?<=phy#)\d+')
	local new_phys=$(comm -13 <(echo "$before_phy" | sort) <(echo "$after_phy" | sort))

	wait_for_status "docker inspect -f '{{.State.Pid}}' $netsim_name" 0 5 > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		pvtest_log ERROR "$netsim_name not responding"
		exit 1
	fi
	local pid=$(docker inspect -f '{{.State.Pid}}' "$netsim_name")

	local ap_phy=$(echo "$new_phys" | sed -n '1p')
	sudo -n iw phy "phy$ap_phy" set netns "$pid"

	wait_for_status "docker inspect -f '{{.State.Pid}}' $tester_name" 0 5 > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		pvtest_log ERROR "$tester_name not responding"
		exit 1
	fi
	local pid=$(docker inspect -f '{{.State.Pid}}' "$tester_name")

	local cl_phy=$(echo "$new_phys" | sed -n '2p')
	sudo -n iw phy "phy$cl_phy" set netns "$pid"
}

teardown_network() {
	sudo -n modprobe -r mac80211_hwsim
}

_AE_DOCKER_ARGS=(
	--net=test-appengine-net
	--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add MKNOD
	--device /dev/kmsg --device /dev/hwrng --device /dev/loop-control
	--device-cgroup-rule 'b 7:* rmw'
	--security-opt apparmor=unconfined --security-opt seccomp=unconfined
	--mount type=tmpfs,target=/usr/lib/lxc/rootfs
	--mount type=tmpfs,target=/volumes
	--mount type=tmpfs,target=/configs
)

_boot_appengine() {
	local ae="$1" cfg="$2" storage_key="$3" initial_rev="$4" pvtx_extra_dir="$5"
	local PVTEST_LOG_TAG="$ae"

	local _cfg_env=() _kv
	for _kv in $cfg; do _cfg_env+=(-e "$_kv"); done

	local storage_dir="$work_path/storage/${storage_key:-$ae}"
	mkdir -p "$storage_dir"

	local ae_valgrind_args=()
	if [ "$valgrind" = "true" ]; then
		mkdir -p "$work_path/valgrind/$ae"
		ae_valgrind_args=(-v "$work_path/valgrind/$ae":/tmp/valgrind)
	fi

	local ae_seed_args=()
	if [ -n "$initial_rev" ]; then
		ae_seed_args=(-e PV_APPENGINE_INITIAL_REV="$initial_rev")
		[ -n "$pvtx_extra_dir" ] && ae_seed_args+=(
			-v "$pvtx_extra_dir":/usr/lib/pantavisor/pvtx.extra.d:ro
		)
	fi

	if ! docker run \
		--name "$ae" \
		-d \
		--rm \
		"${_AE_DOCKER_ARGS[@]}" \
		-v "$storage_dir":/var/pantavisor/storage \
		"${ae_valgrind_args[@]}" \
		"${ae_seed_args[@]}" \
		-e VALGRIND="$valgrind" \
		-e PV_DEBUG_SSH=1 \
		-e PV_DEBUG_SSH_AUTHORIZED_KEYS="pvtest-authorized_keys" \
		-e PV_DEBUG_SSH_PUBKEY="$pvtest_pubkey" \
		-e PV_LOG_SERVER_OUTPUTS="filetree,stdout_direct" \
		-e PV_LOG_TIMESTAMP="absolute" \
		"${_cfg_env[@]}" \
		"pantavisor-appengine:$PVTEST_IMAGE_TAG" \
			/usr/bin/pv-appengine -c "ph_metadata.devmeta.interval=15" > /dev/null; then
		return 1
	fi
	pvtest_log DEBUG "started appengine (cfg=[${cfg:-<none>}])"

	# Dump docker logs into appengine worker log
	touch "$work_path/${ae}.log"
	docker logs -f "$ae" 2>/dev/null \
		| while IFS= read -r _pv_line; do printf '[%s] %s\n' "$ae" "${_pv_line#"[pantavisor] "}"; done \
		>> "$work_path/${ae}.log" &
	echo $! > "$work_path/.logpid.$ae"
	return 0
}

_stop_appengine() {
	local ae="$1"
	local _grace=30 _elapsed=0 _status=

	# Wait for graceful exit (tester has already issued pvcontrol cmd poweroff)
	while _status=$(docker inspect -f '{{.State.Status}}' "$ae" 2>/dev/null) \
	      && [ "$_status" = "running" ] && [ "$_elapsed" -lt "$_grace" ]; do
		sleep 1
		_elapsed=$((_elapsed + 1))
	done

	# Force stop
	if [ "${_status:-}" = "running" ]; then
		docker stop --time 5 "$ae" > /dev/null 2>&1 || true
	fi

	# Kill log tail
	if [ -f "$work_path/.logpid.$ae" ]; then
		kill "$(cat "$work_path/.logpid.$ae")" 2>/dev/null || true
		rm -f "$work_path/.logpid.$ae"
	fi
}


# Reboot appengine and boot again with settings from ctrl
_retype_handle_appengine() {
	local ctrl="$1" id="$2" S="$3" cfg="$4" stor="$5" rev="$6" seed="$7"
	local stf="$ctrl/state/slot${S}.ae" old ae gen

	# Stop appengine and report status down
	old=$(cat "$stf" 2>/dev/null)
	[ -n "$old" ] && _stop_appengine "$old"
	: > "$stf"
	if [ -z "$cfg" ]; then
		_retype_reply "$ctrl" "$id" "status=down"
		return 0
	fi

	# Unique generation per boot, shared by every slot
	gen=$( ( flock -x 8
		local g; g=$(( $(cat "$ctrl/state/gen" 2>/dev/null || echo 0) + 1 ))
		printf '%s' "$g" > "$ctrl/state/gen"; printf '%s' "$g"
	) 8>"$ctrl/state/gen.lock" )

	# Start appengine with settings from ctrl, then report status ready/failed
	ae="pantavisor-appengine-${USER}-${slot}-w${S}-g${gen}"
	cfg="$cfg PV_LOOP_INDEX_BASE=$(( (slot * 64 + S) * 64 ))"
	if _boot_appengine "$ae" "$cfg" "$stor" "$rev" "${seed:+$ctrl/seed/$seed}"; then
		printf '%s' "$ae" > "$stf"
		# Reachable by the run key mounted in the tester, at the name just booted
		_retype_reply "$ctrl" "$id" "ae=$ae" "exec=$(pvtest_ssh_cmd "$ae")" "host=$ae" \
			"status=ready"
	else
		_retype_reply "$ctrl" "$id" "status=failed"
	fi
}


_tester_common_args() {
	_TESTER_ARGS=(
		--rm
		--net=test-appengine-net
		-e OVERWRITE="$overwrite"
		-e VERBOSE="$verbose"
		-e PH_USER="$PH_USER"
		-e PH_PASS="$PH_PASS"
		-e PVTEST_HUB_URL="$PVTEST_HUB_URL"
		-e PVR_DISABLE_SELF_UPGRADE=true
		-e PVTEST_DEVICE_TYPE="${PVTEST_DEVICE_TYPE:-appengine}"
		-e PV_LOG_SERVER_OUTPUTS="filetree,stdout_direct"
		-e PV_LOG_TIMESTAMP="absolute"
		-e RUN_DIR=/work/results
		"${tester_scope_args[@]}"
		-v "$work_path/results":/work/results
	)
}

# Run the tester over the queue
_run_pass() {
	local pass_model="$1"
	local res=0

	local ctrl_dir="$work_path/ctrl"
	mkdir -p "$ctrl_dir/req" "$ctrl_dir/resp" "$ctrl_dir/state"

	local _nq
	_nq=$(printf '%s\n' $pvtest_queue | grep -c .)
	pvtest_log INFO "=== ${pass_model} pool: ${_nq} test(s) across up to ${parallel} slot(s) ==="
	pvtest_log INFO "Hub: $PVTEST_HUB_URL"

	# Storage lineage is persistent within a run but always fresh at its start
	[ "$retype_mech" = "container" ] && rm -rf "$work_path/storage"

	# Reboot container/device with test settings requested by tester
	_retype_service "$ctrl_dir" "$retype_mech" &
	local svc_pid=$!

	mkdir -p "$work_path/results"

	_tester_common_args
	local -a tester_run_args=(
		"${_TESTER_ARGS[@]}"
		--name "${tester_name}"
		-e TEST_PATH="/work/$target_path"
		-e PVTEST_QUEUE="$pvtest_queue"
		-e PVTEST_MODEL="$pass_model"
		-e PVTEST_RETYPE="$retype_mech"
		-e PVTEST_SLOTS="$parallel"
		-e PVTEST_CTRL="/work/ctrl"
		-e PVTEST_TESTER_NAME="${tester_name}"
		-e INTERACTIVE="$interactive"
		-e NETSIM="$netsim"
		-e APPENGINE_LOGS=/work/hostlogs
		-v "$work_path":/work/hostlogs:ro
		-v "$ctrl_dir":/work/ctrl
	)

	if [ -n "$device_file" ]; then
		# Testing on real device extra args
		tester_run_args+=(
			-e PVTEST_EXEC="$_dev_exec"
			-e PVTEST_HOST="$_dev_ip"
			-e PVTEST_DEVICE_TYPE="${PVTEST_DEVICE_TYPE:-$_dev_type}"
			-e PVTEST_DEVICE_NAME="$_dev_name"
			-e PVTEST_TEST_TIMEOUT="${PVTEST_TEST_TIMEOUT:-1800}"
			"${tester_device_args[@]}"
		)
	else
		# Testing on appengine container extra args
		tester_run_args+=(
			-e PVTEST_EXEC="${PVTEST_EXEC:-}"
			-e PVTEST_HOST="${PVTEST_HOST:-}"
			"${tester_shared_args[@]}"
		)
	fi

	docker run "${tester_run_args[@]}" "$tester_image"
	res=$?

	# Stop the lifecycle service and tear down any remaining slot containers
	touch "$ctrl_dir/stop"
	wait "$svc_pid" 2>/dev/null || true
	if [ "$retype_mech" = "container" ]; then
		docker ps -aq --filter "name=pantavisor-appengine-${USER}-${slot}-" | xargs -r docker rm -f 2>/dev/null || true
	fi

	return $res
}


# Run all the tests specified by the user
run_test() {
	local target_path=
	local overwrite="false"
	local interactive="false"
	local manual="false"
	local parallel=0
	local work_path=
	local netsim="false"
	local valgrind="false"
	local fail_on_skip="false"
	local device_file=
	local model="persistent" model_explicit="false"
	local hub_url=

	if [ -n "$1" ] && [ "$(printf '%s' "$1" | cut -c1)" != "-" ]; then
		target_path="$1"
		shift
	fi

	# all is the same as empty target
	[ "$target_path" = "all" ] && target_path=

	while [ $# -gt 0 ]; do
		case "$1" in
			-o|--overwrite)
				overwrite="true"
				shift
				;;
			-i|--interactive)
				interactive="true"
				shift
				;;
			-m|--manual)
				interactive="true"
				manual="true"
				shift
				;;
			-w|--work)
				work_path="$2"
				shift 2
				;;
			-n|--netsim)
				netsim="true"
				shift
				;;
			-V|--valgrind)
				valgrind="true"
				shift
				;;
			-p|--parallel)
				parallel="$2"
				shift 2
				;;
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
				model="$2"
				model_explicit="true"
				shift 2
				;;
			--fail-on-skip)
				fail_on_skip="true"
				shift
				;;
			*)
				pvtest_log ERROR "Unknown argument: $1"
				usage
				exit 1
				;;
		esac
	done

	_resolve_hub_url "$hub_url" || exit 1

	[ -n "$work_path" ] || work_path=$(mktemp -d -t pv_appengine.XXXXXX)

	if [ -n "$device_file" ] && ! _resolve_device_file; then
		exit 1
	fi

	case "$parallel" in
		""|*[!0-9]*)
			pvtest_log ERROR "-p needs a positive integer"
			usage
			exit 1
			;;
	esac
	if [ "$parallel" -le 0 ]; then
		parallel=1
	fi

	if [ "$parallel" -gt 1 ] && { [ "$interactive" = "true" ] || [ "$manual" = "true" ]; }; then
		pvtest_log ERROR "-p is incompatible with -i and -m"
		usage
		exit 1
	fi

	if [ "$parallel" -gt 1 ] && [ "$overwrite" = "true" ]; then
		pvtest_log ERROR "-p is incompatible with -o"
		usage
		exit 1
	fi

	if [ "$netsim" = "true" ] && [ "$parallel" -gt 1 ]; then
		pvtest_log ERROR "-n netsim is incompatible with -p > 1"
		usage
		exit 1
	fi

	if [ -n "$device_file" ] && { [ "$parallel" -gt 1 ] || [ "$netsim" = "true" ] || [ "$valgrind" = "true" ]; }; then
		pvtest_log ERROR "--device is incompatible with -p>1, -n, -V"
		usage
		exit 1
	fi

	if [ -n "$device_file" ] && { [ -n "$PVTEST_EXEC" ] || [ -n "$PVTEST_HOST" ]; }; then
		pvtest_log ERROR "--device is incompatible with pre-set PVTEST_EXEC/PVTEST_HOST"
		exit 1
	fi

	case "$model" in
		persistent|volatile) ;;
		*)
			pvtest_log ERROR "invalid --model '$model' (expected persistent or volatile)"
			usage
			exit 1
			;;
	esac

	if [ -n "$device_file" ] && [ "$model" != "persistent" ]; then
		if [ "$model_explicit" = "true" ]; then
			pvtest_log ERROR "--model $model is not supported with --device; use --model persistent"
			exit 1
		fi
		pvtest_log INFO "--device: selecting --model persistent"
		model="persistent"
	fi

	if [ "$model_explicit" = "true" ] && { [ "$interactive" = "true" ] || [ "$manual" = "true" ]; }; then
		pvtest_log ERROR "--model does not apply to -i/-m"
		usage
		exit 1
	fi

	if [ "$interactive" = true ] && [ -z "$target_path" ]; then
		pvtest_log ERROR "Interactive mode requires a specific test path"
		usage
		exit 1
	fi

	if [ "$interactive" = true ] && [ ! -f "$test_dir/$target_path/test.json" ]; then
		pvtest_log ERROR "'$target_path' is not a leaf test (no test.json found)"
		usage
		exit 1
	fi

	if [ "$overwrite" = "true" ] && [ "$interactive" = "true" ]; then
		pvtest_log ERROR "Cannot use overwrite and interactive at the same time"
		usage
		exit 1
	fi

	local pool_mode=false
	[ -z "$PVTEST_EXEC" ] && [ -z "$device_file" ] && pool_mode=true

	mkdir -p "$work_path"
	{
	pvtest_log DEBUG "workspace=$work_path"
	pvtest_log DEBUG "readme=$work_path/README.md"
	pvtest_log DEBUG "run log=$work_path/run.log"
	pvtest_log DEBUG "test log=$work_path/results/<scope>/<category>/<name>/test.log"
	if [ "$valgrind" = "true" ]; then
		pvtest_log DEBUG "valgrind log=$work_path/storage/<scope>/<category>/<name>/valgrind/valgrind.log.<pid>"
	fi
	pvtest_log DEBUG "diff=$work_path/results/<scope>/<category>/<name>/diff"
	} | tee -a "$work_path/run.log"

	allocate_slot || return 1
	local tester_name="pantavisor-tester-${USER}-${slot}"
	local netsim_name="pantavisor-netsim-${USER}-${slot}"

	docker ps -aq --filter "name=pantavisor-appengine-${USER}-${slot}-" | xargs -r docker rm -f 2>/dev/null || true
	docker ps -aq \
		--filter "name=pantavisor-tester-${USER}-${slot}$" \
		--filter "name=pantavisor-tester-${USER}-${slot}-" \
		| xargs -r docker rm -f 2>/dev/null || true
	docker rm -f "$netsim_name" 2>/dev/null || true

	trap '_abort_run' INT TERM

	local abs_local_path= abs_remote_path=
	if [ -d "$test_dir/local" ]; then
		cd "$test_dir/local"; abs_local_path=$(pwd); cd - > /dev/null
	fi
	if [ -d "$test_dir/remote" ]; then
		cd "$test_dir/remote"; abs_remote_path=$(pwd); cd - > /dev/null
	fi

	local _script_dir
	_script_dir="$(cd "$(dirname "$0")" && pwd)"
	local tester_image="pantavisor-appengine-tester:$PVTEST_IMAGE_TAG"
	local netsim_image="pantavisor-appengine-netsim:$PVTEST_IMAGE_TAG"

	if [ "$interactive" = "false" ] && [ "$manual" = "false" ]; then
		exec > >(tee -a "$work_path/run.log") 2>&1
	fi

	if ! setup_network0; then
		release_slot
		return 1
	fi

	if [ "$netsim" = "true" ]; then
		docker run \
			--name "$netsim_name" \
			--net=test-appengine-net \
			-d \
			-e VERBOSE="$verbose" \
			--rm \
			--cap-add NET_ADMIN \
			"$netsim_image" > /dev/null

		setup_network "$tester_name" "$netsim_name" &
	fi

	# Generate SSH keypair once, shared by all appengine containers for this run
	# real devices are reached via each manifest entry's own exec=
	local shared_ssh_dir= pvtest_pubkey=
	if [ "$pool_mode" = true ] && [ "$manual" = "false" ]; then
		shared_ssh_dir=$(mktemp -d)
		ssh-keygen -t ed25519 -f "$shared_ssh_dir/id_ed25519" -N "" -q
		chmod 600 "$shared_ssh_dir/id_ed25519"
		# Public key is passed as PV_DEBUG_SSH_PUBKEY env var; pv-appengine writes
		# it to /etc/pantavisor/ssh/ as root, avoiding the need for host sudo.
		pvtest_pubkey=$(cat "$shared_ssh_dir/id_ed25519.pub")
	fi

	# Tester-shared mounts (SSH key) and scope mounts (local/remote test trees)
	local tester_shared_args=()
	if [ "$pool_mode" = true ]; then
		tester_shared_args=(-v "$shared_ssh_dir/id_ed25519":/tmp/pvtest_id:ro)
	fi
	local tester_scope_args=()
	[ -n "$abs_local_path" ] && tester_scope_args+=(-v "$abs_local_path":/work/local)
	[ -n "$abs_remote_path" ] && tester_scope_args+=(-v "$abs_remote_path":/work/remote)

	local tester_device_args=()
	if [ -n "$device_file" ]; then
		if ! _parse_device_manifest "$device_file"; then
			release_slot
			return 1
		fi
		local PVTEST_LOG_TAG="$_dev_name"

		if ! _lock_device "$_dev_name"; then
			release_slot
			return 1
		fi

		_start_device_capture "$_dev_name" "$_dev_tty" "$_dev_baud" \
			|| pvtest_log ERROR "failed to start tty capture for device '$_dev_name'"

		local _devfile_abs_dir
		_devfile_abs_dir="$(cd "$(dirname "$device_file")" && pwd)"
		tester_device_args=(-v "$_devfile_abs_dir":"$_devfile_abs_dir":ro)
	fi

	if [ "$manual" = "true" ]; then
		if [ -n "$device_file" ]; then
			pvtest_log INFO "manual: entering device '$_dev_name' as it is (test config.env not applied)"
			$_dev_exec
			_release_device
		else
			local manual_cfg_args=() _mkv
			for _mkv in $(_test_cfg "$test_dir/$target_path"); do
				manual_cfg_args+=(-e "$_mkv")
			done
			docker run -it --rm \
				--name "pantavisor-appengine-${USER}-${slot}-0" \
				"${_AE_DOCKER_ARGS[@]}" \
				-v "$work_path/storage/0":/var/pantavisor/storage \
				"${manual_cfg_args[@]}" \
				"pantavisor-appengine:$PVTEST_IMAGE_TAG" \
				/usr/bin/pv-appengine -m
		fi
		release_slot
		return
	fi

	# How this run's target changes config
	local retype_mech=none
	if [ "$pool_mode" = true ]; then
		retype_mech=container
	elif [ -n "$_dev_setbootconfig" ]; then
		retype_mech=setbootconfig
	fi

	local target_type abs_targets_path=
	target_type="${PVTEST_DEVICE_TYPE:-${_dev_type:-appengine}}"
	if [ ! -d "$test_dir/targets/$target_type" ]; then
		pvtest_log ERROR "no container tarballs for target type '$target_type'"
		pvtest_log ERROR "  expected: $test_dir/targets/$target_type/{local,remote}"
		pvtest_log ERROR "  available: $(ls "$test_dir/targets" 2>/dev/null | tr '\n' ' ')"
		pvtest_log ERROR "  add one with: ./test.docker.sh install-tarballs $target_type <exports>"
		[ -n "$device_file" ] && _release_device
		release_slot
		return 1
	fi
	abs_targets_path=$(cd "$test_dir/targets/$target_type" && pwd)
	[ -n "$abs_local_path" ] \
		&& tester_scope_args+=(-v "$abs_targets_path/local":/work/local/common/tarballs)
	[ -n "$abs_remote_path" ] \
		&& tester_scope_args+=(-v "$abs_targets_path/remote":/work/remote/common/tarballs)
	pvtest_log INFO "target type: $target_type (tarballs from targets/$target_type)" \
		| tee -a "$work_path/run.log"

	if [ "$interactive" = "true" ]; then
		local _iae= iface_args=()
		if [ -n "$device_file" ]; then
			iface_args=(
				-e PVTEST_EXEC="$_dev_exec"
				-e PVTEST_HOST="$_dev_ip"
				-e PVTEST_DEVICE_TYPE="${PVTEST_DEVICE_TYPE:-$_dev_type}"
				-e PVTEST_DEVICE_NAME="$_dev_name"
				"${tester_device_args[@]}"
			)
		else
			local _icfg
			_icfg=$(pvtest_cfg_with_hub "$(_test_cfg "$test_dir/$target_path")" "$PVTEST_HUB_URL")
			_iae="pantavisor-appengine-${USER}-${slot}-w0-g1"
			_boot_appengine "$_iae" "$_icfg"
			iface_args=(
				-e PVTEST_EXEC="$(pvtest_ssh_cmd "$_iae")"
				-e PVTEST_HOST="$_iae"
				-e PVTEST_DEVICE_TYPE="${PVTEST_DEVICE_TYPE:-appengine}"
				"${tester_shared_args[@]}"
			)
		fi
		docker run -it --rm \
			--net=test-appengine-net \
			--name "$tester_name" \
			-e TEST_PATH="/work/$target_path" \
			-e INTERACTIVE=true \
			-e PVTEST_RETYPE="$retype_mech" \
			-e VERBOSE="$verbose" \
			-e PH_USER="$PH_USER" \
			-e PH_PASS="$PH_PASS" \
			-e PVTEST_HUB_URL="$PVTEST_HUB_URL" \
			-e PVR_DISABLE_SELF_UPGRADE=true \
			"${iface_args[@]}" \
			"${tester_scope_args[@]}" \
			"$tester_image"
		if [ -n "$device_file" ]; then
			_release_device
		else
			_stop_appengine "$_iae"
			[ -z "$PVTEST_EXEC" ] && rm -rf "$shared_ssh_dir"
		fi
		release_slot
		return
	fi

	local pvtest_queue="" _json _rel
	while IFS= read -r _json; do
		[ -n "$_json" ] || continue
		_rel=${_json#"$test_dir"/}; _rel=${_rel#./}
		pvtest_queue="${pvtest_queue:+$pvtest_queue }/work/$_rel"
	done < <(find "$test_dir/${target_path:-.}" -name test.json 2>/dev/null | sort)

	if [ -z "$pvtest_queue" ]; then
		pvtest_log WARN "no tests found under '${target_path:-<all>}'"
		[ -n "$device_file" ] && _release_device
		release_slot
		[ "$pool_mode" = true ] && rm -rf "$shared_ssh_dir"
		return 0
	fi

	local res=0
	_run_pass "$model" || res=1

	[ "$pool_mode" = true ] && rm -rf "$shared_ssh_dir"

	if [ "$pool_mode" = true ] && [ -d "$work_path/storage" ]; then
		docker run --rm -v "$work_path/storage":/storage "pantavisor-appengine:$PVTEST_IMAGE_TAG" \
			-c "chown -R $(id -u):$(id -g) /storage" > /dev/null 2>&1 || true
	fi

	[ -n "$device_file" ] && _release_device

	if [ "$netsim" = "true" ]; then
		docker stop "$netsim_name" > /dev/null 2>&1
		docker wait "$netsim_name" > /dev/null 2>&1
		teardown_network
	fi

	release_slot

	local skip_fail=0
	_print_summary "$work_path/run.log" || skip_fail=1

	[ "${CI:-false}" = "true" ] && cp "$work_path/run.log" ./run.log

	cp "$_script_dir/workspace-README.md" "$work_path/README.md" 2>/dev/null \
		|| pvtest_log WARN "workspace-README.md not found beside $0"

	if [ $res -ne 0 ] || [ "${skip_fail:-0}" -ne 0 ]; then
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
	install-deps)
		install_deps
		;;
	install-docker)
		install_docker
		;;
	clean-docker)
		clean_docker
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
