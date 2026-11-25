#!/bin/bash

PVTEST_LOG_SOURCE=run.docker.sh
PVTEST_LOG_HOST="$(hostname 2>/dev/null || echo host)"

_pvtest_root="$(dirname "$0")"
[ -r "$_pvtest_root/pvtest/common" ] || _pvtest_root="$_pvtest_root/.."
. "$_pvtest_root/pvtest/common" || exit 1
. "$_pvtest_root/pvtest/host-common" || exit 1
. "$_pvtest_root/pvtest/host-docker" || exit 1

PVTEST_IMAGE_TAG="${PVTEST_IMAGE_TAG:-latest}"
PVTEST_INSTANCES_DIR="${PVTEST_INSTANCES_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/pvtest/instances}"

# far above the pvtest slot range ((slot * 64 + S) * 64) so instances and test runs share a host
_LOOP_BASE0=524288

usage() {
	echo ""
	echo "Usage: $0 [options] <command> [arguments]"
	echo "Run Pantavisor appengine instances"
	echo ""
	echo "Options:"
	echo "  -h, --help    Display this help message"
	echo "  -v, --verbose Print debug logs"
	echo ""
	echo "Commands:"
	echo "  install-deps          Install dependencies (and docker)"
	echo "  install-docker        Load the appengine docker image"
	echo "  up <json>             Boot a new instance with the setup in <json>"
	echo "  ls                    List instances"
	echo "  attach <name>         Follow the console of a running instance"
	echo "  exec <name> [cmd...]  Run cmd in an instance (default: bash)"
	echo "  logs <name>           Print the instance console log"
	echo "  stop <name>           Power off the instance, keep its storage"
	echo "  start <name> [-d]     Boot a stopped instance again"
	echo "  down <name>           Remove the instance and its storage"
	echo ""
	echo "Arguments for 'up' command:"
	echo "  -d, --detach          Run in background, return once ready"
	echo "  -N, --name NAME       Instance name (default: json basename)"
	echo "  -w, --work PATH       Instance workdir (default:"
	echo "                        $PVTEST_INSTANCES_DIR/NAME)"
	echo "  -e KEY=VALUE          Config on top of setup.config.env (repeatable)"
	echo "  -P, --publish PORT    Publish the pvr endpoint (12368) on host PORT"
	echo "  -t, --timeout SECS    Ready wait (default: 300)"
	echo "  -V, --valgrind        Run Pantavisor with valgrind"
	echo "  --hub URL             Hub the instance targets (default:"
	echo "                        https://api.pantahub.com)"
	echo ""
	echo "<json> is a templates/run.docker.json (\"#spec\": \"pv-appengine@1\") or a test.json; see"
	echo "README.md."
	echo ""
}

_ctr() { printf 'pantavisor-appengine-%s-i-%s' "$USER" "$1"; }

_label() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$(_ctr "$1")" 2>/dev/null; }

_status() { docker inspect -f '{{.State.Status}}' "$(_ctr "$1")" 2>/dev/null; }

_ip() {
	docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(_ctr "$1")" 2>/dev/null
}

# Die unless instance $1 exists; sets $work
_need_instance() {
	if [ -z "$1" ]; then
		pvtest_log ERROR "missing instance name"
		usage
		exit 1
	fi
	if [ -z "$(_status "$1")" ]; then
		pvtest_log ERROR "no instance '$1' (see: $0 ls)"
		exit 1
	fi
	work=$(_label "$1" pvtest.work)
}

# Lowest loop slot index not used by any instance on this host, any user
_loop_index() {
	local used i=0
	used=$(docker ps -aq --filter label=pvtest.loopidx \
		| xargs -r docker inspect -f '{{index .Config.Labels "pvtest.loopidx"}}' 2>/dev/null)
	while printf '%s\n' $used | grep -qx "$i"; do i=$((i + 1)); done
	printf '%s' "$i"
}

# Resolve test.json/run.docker.json tarball $1 against json dir $2
_resolve_tarball() {
	local t="$1" jdir="$2" s
	case "$t" in
		/*) [ -f "$t" ] && { printf '%s' "$t"; return 0; } ;;
		*)
			[ -f "$jdir/$t" ] && { printf '%s' "$jdir/$t"; return 0; }
			# test.json paths point at the suite common/tarballs, installed under targets/
			case "$t" in
				*common/tarballs/*)
					for s in local remote; do
						local f="$_pvtest_root/targets/${PVTEST_DEVICE_TYPE:-appengine}/$s/${t##*/}"
						[ -f "$f" ] && { printf '%s' "$f"; return 0; }
					done
					;;
			esac
			;;
	esac
	return 1
}

# Start the detached console follower of instance $1, appending to its console.log
_follow() {
	local name="$1" since
	_unfollow "$name"
	since=$(docker inspect -f '{{.State.StartedAt}}' "$(_ctr "$name")")
	setsid -f sh -c 'echo $$ > "$1/.console.pid"; exec docker logs -f --since "$2" "$3" >> "$1/console.log" 2>&1' \
		_ "$work" "$since" "$(_ctr "$name")" < /dev/null > /dev/null 2>&1
	local i=0
	while [ ! -s "$work/.console.pid" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
}

_unfollow() {
	[ -f "$work/.console.pid" ] || return 0
	kill "$(cat "$work/.console.pid")" 2>/dev/null || true
	rm -f "$work/.console.pid"
}

# Follow console.log of instance $1 until its container stops (or Ctrl-C)
_tail() {
	local pid
	pid=$(cat "$work/.console.pid" 2>/dev/null)
	tail -n +1 -f ${pid:+--pid="$pid"} "$work/console.log"
}

# Wait up to $3 secs for instance $1 to run revision $2 (any if empty) in DONE
_wait_ready() {
	local name="$1" want="$2" timeout="$3" ctr rev st t=0
	ctr=$(_ctr "$name")
	while [ "$t" -lt "$timeout" ]; do
		if [ "$(_status "$name")" != running ]; then
			pvtest_log ERROR "$name stopped while booting (see $work/console.log)"
			return 1
		fi
		rev=$(docker exec "$ctr" pvcontrol devmeta ls 2>/dev/null \
			| jq -r '.["pantavisor.revision"] // empty' 2>/dev/null | tr -d '\r')
		if [ -n "$rev" ] && { [ -z "$want" ] || [ "$rev" = "$want" ]; }; then
			st=$(docker exec "$ctr" pvcontrol steps show-progress "$rev" 2>/dev/null \
				| jq -r '.status // empty' 2>/dev/null)
			# the seeded revision is DONE from boot, so also wait for its containers
			if [ "$st" = DONE ] && docker exec "$ctr" pvcontrol ls 2>/dev/null \
				| jq -e 'length > 0 and all(.[]; .status == .status_goal)' > /dev/null 2>&1; then
				READY_REV="$rev"
				return 0
			fi
		fi
		sleep 2
		t=$((t + 2))
	done
	pvtest_log ERROR "$name not ready after ${timeout}s (revision='${rev:-<none>}' status='${st:-<none>}')"
	return 1
}

_ready_msg() {
	local name="$1" ip
	ip=$(_ip "$name")
	pvtest_log INFO "$name: ready, revision $READY_REV DONE (ip ${ip:-<none>})"
	pvtest_log INFO "  shell:   $0 exec $name"
	pvtest_log INFO "  console: $0 attach $name"
	pvtest_log INFO "  pvr:     http://${ip:-<ip>}:12368/cgi-bin/pvr"
}

_poweroff() {
	local name="$1" t=0
	[ "$(_status "$name")" = running ] || return 0
	docker exec "$(_ctr "$name")" pvcontrol cmd poweroff "run.docker.sh: stop" > /dev/null 2>&1 || true
	while [ "$(_status "$name")" = running ] && [ "$t" -lt 30 ]; do sleep 1; t=$((t + 1)); done
	[ "$(_status "$name")" = running ] && docker stop --time 5 "$(_ctr "$name")" > /dev/null 2>&1
	return 0
}

# Attached mode: show the console until the instance stops; Ctrl-C powers it off
_attached() {
	local name="$1" want="$2" timeout="$3" usrmeta="$4" tail_pid
	trap 'trap - INT TERM; pvtest_log INFO "stopping $name ..."; _poweroff "$name"; _unfollow "$name"; kill $tail_pid 2>/dev/null; exit 130' INT TERM
	_tail &
	tail_pid=$!
	if _wait_ready "$name" "$want" "$timeout"; then
		_apply_usrmeta "$name" "$usrmeta"
		_ready_msg "$name"
	fi
	wait "$tail_pid"
	trap - INT TERM
	_unfollow "$name"
}

_apply_usrmeta() {
	local name="$1" kv
	for kv in $2; do
		pvtest_log INFO "$name: usrmeta save ${kv%%=*}=${kv#*=}"
		docker exec "$(_ctr "$name")" pvcontrol usrmeta save "${kv%%=*}" "${kv#*=}" > /dev/null \
			|| pvtest_log ERROR "$name: usrmeta save ${kv%%=*} failed"
	done
}

cmd_up() {
	local json= name= detach=false publish= timeout=300 valgrind=false hub_url= hub_explicit=false
	local cli_env=""

	if [ -n "$1" ] && [ "${1#-}" = "$1" ]; then
		json="$1"
		shift
	fi
	while [ $# -gt 0 ]; do
		case "$1" in
			-d|--detach) detach=true; shift ;;
			-N|--name) name="$2"; shift 2 ;;
			-w|--work) work="$2"; shift 2 ;;
			-e) cli_env="$cli_env $2"; shift 2 ;;
			-P|--publish) publish="$2"; shift 2 ;;
			-t|--timeout) timeout="$2"; shift 2 ;;
			-V|--valgrind) valgrind=true; shift ;;
			--hub) hub_url="$2"; hub_explicit=true; shift 2 ;;
			*)
				pvtest_log ERROR "Unknown argument: $1"
				usage
				exit 1
				;;
		esac
	done

	if [ -z "$json" ] || [ ! -f "$json" ]; then
		pvtest_log ERROR "up needs an existing setup json (got '${json:-<none>}')"
		usage
		exit 1
	fi
	local spec
	spec=$(jq -r '."#spec" // empty' "$json" 2>/dev/null) || {
		pvtest_log ERROR "'$json' is not valid JSON"
		exit 1
	}
	case "$spec" in
		pv-appengine@1|pv-test@1) ;;
		*)
			pvtest_log ERROR "'$json': unsupported #spec '${spec:-<none>}' (expected pv-appengine@1 or pv-test@1)"
			exit 1
			;;
	esac
	if [ "$(jq -r '.setup."self-claim" // "false"' "$json")" = "true" ]; then
		pvtest_log ERROR "'$json': self-claim=true is not supported by run.docker.sh"
		exit 1
	fi
	case "$timeout" in ""|*[!0-9]*) pvtest_log ERROR "-t needs seconds"; exit 1 ;; esac

	local jdir
	jdir=$(cd "$(dirname "$json")" && pwd)
	if [ -z "$name" ]; then
		name=$(basename "$json" .json)
		# a test.json is named after its test
		[ "$name" = test ] && name=$(basename "$jdir")
	fi
	case "$name" in
		""|*[!A-Za-z0-9_.-]*)
			pvtest_log ERROR "invalid instance name '$name' (letters, digits, '_', '.', '-')"
			exit 1
			;;
	esac
	local PVTEST_LOG_TAG="$name"
	if [ -n "$(_status "$name")" ]; then
		pvtest_log ERROR "instance '$name' exists; use 'start $name' or 'down $name'"
		exit 1
	fi
	[ -n "$work" ] || work="$PVTEST_INSTANCES_DIR/$name"
	if [ -e "$work" ] && [ -n "$(ls -A "$work" 2>/dev/null)" ]; then
		pvtest_log ERROR "workdir '$work' is not empty; remove it or pass another -w"
		exit 1
	fi
	mkdir -p "$work/storage" "$work/seed" || exit 1
	work=$(cd "$work" && pwd)
	cp "$json" "$work/setup.json"

	local t src n=0
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		if ! src=$(_resolve_tarball "$t" "$jdir"); then
			pvtest_log ERROR "tarball '$t' not found (relative to $jdir)"
			rm -rf "$work"
			exit 1
		fi
		cp "$src" "$(printf '%s/%02d-%s' "$work/seed" "$n" "${src##*/}")" || exit 1
		n=$((n + 1))
	done < <(jq -r '.setup.containers.tarballs[]? // empty' "$json")

	_resolve_hub_url "$hub_url" || exit 1
	local cfg usrmeta
	cfg=$(pvtest_cfg_with_hub "$(jq -r '.setup.config.env // ""' "$json") $cli_env" "$PVTEST_HUB_URL")
	if [ "$hub_explicit" = true ] && [ "${cfg#*PH_CREDS_HOST=}" = "$cfg" ]; then
		cfg="$cfg $(pvtest_hub_cfg "$PVTEST_HUB_URL")"
	fi
	usrmeta=$(jq -r '.setup.config.usrmeta // ""' "$json")

	local rev="locals/$(printf '%s' "$name" | tr '.-' '__')"
	local env_args=() kv
	for kv in $cfg; do env_args+=(-e "$kv"); done
	local extra_args=()
	[ -n "$publish" ] && extra_args+=(-p "$publish:12368")
	if [ "$valgrind" = true ]; then
		mkdir -p "$work/valgrind"
		extra_args+=(-v "$work/valgrind":/tmp/valgrind)
	fi

	setup_network0 || exit 1

	# Serialize loop index picking against concurrent 'up'
	local lock_fd idx
	exec {lock_fd}>/tmp/pv_appengine.instance.lock || exit 1
	flock "$lock_fd"
	idx=$(_loop_index)

	pvtest_log INFO "booting $name (revision $rev, $n tarball(s), cfg=[${cfg:-<none>}])"
	if ! docker run -d \
		--name "$(_ctr "$name")" \
		--label pvtest.user="$USER" \
		--label pvtest.instance="$name" \
		--label pvtest.work="$work" \
		--label pvtest.rev="$rev" \
		--label pvtest.loopidx="$idx" \
		"${_AE_DOCKER_ARGS[@]}" \
		-v "$work/storage":/var/pantavisor/storage \
		-v "$work/seed":/usr/lib/pantavisor/pvtx.extra.d:ro \
		"${extra_args[@]}" \
		-e PV_APPENGINE_INITIAL_REV="$rev" \
		-e VALGRIND="$valgrind" \
		-e PV_LOG_SERVER_OUTPUTS="filetree,stdout_direct" \
		-e PV_LOG_TIMESTAMP="absolute" \
		"${env_args[@]}" \
		-e PV_LOOP_INDEX_BASE=$((_LOOP_BASE0 + idx * 64)) \
		"pantavisor-appengine:$PVTEST_IMAGE_TAG" \
			/usr/bin/pv-appengine > /dev/null; then
		exec {lock_fd}>&-
		pvtest_log ERROR "docker run failed for $name"
		exit 1
	fi
	exec {lock_fd}>&-

	: > "$work/console.log"
	_follow "$name"

	if [ "$detach" = false ]; then
		_attached "$name" "$rev" "$timeout" "$usrmeta"
		return 0
	fi
	_wait_ready "$name" "$rev" "$timeout" || {
		pvtest_log ERROR "$name left running for inspection; '$0 down $name' to remove"
		exit 1
	}
	_apply_usrmeta "$name" "$usrmeta"
	_ready_msg "$name"
}

cmd_start() {
	local name="$1" detach=false timeout=300
	shift
	while [ $# -gt 0 ]; do
		case "$1" in
			-d|--detach) detach=true; shift ;;
			-t|--timeout) timeout="$2"; shift 2 ;;
			*) pvtest_log ERROR "Unknown argument: $1"; usage; exit 1 ;;
		esac
	done
	_need_instance "$name"
	local PVTEST_LOG_TAG="$name"
	if [ "$(_status "$name")" = running ]; then
		pvtest_log ERROR "$name is already running"
		exit 1
	fi
	setup_network0 || exit 1
	docker start "$(_ctr "$name")" > /dev/null || exit 1
	_follow "$name"
	if [ "$detach" = false ]; then
		_attached "$name" "" "$timeout" ""
		return 0
	fi
	_wait_ready "$name" "" "$timeout" || exit 1
	_ready_msg "$name"
}

cmd_stop() {
	_need_instance "$1"
	local PVTEST_LOG_TAG="$1"
	_poweroff "$1"
	_unfollow "$1"
	pvtest_log INFO "$1: $(_status "$1")"
}

cmd_down() {
	_need_instance "$1"
	local PVTEST_LOG_TAG="$1"
	_poweroff "$1"
	_unfollow "$1"
	docker rm -f "$(_ctr "$1")" > /dev/null
	# storage is written as root from inside the container
	if [ -n "$work" ] && [ -f "$work/setup.json" ]; then
		docker run --rm -v "$work":/work "pantavisor-appengine:$PVTEST_IMAGE_TAG" \
			-c "rm -rf /work/storage /work/valgrind" > /dev/null 2>&1
		rm -rf "$work"
	fi
	pvtest_log INFO "$1: removed"
}

cmd_attach() {
	_need_instance "$1"
	if [ "$(_status "$1")" != running ]; then
		pvtest_log ERROR "$1 is not running (status: $(_status "$1"))"
		exit 1
	fi
	# a host reboot or kill can lose the follower
	if ! kill -0 "$(cat "$work/.console.pid" 2>/dev/null)" 2>/dev/null; then
		_follow "$1"
	fi
	trap 'exit 0' INT
	_tail
}

cmd_exec() {
	local name="$1"
	shift
	_need_instance "$name"
	local tty=()
	[ -t 0 ] && [ -t 1 ] && tty=(-t)
	[ $# -gt 0 ] || set -- bash
	exec docker exec -i "${tty[@]}" "$(_ctr "$name")" "$@"
}

cmd_logs() {
	_need_instance "$1"
	cat "$work/console.log"
}

cmd_ls() {
	local cid
	printf '%-20s %-10s %-24s %-15s %s\n' NAME STATUS REVISION IP WORKDIR
	docker ps -aq --filter label=pvtest.user="$USER" --filter label=pvtest.instance \
		| while IFS= read -r cid; do
			docker inspect -f '{{index .Config.Labels "pvtest.instance"}} {{.State.Status}} {{index .Config.Labels "pvtest.rev"}} {{if .State.Running}}{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}{{else}}-{{end}} {{index .Config.Labels "pvtest.work"}}' "$cid"
		done | sort | while read -r n s r i w; do
			printf '%-20s %-10s %-24s %-15s %s\n' "$n" "$s" "$r" "$i" "$w"
		done
}

verbose="false"
work=

while [ $# -gt 0 ]; do
	case "$1" in
		-h|--help) usage; exit 0 ;;
		-v|--verbose) set -x; verbose="true"; shift ;;
		*) break ;;
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
	install-deps) install_deps appengine ;;
	install-docker) install_docker appengine ;;
	up) cmd_up "$@" ;;
	start) cmd_start "$@" ;;
	stop) cmd_stop "$1" ;;
	down) cmd_down "$1" ;;
	attach) cmd_attach "$1" ;;
	exec) cmd_exec "$@" ;;
	logs) cmd_logs "$1" ;;
	ls) cmd_ls ;;
	*)
		pvtest_log ERROR "Unknown command: $command"
		usage
		exit 1
		;;
esac
