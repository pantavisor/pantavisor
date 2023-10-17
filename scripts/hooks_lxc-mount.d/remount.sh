#!/bin/sh
 
set -e

PATH=$LIBPVPATH:$PATH
export PATH

/bin/cat /proc/self/environ | tr '\0' '\n'

statejson=/storage/trails/current/.pvr/json
runjson=$LXC_NAME/run.json
devicejson=device.json
pv_policy=${pv_policy:-default}
pv_policy=${pv_remount_policy:-$pv_policy}

if ! [ -f $container_runjson ]; then
	echo "ERROR: container $LXC_NAME must have a run.json"
	exit 2
fi

echo "RUNJSON: $statejson"

tmpf=`mktemp -t remounts.XXXXXXXX`

# unix_proxy="local:/pv/pv-ctrl" wget -O- http://localhost/config

catstatejson() {
	_json="$1"
	_pol="$2"
	#if ! cat $statejson | JSON.sh -l | grep -E -q '\["'${_json}'","remount","'${_pol}'",[0-9]*,'; then
	#	return 1
	#fi

	cat $statejson \
		| JSON.sh -l \
		| grep -E '\["'"(${_json})"'","remount","'"(${_pol})"'",[0-9]*,' \
		| sed -E 's#\["'"(${_json})"'","remount","'"(${_pol})"'",[0-9]*,"(.*)"\][^[:space:]]*[[:space:]]"(.*)"#bind,remount,\4 \3#'
}

catstatejson "${devicejson}|${runjson}" "${pv_policy}|default" >> $tmpf

echo "remounting these:"
cat $tmpf

echo "current mountinfo:"
cat /proc/self/mountinfo

cat $tmpf | while read -r line; do
	opt=`echo "$line" | awk '{ print $1 }'`
	exp=`echo "$line" | awk '{ print $2 }'`
	if [ -z "$opt" ] || [ -z "$exp" ]; then
		continue
	fi
	if [ "$exp" = "/" ]; then
		exp=
	fi
	cat /proc/mounts | grep "[[:space:]]${LXC_ROOTFS_MOUNT}${exp}[[:space:]]" | while read -r line2; do
		path=`echo $line2 | awk '{ print $2 }'`
		echo "remounting with new mount options: $path + $opt"
		set -x
		mount -o $opt $path
		set +x
	done
done

echo "Success."

rm -f $tmpf
