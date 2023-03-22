#!/bin/sh
 
set -x

PATH=$PATH:/lib/pv

/bin/cat /proc/self/environ | tr '\0' '\n'

container_runjson=/storage/trails/current/$LXC_NAME/run.json

if ! [ -f $container_runjson ]; then
	echo "ERROR: container $LXC_NAME must have a run.json"
	exit 2
fi

echo "RUNJSON: $container_runjson"
tmpf=`mktemp -t remounts.XXXXXXXX`

cat $container_runjson \
	| JSON.sh -l \
	| grep '\["remount",' \
	| sed 's/\["remount","\(.*\)"\][^[:space:]]*[[:space:]]"\(.*\)"/bind,remount,\2 \1/' \
	> $tmpf

echo "remounting these:"
cat $tmpf

echo "current mountinfo:"
cat /proc/self/mountinfo

cat $tmpf | while read -r line; do
	opt=`echo "$line" | awk '{ print $1 }'`
	exp=`echo "$line" | awk '{ print $2 }'`
	echo "Remounting $exp with $opt"
	if [ -z "$opt" ] || [ -z "$exp" ]; then
		continue
	fi
	if [ "$exp" = "/" ]; then
		exp=
	fi
	cat /proc/mounts | grep "[[:space:]]${LXC_ROOTFS_MOUNT}${exp}[[:space:]]" | while read -r line2; do
		path=`echo $line2 | awk '{ print $2 }'`
		echo "Doing remount of $path with opt $opt"
		mount -o $opt $path
		cat /proc/self/mountinfo
	done
done

rm -f $tmpf

