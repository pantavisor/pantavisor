#!/bin/sh

set -e
exec 2>&1 > /dev/kmsg

dirname_r() {
	echo $1 | sed 's/\(.*\)\/.*/\1/'
}

CMD=$0
DIR=$(sh -c "cd `dirname_r $0`; pwd")
LIBDIR=$(sh -c "cd `dirname_r $0`/..; pwd")
CONTAINER_NAME=$1
ALWAYS_LXC=$2
HOOK_TYPE=$3

if test -z "$CONTAINER_NAME"; then
	echo "$0 Must have Container name as first argument"
	echo "   command failed: $0 $@"
	exit 1
fi

runjson=`dirname_r $LXC_CONFIG_FILE`/run.json

if ! test -f $runjson; then
	echo "$0 requires $runjson to process exports"
	exit 1
fi

if ! cat $runjson | sh $LIBDIR/JSON.sh -l > /dev/null; then
	echo "Error parsing runjson. Needs to be valid json"
	exit 2
fi

exports=`cat $runjson | \
	sh $LIBDIR/JSON.sh -l -n | \
	grep '\["exports",[0-9][0-9]*\]' | \
	sed -e 's/^"\(.*\)"$/\1/' | \
	awk '{ print $2}'`

if test -z "$exports"; then
	echo "No exports ... nothing to do ..."
	exit 0
fi

for e in $exports; do
	a=`eval echo $e`
	volume=/exports/$CONTAINER_NAME/$a
	mkdir -p $volume
	echo "exporting mount -o bind $LXC_ROOTFS_MOUNT/$a $volume"
	mount -o bind $LXC_ROOTFS_MOUNT/$a $volume || true
done

