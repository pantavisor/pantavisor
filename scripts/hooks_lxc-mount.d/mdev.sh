#!/bin/sh

container_mdev=/storage/trails/current/$LXC_NAME/mdev.json

if ! [ -f $container_mdev ]; then
	exit 0
fi

tmpf=`mktemp -t mdev.conf.XXXXXXX`
cat $container_mdev \
	| /lib/pv/JSON.sh -l \
	| grep '\["rules",' \
	| sed 's/[^[:space:]]*[[:space:]]"//;s/"$//' \
	> $tmpf

FOLLOW_X_ROOT=$LXC_ROOTFS_MOUNT MDEV_CONF=$tmpf mdev ${MDEV_VERBOSE:+-$MDEV_VERBOSE} -S -d

