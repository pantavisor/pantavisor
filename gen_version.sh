#!/bin/bash

buildir=$2

IFS=
manifest=$(repo manifest -r)
sha256=$(echo $manifest | sha256sum | awk '{print $1}')
manifest=$(echo $manifest | sed 's/"/\\"/g' | sed -e '$ ! s/$/ \\n \\/')

now=$(date +'%y%m%d')

echo "const char *pv_build_manifest = \"${manifest}\";" > $buildir/version.c
echo "const char *pv_build_version = \"${PANTAVISOR_VERSION}-${now}-${sha256:0:7}\";" >> $buildir/version.c
