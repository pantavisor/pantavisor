#!/bin/bash

buildir=$2

IFS=
manifest=$(.repo/repo/repo manifest -r)
gitdescribe=$(cd .repo/manifests; git describe --tags)
sha256=$(echo $manifest | sha256sum | awk '{print $1}')
manifest=$(echo $manifest | sed 's/"/\\"/g' | sed -e '$ ! s/$/ \\n \\/')

now=$(date +'%y%m%d')

echo "const char *pv_build_manifest = \"${manifest}\";" > $buildir/version.c
echo "const char *pv_build_version = \"${gitdescribe}-${now}-${sha256:0:7}\";" >> $buildir/version.c
echo "const char *pv_build_date = \"${now}\";" >> $buildir/version.c
echo "const char *pv_build_arch = \"${3}\";" >> $buildir/version.c

echo "version.c generated like:"
cat $buildir/version.c

