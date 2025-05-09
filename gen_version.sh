#!/bin/bash

type=$1
buildir=$2

IFS=
now=$(date +'%y%m%d')

if [ "$type" = CMAKE ]; then
    gitdescribe=$(git describe --tags)

    echo "const char *pv_build_manifest = \"\";" > $buildir/version.c
    echo "const char *pv_build_version = \"${gitdescribe}-${now}${DISTRO_NAME:+ | ${DISTRO_NAME}}${DISTRO_VERSION:+ (${DISTRO_VERSION})}\";" >> $buildir/version.c
    echo "const char *pv_build_date = \"${now}\";" >> $buildir/version.c
    echo "const char *pv_build_arch = \"${3}\";" >> $buildir/version.c

elif [ "$type" = PVALCHEMY ]; then
    manifest=$(.repo/repo/repo manifest -r)
    gitdescribe=$(cd .repo/manifests; git describe --tags)
    sha256=$(echo $manifest | sha256sum | awk '{print $1}')
    manifest=$(echo $manifest | sed 's/"/\\"/g' | sed -e '$ ! s/$/ \\n \\/')

    echo "const char *pv_build_manifest = \"${manifest}\";" > $buildir/version.c
    echo "const char *pv_build_version = \"${gitdescribe}-${now}-${sha256:0:7}\";" >> $buildir/version.c
    echo "const char *pv_build_date = \"${now}\";" >> $buildir/version.c
    echo "const char *pv_build_arch = \"${3}\";" >> $buildir/version.c

else
    echo "ERROR: unknown build system type for gen_version.sh: $type"
    exit 128
fi

echo "version.c generated like:"
cat $buildir/version.c

