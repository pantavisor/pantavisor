#!/bin/bash -x

srcdir=$1
buildir=$2

pushd $srcdir;

version=$(git rev-parse --short HEAD)
now=$(date +'%m%d%y')

echo "#define PV_BUILD_VERSION \"$version\"" > $buildir/version.h
echo "#define PV_BUILD_DATE \"$now\"" >> $buildir/version.h
