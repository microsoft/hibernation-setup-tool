#!/bin/bash

rootdir=$(pwd)
rm -rf build
mkdir build

pkgversion=$(grep -o -P -m 1 '^hibernation-setup-tool \(\K([a-z0-9\.-]+)' debian/changelog | xargs)
echo "Package version: ${pkgversion}"

pushd build

git clone -l ${rootdir}
pushd hibernation-setup-tool
git switch main
rm -rf .git
popd

mv hibernation-setup-tool hibernation-setup-tool_${pkgversion}
pkgnodebver=$(echo $pkgversion | cut -d'-' -f1)
tar czvf ${rootdir}/build/hibernation-setup-tool_${pkgnodebver}.orig.tar.gz hibernation-setup-tool_${pkgversion}

mkdir hibernation-setup-tool_${pkgversion}/debian
cp -r ${rootdir}/debian hibernation-setup-tool_${pkgversion}

pushd hibernation-setup-tool_${pkgversion}/
debuild
