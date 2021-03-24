#!/bin/bash

rootdir=$(pwd)
rm -rf build
mkdir build

pkgversion=$(grep -o -P -m 1 '^az-hibernate-agent \(\K([a-z0-9\.-]+)' debian/changelog | xargs)
echo "Package version: ${pkgversion}"

pushd build

git clone -l ${rootdir}
pushd az-hibernate-agent
git switch main
rm -rf .git
popd

mv az-hibernate-agent az-hibernate-agent_${pkgversion}
pkgnodebver=$(echo $pkgversion | cut -d'-' -f1)
tar czvf ${rootdir}/build/az-hibernate-agent_${pkgnodebver}.orig.tar.gz az-hibernate-agent_${pkgversion}

mkdir az-hibernate-agent_${pkgversion}/debian
cp -r ${rootdir}/debian az-hibernate-agent_${pkgversion}

pushd az-hibernate-agent_${pkgversion}/
debuild
