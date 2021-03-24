#!/bin/bash

rootdir=$(pwd)
rm -rf build
mkdir build

pushd build

git clone -l ${rootdir}
pushd az-hibernate-agent

git switch main
pkgversion=$(grep '$PackageVersion$ ' az-hibernate-agent.c | cut -d'$' -f3 | xargs)
popd

echo "Package version: ${pkgversion}"

rm -rf az-hibernate-agent/.git
mv az-hibernate-agent az-hibernate-agent_${pkgversion}
pkgnodebver=$(echo $pkgversion | cut -d'-' -f1)
tar czvf ${rootdir}/build/az-hibernate-agent_${pkgnodebver}.orig.tar.gz az-hibernate-agent_${pkgversion}

mkdir az-hibernate-agent_${pkgversion}/debian
cp -r ${rootdir}/debian az-hibernate-agent_${pkgversion}

pushd az-hibernate-agent_${pkgversion}/
debuild
