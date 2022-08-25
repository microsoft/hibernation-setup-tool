#!/bin/bash

rootdir=$(pwd)
rm -rf build
mkdir build

pkgversion=1.0.9
echo "Package version: ${pkgversion}"

pushd build

git clone -l ${rootdir}
pushd hibernation-setup-tool
git switch main
rm -rf .git
popd

mv hibernation-setup-tool hibernation-setup-tool_${pkgversion}
tar czvf hibernation-setup-tool_${pkgversion}.tar.gz hibernation-setup-tool_${pkgversion}
popd
pushd rpmbuild
mkdir "SOURCES", "BUILD", "RPMS", "SRPMS"
cp build/hibernation-setup-tool_${pkgversion}.tar.gz SOURCES/

rpmbuild --define "_topdir %(echo $(pwd))" -ba SPECS/hibernation-setup-tool.spec