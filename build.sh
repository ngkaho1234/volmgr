#!/bin/bash

E2FSPROGS_DESTDIR=e2fsprogs_destdir

CC=aarch64-linux-android-gcc
INCLUDE_DIR=(
	'-Ilibuv/include'
	"-I${E2FSPROGS_DESTDIR}/usr/include")
LIB_DIR=("-L${E2FSPROGS_DESTDIR}/usr/lib")
CFLAGS=('-D_FILE_OFFSET_BITS=64'
	'-g')
LDFLAGS=('-fPIC -pie')

NDK_PATH=~/android-ndk/android-ndk-r12b
CURR_PWD=${PWD}

git clone https://github.com/libuv/libuv
pushd libuv > /dev/zero
git clone https://chromium.googlesource.com/external/gyp.git build/gyp
source ${CURR_PWD}/libuv-android-configure ${NDK_PATH} gyp
make -C out BUILDTYPE=Release -j8
popd > /dev/zero
cp libuv/out/Release/libuv.a .

if [[ ! -f ${CURR_PWD}/${E2FSPROGS_DESTDIR}/usr/lib/libblkid.a ]]; then
	git clone https://github.com/tytso/e2fsprogs
	pushd e2fsprogs > /dev/zero
	git checkout v1.42.3
	mkdir build;cd build
	../configure --host=aarch64-linux-android --disable-nls --prefix=/usr
	mkdir ${CURR_PWD}/${E2FSPROGS_DESTDIR}
	make -j8
	make DESTDIR=${CURR_PWD}/${E2FSPROGS_DESTDIR} install-libs
	popd > /dev/zero
fi


${CC} ${CFLAGS[@]} ${LDFLAGS[@]} ${INCLUDE_DIR[@]} ${LIB_DIR[@]} volmgr.c -lblkid -luuid libuv.a -o volmgr
