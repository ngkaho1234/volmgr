#!/bin/bash

CC=aarch64-linux-android-gcc
INCLUDE_DIR=(
	'-Ilibuv/include'
	'-Ie2fsprogs-destdir/usr/include')
LIB_DIR=('-Le2fsprogs-destdir/usr/lib')
CFLAGS=('-D_FILE_OFFSET_BITS=64'
	'-g')
LDFLAGS=('-fPIC -pie')

NDK_PATH=~/android-ndk/android-ndk-r12b

git clone https://github.com/libuv/libuv
pushd libuv > /dev/zero
git clone https://chromium.googlesource.com/external/gyp.git build/gyp
source ./android-configure ${NDK_PATH} gyp
make -C out BUILDTYPE=Release -j8
popd > /dev/zero
cp libuv/out/Release/libuv.a .

CURR_PWD=${PWD}
if [[ ! -f ${CURR_PWD}/e2fsprogs-destdir/usr/lib/libblkid.a ]]; then
	git clone https://github.com/tytso/e2fsprogs
	pushd e2fsprogs > /dev/zero
	mkdir build;cd build
	../configure --host=aarch64-linux-android --disable-nls --prefix=/usr
	mkdir ${CURR_PWD}/e2fsprogs-destdir
	make -j8
	make DESTDIR=${CURR_PWD}/e2fsprogs-destdir install-libs
	popd > /dev/zero
fi

${CC} ${CFLAGS[@]} ${LDFLAGS[@]} ${INCLUDE_DIR[@]} ${LIB_DIR[@]} volmgr.c e2fsprogs-destdir/usr/lib/libblkid.a libuv.a -o volmgr
gcc ${CFLAGS[@]} ${LDFLAGS[@]} volmgr.c -lblkid -luv -pthread -o volmgr-host
