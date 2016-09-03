#!/bin/bash

CC=aarch64-linux-android-gcc
INCLUDE_DIR=('-Ilibuv/include')
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

${CC} ${CFLAGS} ${LDFLAGS} ${INCLUDE_DIR} volmgr.c libuv.a -o volmgr
gcc ${CFLAGS} ${LDFLAGS} volmgr.c -luv -pthread -o volmgr-host
