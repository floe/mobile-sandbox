#!/bin/bash

PATCHDIR=$(dirname $0)

cd dalvik
patch -p1 < "$PATCHDIR/dalvik-droidbox.patch"

cd ../external/bouncycastle
patch -p1 < "$PATCHDIR/external-bouncycastle-droidbox.patch"

cd ../../frameworks/base
patch -p1 < "$PATCHDIR/frameworks-base-droidbox.patch"

cd ../../libcore
patch -p1 < "$PATCHDIR/libcore-droidbox.patch"

