#!/bin/bash
export DISPLAY=:1

cd $(dirname $0)

# NOTE: change -avd parameter to existing emulator image
Xvfb :1 -screen 0 1024x768x16 & emulator -no-boot-anim -system system.img -ramdisk ramdisk.img -avd sandbox -wipe-data -tcpdump $1 -port $2 & x11vnc -display :1 -bg -nopw -listen localhost -xkb

# wait until emulator has started, set magic dalvik parameter
adb wait-for-device ; sleep 2
adb shell setprop dalvik.vm.execution-mode int:portable

# push ltrace binary & config to executable directory
#adb push ltrace      /data/local/tmp
#adb push ltrace.conf /data/local/tmp