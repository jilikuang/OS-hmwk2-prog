#!/bin/bash

adb remount
adb push prinfo /sdcard/prinfo
adb shell chmod 777 /sdcard/prinfo
adb shell /sdcard/prinfo 1> /tmp/log.txt
